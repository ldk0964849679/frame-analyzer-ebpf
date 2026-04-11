/*
* Copyright (c) 2024 shadow3aaa@gitbub.com
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use std::{
    collections::{HashSet, VecDeque},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex,
    },
    thread,
    time::Duration,
    os::unix::io::RawFd,
};

use libc::{
    c_int, c_uint, c_void, close, eventfd, read, write, EFD_CLOEXEC, EFD_NONBLOCK,
};

use crate::{Analyzer, Pid};

/// 帧数据缓冲区：分离监听与读取逻辑，避免锁竞争
struct FrameBuffer {
    data: Mutex<VecDeque<(Pid, Duration)>>,
    running: AtomicBool,
}

impl FrameBuffer {
    fn new() -> Self {
        Self {
            data: Mutex::new(VecDeque::with_capacity(1024)),
            running: AtomicBool::new(true),
        }
    }

    fn push(&self, pid: Pid, frametime: Duration) {
        if !self.running.load(Ordering::Acquire) {
            return;
        }
        let mut data = self.data.lock().unwrap();
        data.push_back((pid, frametime));
    }

    fn pop(&self, pid: Pid, timeout: Duration) -> Option<Duration> {
        if !self.running.load(Ordering::Acquire) {
            return None;
        }

        let start = std::time::Instant::now();
        
        loop {
            {
                let mut data = self.data.lock().unwrap();
                
                // 查找指定 PID 的帧数据
                if let Some(pos) = data.iter().position(|(p, _)| *p == pid) {
                    let (_, ft) = data.remove(pos).unwrap();
                    return Some(ft);
                }
            }
            
            // 检查是否超时
            if start.elapsed() >= timeout {
                return None;
            }
            
            // 短暂休眠避免忙等，使用微秒级休眠减少延迟
            thread::sleep(Duration::from_micros(100));
        }
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Release);
    }
}

static RUNNING: AtomicBool = AtomicBool::new(false);
static GLOBAL_ANALYZER: Mutex<Option<Arc<Mutex<Analyzer>>>> = Mutex::new(None);
static FRAME_BUFFER: LazyLock<Arc<FrameBuffer>> = LazyLock::new(|| Arc::new(FrameBuffer::new()));
static NOTIFY_FD: Mutex<Option<RawFd>> = Mutex::new(None);
static NOTIFY_THREAD: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);

static PID_ATTACHED: LazyLock<Mutex<HashSet<Pid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static PAUSED: AtomicBool = AtomicBool::new(false);

#[repr(C)]
pub struct FrameTime {
    pub secs: c_uint,
    pub nanos: c_uint,
}

fn read_eventfd(fd: RawFd) {
    let mut val = 0u64;
    unsafe { read(fd, &mut val as *mut u64 as *mut c_void, 8) };
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_init() -> c_int {
    if RUNNING.load(Ordering::Acquire) {
        return 0;
    }

    let mut global = GLOBAL_ANALYZER.lock().unwrap();
    if global.is_some() {
        return 0;
    }

    let analyzer = match catch_unwind(|| Analyzer::new()) {
        Ok(Ok(a)) => a,
        _ => return -1,
    };

    let efd = unsafe { eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC) };
    if efd < 0 {
        return -1;
    }

    let analyzer_arc = Arc::new(Mutex::new(analyzer));
    let analyzer_clone = analyzer_arc.clone();
    let efd_clone = efd;
    let buffer_clone = FRAME_BUFFER.clone();

    // 低功耗监听线程
    let thread = thread::spawn(move || {
        while RUNNING.load(Ordering::Acquire) {
            // 暂停时休眠更长，大幅降功耗
            if PAUSED.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(20));
                continue;
            }

            // 🔧 修复：给 analyzer 加上 mut 修饰，允许调用可变方法 recv_timeout
            let mut analyzer = match analyzer_clone.lock() {
                Ok(a) => a,
                Err(_) => {
                    // 锁被 poison，等待恢复
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };

            // recv_timeout 使用 10ms，减少 CPU 唤醒次数
            let result = catch_unwind(AssertUnwindSafe(|| {
                analyzer.recv_timeout(Duration::from_millis(10))
            }));

            // 释放锁，让其他操作可以获取
            drop(analyzer);

            match result {
                Ok(Some((pid, ft))) => {
                    buffer_clone.push(pid, ft);
                    let val: u64 = 1;
                    unsafe { write(efd_clone, &val as *const u64 as *const c_void, 8) };
                }
                Ok(None) => {
                    // 没数据也睡 4ms，给CPU喘息
                    thread::sleep(Duration::from_millis(4));
                }
                Err(_) => break,
            }
        }

        unsafe { close(efd_clone) };
    });

    *global = Some(analyzer_arc);
    *NOTIFY_FD.lock().unwrap() = Some(efd);
    *NOTIFY_THREAD.lock().unwrap() = Some(thread);
    RUNNING.store(true, Ordering::Release);

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_attach(pid: c_int) -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    let pid = pid as Pid;
    let mut attached = PID_ATTACHED.lock().unwrap();
    if attached.contains(&pid) {
        return 0;
    }

    let global = GLOBAL_ANALYZER.lock().unwrap();
    let analyzer = match global.as_ref() {
        Some(a) => a,
        None => return -1,
    };

    // 带超时保护的锁获取
    let start = std::time::Instant::now();
    let mut analyzer = loop {
        match analyzer.try_lock() {
            Ok(lock) => break lock,
            Err(_) => {
                if start.elapsed() > Duration::from_secs(2) {
                    eprintln!("frame_analyzer_attach: timeout waiting for analyzer lock");
                    return -1;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    };

    match catch_unwind(AssertUnwindSafe(|| analyzer.attach_app(pid))) {
        Ok(Ok(())) => {
            attached.insert(pid);
            0
        }
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_frametime(
    pid: c_int,
    timeout_ms: c_int,
    out_frametime: *mut FrameTime,
) -> c_int {
    if out_frametime.is_null() || !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    let pid = pid as Pid;
    let timeout = if timeout_ms <= 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(timeout_ms as u64)
    };

    // 清空 eventfd，避免重复通知
    if let Some(fd) = *NOTIFY_FD.lock().unwrap() {
        read_eventfd(fd);
    }

    match FRAME_BUFFER.pop(pid, timeout) {
        Some(frametime) => {
            let ft = FrameTime {
                secs: frametime.as_secs() as c_uint,
                nanos: frametime.subsec_nanos() as c_uint,
            };
            unsafe { *out_frametime = ft; }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_detach(pid: c_int) -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    let pid = pid as Pid;

    let global = GLOBAL_ANALYZER.lock().unwrap();
    let analyzer = match global.as_ref() {
        Some(a) => a,
        None => return -1,
    };

    // 带超时保护的锁获取
    let start = std::time::Instant::now();
    let mut analyzer = loop {
        match analyzer.try_lock() {
            Ok(lock) => break lock,
            Err(_) => {
                if start.elapsed() > Duration::from_secs(2) {
                    eprintln!("frame_analyzer_detach: timeout waiting for analyzer lock");
                    return -1;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    };

    match catch_unwind(AssertUnwindSafe(|| analyzer.detach_app(pid))) {
        Ok(Ok(())) => {
            let mut attached = PID_ATTACHED.lock().unwrap();
            attached.remove(&pid);
            0
        }
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_destroy() -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return 0;
    }

    // 先停止运行标志，让监听线程退出
    RUNNING.store(false, Ordering::Release);
    
    // 清除暂停标志
    PAUSED.store(false, Ordering::Release);
    
    // 停止 FrameBuffer
    FRAME_BUFFER.stop();

    // 等待监听线程结束，添加超时保护
    if let Some(thread) = NOTIFY_THREAD.lock().unwrap().take() {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(1) {
            if thread.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !thread.is_finished() {
            eprintln!("frame_analyzer_destroy: thread join timeout, continuing cleanup");
        }
    }

    // 清理已附加的 PID 列表
    let mut attached = PID_ATTACHED.lock().unwrap();
    attached.clear();
    drop(attached);

    // 清理全局 analyzer
    let mut global = GLOBAL_ANALYZER.lock().unwrap();
    if let Some(analyzer) = global.as_ref() {
        if let Ok(mut analyzer) = analyzer.try_lock() {
            let _ = catch_unwind(AssertUnwindSafe(|| analyzer.detach_apps()));
        }
    }
    *global = None;

    // 清理通知 fd
    let mut notify_fd = NOTIFY_FD.lock().unwrap();
    if let Some(fd) = *notify_fd {
        unsafe { close(fd); }
    }
    *notify_fd = None;

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_notify_fd() -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    // 🔧 修复：正确解引用 MutexGuard，移除多余 mut
    NOTIFY_FD.lock().ok().and_then(|guard| *guard).unwrap_or(-1) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_pause() -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    PAUSED.store(true, Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_resume() -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    PAUSED.store(false, Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_is_paused() -> c_int {
    if PAUSED.load(Ordering::Acquire) {
        1
    } else {
        0
    }
}

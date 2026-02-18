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
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use std::{
collections::{HashSet, VecDeque},
panic::{catch_unwind, AssertUnwindSafe},
sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, LazyLock, Mutex,
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
cond: Condvar,
running: AtomicBool,
}

impl FrameBuffer {
fn new() -> Self {
    Self {
        data: Mutex::new(VecDeque::with_capacity(1024)),
        cond: Condvar::new(),
        running: AtomicBool::new(true),
    }
}

fn push(&self, pid: Pid, frametime: Duration) {
    if !self.running.load(Ordering::Acquire) {
        return;
    }
    let mut data = self.data.lock().unwrap();
    data.push_back((pid, frametime));
    self.cond.notify_one();
}

// 🔧 修复1：修正锁逻辑（必须是 mut 锁，否则无法 remove 帧数据）
fn pop(&self, pid: Pid, timeout: Duration) -> Option<Duration> {
    if !self.running.load(Ordering::Acquire) {
        return None;
    }

    // 关键修正：data 必须是可变锁，才能调用 remove
    let mut data = self.data.lock().unwrap();
    let (mut data, _) = self.cond.wait_timeout(data, timeout).unwrap();

    data.iter().position(|(p, _)| *p == pid).map(|pos| {
        let (_, ft) = data.remove(pos).unwrap();
        ft
    })
}

fn stop(&self) {
    self.running.store(false, Ordering::Release);
    self.cond.notify_all();
}
}

// 全局资源
static RUNNING: AtomicBool = AtomicBool::new(false);
static GLOBAL_ANALYZER: Mutex<Option<Arc<Mutex<Analyzer>>>> = Mutex::new(None);
static FRAME_BUFFER: LazyLock<Arc<FrameBuffer>> = LazyLock::new(|| Arc::new(FrameBuffer::new()));
static NOTIFY_FD: Mutex<Option<RawFd>> = Mutex::new(None);
static NOTIFY_THREAD: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);

// 防重复绑定状态（保留功能）
static PID_ATTACHED: LazyLock<Mutex<HashSet<Pid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

// 暂停控制相关全局变量
static PAUSED: AtomicBool = AtomicBool::new(false);
static PAUSE_COND: Condvar = Condvar::new();
static PAUSE_MTX: Mutex<()> = Mutex::new(());

/// C接口帧时间结构体
#[repr(C)]
pub struct FrameTime {
pub secs: c_uint,
pub nanos: c_uint,
}

/// 简化eventfd读取：仅清空一次，无循环无返回值
fn read_eventfd(fd: RawFd) {
let mut val = 0u64;
unsafe { read(fd, &mut val as *mut u64 as *mut c_void, 8) };
}

/// 初始化EBPF和全局资源
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

// 启动后台监听线程
let thread = thread::spawn(move || {
    while RUNNING.load(Ordering::Acquire) {
        let pause_guard = PAUSE_MTX.lock().unwrap();
        let paused_guard = PAUSE_COND.wait_while(pause_guard, |_guard| {
            PAUSED.load(Ordering::Acquire) && RUNNING.load(Ordering::Acquire)
        }).unwrap();
        drop(paused_guard);

        if !RUNNING.load(Ordering::Acquire) {
            break;
        }

        let mut analyzer = match analyzer_clone.try_lock() {
            Ok(a) => a,
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };

        // 🔧 无需修改：1ms超时是合理优化，提升采集密度，不影响PID切换
        let result = catch_unwind(AssertUnwindSafe(|| analyzer.recv_timeout(Duration::from_millis(1))));
        drop(analyzer);

        match result {
            Ok(Some((pid, ft))) => {
                buffer_clone.push(pid, ft);
                let val: u64 = 1;
                unsafe { write(efd_clone, &val as *const u64 as *const c_void, 8) };
            }
            Ok(None) => thread::sleep(Duration::from_millis(1)),
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

/// 绑定目标PID（保留防重复功能）
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

let mut analyzer_lock = None;
for _ in 0..50 {
    match analyzer.try_lock() {
        Ok(lock) => {
            analyzer_lock = Some(lock);
            break;
        }
        Err(_) => thread::sleep(Duration::from_millis(10)),
    }
}

let mut analyzer = match analyzer_lock {
    Some(l) => l,
    None => return -1,
};

match catch_unwind(AssertUnwindSafe(|| analyzer.attach_app(pid))) {
    Ok(Ok(())) => {
        attached.insert(pid);
        0
    }
    _ => -1,
}
}

/// 获取帧时间数据
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
// 🔧 修复3：还原原版超时逻辑（移除硬限制，直接转换，适配C++侧灵活超时需求）
let timeout = if timeout_ms <= 0 {
    Duration::ZERO
} else {
    Duration::from_millis(timeout_ms as u64)
};

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

/// 解绑PID
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

let mut analyzer_lock = None;
for _ in 0..50 {
    match analyzer.try_lock() {
        Ok(lock) => {
            analyzer_lock = Some(lock);
            break;
        }
        Err(_) => thread::sleep(Duration::from_millis(10)),
    }
}

let mut analyzer = match analyzer_lock {
    Some(l) => l,
    None => return -1,
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

/// 销毁资源
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_destroy() -> c_int {
if !RUNNING.load(Ordering::Acquire) {
    return 0;
}

PAUSED.store(false, Ordering::Release);
PAUSE_COND.notify_all();

RUNNING.store(false, Ordering::Release);
FRAME_BUFFER.stop();

if let Some(thread) = NOTIFY_THREAD.lock().unwrap().take() {
    let _ = thread.join();
}

let mut attached = PID_ATTACHED.lock().unwrap();
attached.clear();
drop(attached);

let mut global = GLOBAL_ANALYZER.lock().unwrap();
if let Some(analyzer) = global.as_ref() {
    if let Ok(mut analyzer) = analyzer.try_lock() {
        let _ = catch_unwind(AssertUnwindSafe(|| analyzer.detach_apps()));
    }
}
*global = None;

let mut notify_fd = NOTIFY_FD.lock().unwrap();
if let Some(fd) = *notify_fd {
    unsafe { close(fd); }
}
*notify_fd = None;

0
}

/// 获取通知FD
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_notify_fd() -> c_int {
if !RUNNING.load(Ordering::Acquire) {
    return -1;
}

let guard = NOTIFY_FD.lock().unwrap();
guard.as_ref().copied().unwrap_or(-1) as c_int
}

/// 暂停监听线程
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_pause() -> c_int {
if !RUNNING.load(Ordering::Acquire) {
    return -1;
}

PAUSED.store(true, Ordering::Release);
0
}

/// 恢复监听线程
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_resume() -> c_int {
if !RUNNING.load(Ordering::Acquire) {
    return -1;
}

PAUSED.store(false, Ordering::Release);
PAUSE_COND.notify_all();
0
}

/// 查询暂停状态
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_is_paused() -> c_int {
if PAUSED.load(Ordering::Acquire) {
    1
} else {
    0
}
}

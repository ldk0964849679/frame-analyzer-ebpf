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
        atomic::{AtomicBool, AtomicI32, Ordering},
        Arc, LazyLock, Mutex, MutexGuard, OnceLock, RwLock,
    },
    thread,
    time::Duration,
    os::unix::io::RawFd,
};

use libc::{
    c_int, c_uint, c_void, close, eventfd, read, write, EFD_CLOEXEC, EFD_NONBLOCK,
};

use crate::{Analyzer, Pid};

// ==================== 帧缓冲区 ====================
struct FrameBuffer {
    data: Mutex<VecDeque<(Pid, Duration)>>,
    running: AtomicBool,
}

impl FrameBuffer {
    fn new() -> Self {
        Self {
            data: Mutex::new(VecDeque::with_capacity(512)),
            running: AtomicBool::new(true),
        }
    }

    fn push(&self, pid: Pid, frametime: Duration) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(mut data) = self.data.lock() {
            data.push_back((pid, frametime));
        }
    }

    fn drain_for_pid(&self, pid: Pid) -> Vec<Duration> {
        if !self.running.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let mut data = self.data.lock().unwrap();
        let mut result = Vec::new();
        data.retain(|(p, ft)| {
            if *p == pid {
                result.push(*ft);
                false
            } else {
                true
            }
        });
        result
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Release);
    }
}

// ==================== 全局资源 ====================
static RUNNING: AtomicBool = AtomicBool::new(false);
static GLOBAL_ANALYZER: OnceLock<Arc<Mutex<Analyzer>>> = OnceLock::new();
static FRAME_BUFFER: LazyLock<Arc<FrameBuffer>> = LazyLock::new(|| Arc::new(FrameBuffer::new()));
static NOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
static NOTIFY_THREAD: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);
static PID_ATTACHED: LazyLock<RwLock<HashSet<Pid>>> = LazyLock::new(|| RwLock::new(HashSet::new()));
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

fn wait_for_lock<T>(arc: &Arc<Mutex<T>>, max_attempts: usize) -> Option<MutexGuard<'_, T>> {
    for _ in 0..max_attempts {
        match arc.try_lock() {
            Ok(guard) => return Some(guard),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_init() -> c_int {
    if RUNNING.load(Ordering::Acquire) {
        return 0;
    }

    let analyzer = match catch_unwind(|| Analyzer::new()) {
        Ok(Ok(a)) => Arc::new(Mutex::new(a)),
        Ok(Err(e)) => {
            eprintln!("frame_analyzer_init: failed to create analyzer: {:?}", e);
            return -1;
        }
        Err(_) => {
            eprintln!("frame_analyzer_init: panic during analyzer creation");
            return -1;
        }
    };

    if GLOBAL_ANALYZER.set(analyzer.clone()).is_err() {
        eprintln!("frame_analyzer_init: analyzer already initialized");
        return -1;
    }

    let efd = unsafe { eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC) };
    if efd < 0 {
        return -1;
    }
    NOTIFY_FD.store(efd, Ordering::Release);

    let analyzer_clone = analyzer;
    let efd_clone = efd;
    let buffer_clone = FRAME_BUFFER.clone();

    let thread = thread::spawn(move || {
        while RUNNING.load(Ordering::Acquire) {
            if PAUSED.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(20));
                continue;
            }

            let mut analyzer = match analyzer_clone.lock() {
                Ok(a) => a,
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };

            let result = catch_unwind(AssertUnwindSafe(|| {
                analyzer.recv_timeout(Duration::from_millis(10))
            }));

            drop(analyzer);

            match result {
                Ok(Some((pid, ft))) => {
                    buffer_clone.push(pid, ft);
                    let val: u64 = 1;
                    unsafe { write(efd_clone, &val as *const u64 as *const c_void, 8) };
                }
                Ok(None) => {
                    thread::sleep(Duration::from_millis(4));
                }
                Err(_) => break,
            }
        }

        unsafe { close(efd_clone) };
    });

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
    
    if PID_ATTACHED.read().unwrap().contains(&pid) {
        return 0;
    }

    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };

    let mut analyzer = match wait_for_lock(analyzer, 50) {
        Some(a) => a,
        None => return -1,
    };

    match catch_unwind(AssertUnwindSafe(|| analyzer.attach_app(pid))) {
        Ok(Ok(())) => {
            PID_ATTACHED.write().unwrap().insert(pid);
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
    if out_frametime.is_null() || !RUNNING.load(Ordering::Relaxed) {
        return -1;
    }

    let pid = pid as Pid;
    let timeout = if timeout_ms <= 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(timeout_ms as u64)
    };

    let fd = NOTIFY_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        read_eventfd(fd);
    }

    let frames = FRAME_BUFFER.drain_for_pid(pid);
    
    if let Some(&ft) = frames.first() {
        let ft_struct = FrameTime {
            secs: ft.as_secs() as c_uint,
            nanos: ft.subsec_nanos() as c_uint,
        };
        unsafe { *out_frametime = ft_struct };
        return 0;
    }

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let frames = FRAME_BUFFER.drain_for_pid(pid);
        if let Some(&ft) = frames.first() {
            let ft_struct = FrameTime {
                secs: ft.as_secs() as c_uint,
                nanos: ft.subsec_nanos() as c_uint,
            };
            unsafe { *out_frametime = ft_struct };
            return 0;
        }
        thread::sleep(Duration::from_micros(100));
    }

    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_detach(pid: c_int) -> c_int {
    if !RUNNING.load(Ordering::Acquire) {
        return -1;
    }

    let pid = pid as Pid;
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };

    let mut analyzer = match wait_for_lock(analyzer, 50) {
        Some(a) => a,
        None => return -1,
    };

    match catch_unwind(AssertUnwindSafe(|| analyzer.detach_app(pid))) {
        Ok(Ok(())) => {
            PID_ATTACHED.write().unwrap().remove(&pid);
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

    RUNNING.store(false, Ordering::Release);
    PAUSED.store(false, Ordering::Release);
    FRAME_BUFFER.stop();

    if let Some(thread) = NOTIFY_THREAD.lock().unwrap().take() {
        let _ = thread.join();
    }

    PID_ATTACHED.write().unwrap().clear();

    if let Some(analyzer) = GLOBAL_ANALYZER.get() {
        if let Ok(mut a) = analyzer.lock() {
            let _ = catch_unwind(AssertUnwindSafe(|| a.detach_apps()));
        }
    }

    let fd = NOTIFY_FD.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        unsafe { close(fd) };
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_notify_fd() -> c_int {
    if !RUNNING.load(Ordering::Relaxed) {
        return -1;
    }
    NOTIFY_FD.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_pause() -> c_int {
    if !RUNNING.load(Ordering::Relaxed) {
        return -1;
    }
    PAUSED.store(true, Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_resume() -> c_int {
    if !RUNNING.load(Ordering::Relaxed) {
        return -1;
    }
    PAUSED.store(false, Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_is_paused() -> c_int {
    PAUSED.load(Ordering::Relaxed) as c_int
}
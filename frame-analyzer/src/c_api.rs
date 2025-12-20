/*
* Copyright (c) 2024 shadow3aaa@gitbub.com
*
* This file is part of frame-analyzer-ebpf.
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

#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::c_char;
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use libc::c_int;
use once_cell::sync::Lazy;

use crate::{Analyzer, AnalyzerError, Pid};

/// C 句柄类型（指向Rust的Analyzer实例）
pub type FrameAnalyzerHandle = *mut Analyzer;

/// 全局错误缓冲区（线程安全，Lazy确保只初始化一次）
static LAST_ERROR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

/// 安全获取错误缓冲区锁（处理PoisonError）
fn lock_error_buf() -> MutexGuard<'static, String> {
    match LAST_ERROR.lock() {
        Ok(guard) => guard,
        Err(PoisonError(guard)) => {
            // 锁被恐慌污染时仍继续使用，避免C API调用失败
            eprintln!("Warning: LAST_ERROR mutex poisoned, continuing with corrupted state");
            guard
        }
    }
}

/// 设置错误信息
fn set_last_error(err: &str) {
    let mut buffer = lock_error_buf();
    *buffer = err.to_string();
}

/// 清除错误信息
fn clear_last_error() {
    set_last_error("");
}

/// Rust错误转换为C错误码
fn error_to_code(err: &AnalyzerError) -> c_int {
    match err {
        AnalyzerError::EbpfError(_) => -1,
        AnalyzerError::BpfProgramError(_) => -2,
        AnalyzerError::BpfMapError(_) => -3,
        AnalyzerError::IOError(_) => -4,
        AnalyzerError::AppNotFound => -5,
        AnalyzerError::MapError => -6,
    }
}

/// 创建帧分析器实例
/// 返回：句柄（非空为成功）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_create() -> FrameAnalyzerHandle {
    clear_last_error();
    match Analyzer::new() {
        Ok(analyzer) => Box::into_raw(Box::new(analyzer)),
        Err(e) => {
            set_last_error(&format!("Create failed: {}", e));
            ptr::null_mut()
        }
    }
}

/// 销毁帧分析器实例
/// 参数：handle - 分析器句柄
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_destroy(handle: FrameAnalyzerHandle) {
    clear_last_error();
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle); // 显式忽略返回值，消除must_use警告
        }
    }
}

/// 附加应用进程监控
/// 参数：handle - 句柄，pid - 进程ID
/// 返回：0=成功，负数=错误码
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_attach_app(handle: FrameAnalyzerHandle, pid: c_int) -> c_int {
    clear_last_error();
    if handle.is_null() {
        set_last_error("Invalid handle");
        return -100;
    }
    let analyzer = unsafe { &mut *handle };
    match analyzer.attach_app(pid as Pid) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(&format!("Attach PID {} failed: {}", pid, e));
            error_to_code(&e)
        }
    }
}

/// 分离应用进程监控
/// 参数：handle - 句柄，pid - 进程ID
/// 返回：0=成功，负数=错误码
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_detach_app(handle: FrameAnalyzerHandle, pid: c_int) -> c_int {
    clear_last_error();
    if handle.is_null() {
        set_last_error("Invalid handle");
        return -100;
    }
    let analyzer = unsafe { &mut *handle };
    match analyzer.detach_app(pid as Pid) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(&format!("Detach PID {} failed: {}", pid, e));
            error_to_code(&e)
        }
    }
}

/// 分离所有应用
/// 参数：handle - 句柄
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_detach_all(handle: FrameAnalyzerHandle) {
    clear_last_error();
    if !handle.is_null() {
        let analyzer = unsafe { &mut *handle };
        analyzer.detach_apps();
    }
}

/// 接收帧时间（阻塞，带超时）
/// 参数：handle-句柄，pid-输出PID，frametime_ns-输出帧时间（纳秒），timeout_ms-超时（毫秒）
/// 返回：0=成功，-1=超时，负数=错误码
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_recv(
    handle: FrameAnalyzerHandle,
    pid: *mut c_int,
    frametime_ns: *mut u64,
    timeout_ms: c_int,
) -> c_int {
    clear_last_error();
    if handle.is_null() || pid.is_null() || frametime_ns.is_null() {
        set_last_error("Invalid handle or output pointer");
        return -100;
    }
    let analyzer = unsafe { &mut *handle };
    let result = if timeout_ms > 0 {
        analyzer.recv_timeout(Duration::from_millis(timeout_ms as u64))
    } else {
        analyzer.recv()
    };
    match result {
        Some((p, t)) => {
            unsafe {
                *pid = p as c_int;
                *frametime_ns = t.as_nanos() as u64;
            }
            0
        }
        None => -1, // 超时或无数据
    }
}

/// 非阻塞接收帧时间
/// 参数：handle-句柄，pid-输出PID，frametime_ns-输出帧时间（纳秒）
/// 返回：0=成功，1=无数据，负数=错误码
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_try_recv(
    handle: FrameAnalyzerHandle,
    pid: *mut c_int,
    frametime_ns: *mut u64,
) -> c_int {
    clear_last_error();
    if handle.is_null() || pid.is_null() || frametime_ns.is_null() {
        set_last_error("Invalid handle or output pointer");
        return -100;
    }
    let analyzer = unsafe { &mut *handle };

    // 非阻塞逻辑：直接检查缓冲区，不等待
    if analyzer.buffer.is_empty() {
        return 1; // 无数据
    }

    let p = match analyzer.buffer.pop_front() {
        Some(pid) => pid,
        None => return 1,
    };

    let frametime = match analyzer.map.get_mut(&p) {
        Some(target) => target.update(),
        None => return 1,
    };

    if let Some(t) = frametime {
        unsafe {
            *pid = p as c_int;
            *frametime_ns = t.as_nanos() as u64;
        }
        0 // 成功
    } else {
        1 // 无有效帧时间
    }
}

/// 检查是否监控指定PID
/// 返回：1=是，0=否，负数=错误码
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_is_monitoring(handle: FrameAnalyzerHandle, pid: c_int) -> c_int {
    clear_last_error();
    if handle.is_null() {
        set_last_error("Invalid handle");
        return -100;
    }
    let analyzer = unsafe { &*handle };
    if analyzer.contains(pid as Pid) { 1 } else { 0 }
}

/// 获取最后错误信息
/// 返回：C字符串（空串为无错误）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_last_error(_handle: FrameAnalyzerHandle) -> *const c_char {
    // 安全读取错误信息，处理锁污染
    let error = lock_error_buf().clone();
    // 静态缓冲区存储错误信息（确保线程安全和字符串终止符）
    static mut BUF: [u8; 256] = [0; 256];

    unsafe {
        let bytes = error.as_bytes();
        let len = bytes.len().min(255); // 预留1字节给终止符
        BUF[..len].copy_from_slice(&bytes[..len]);
        BUF[len] = 0; // 强制添加C字符串终止符
        // 兼容Rust版本，直接转换为C字符指针
        BUF.as_ptr() as *const c_char
    }
}

/// 获取版本号
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_version() -> *const c_char {
    // 静态常量确保字符串生命周期全局有效，且自带终止符
    static VERSION: &str = concat!(
        env!("CARGO_PKG_VERSION_MAJOR"),
        ".",
        env!("CARGO_PKG_VERSION_MINOR"),
        ".",
        env!("CARGO_PKG_VERSION_PATCH"),
        "\0" // 显式添加C字符串终止符，避免跨平台兼容问题
    );
    VERSION.as_ptr() as *const c_char
}

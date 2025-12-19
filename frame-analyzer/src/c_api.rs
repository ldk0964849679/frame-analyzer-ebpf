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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

// 移除未使用的 CStr 导入，消除警告
use std::os::raw::c_char;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// 移除未使用的 size_t 导入，消除警告
use libc::c_int;

use crate::{Analyzer, AnalyzerError, Pid};

/// C 句柄类型（指向Rust的Analyzer实例）
pub type FrameAnalyzerHandle = *mut Analyzer;

/// 全局错误缓冲区（线程安全）
static mut LAST_ERROR: Option<Arc<Mutex<String>>> = None;

/// 初始化错误缓冲区
fn init_error_buffer() {
    unsafe {
        if LAST_ERROR.is_none() {
            LAST_ERROR = Some(Arc::new(Mutex::new(String::new())));
        }
    }
}

/// 设置错误信息
fn set_last_error(err: &str) {
    init_error_buffer();
    unsafe {
        if let Some(error_buffer) = &LAST_ERROR {
            if let Ok(mut buffer) = error_buffer.lock() {
                *buffer = err.to_string();
            }
        }
    }
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
pub extern "C" fn frame_analyzer_destroy(handle: FrameAnalyzerHandle) {
    clear_last_error();
    if !handle.is_null() {
        unsafe { Box::from_raw(handle); }
    }
}

/// 附加应用进程监控
/// 参数：handle - 句柄，pid - 进程ID
/// 返回：0=成功，负数=错误码
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
pub extern "C" fn frame_analyzer_try_recv(
    handle: FrameAnalyzerHandle,
    pid: *mut c_int,
    frametime_ns: *mut u64,
) -> c_int {
    frame_analyzer_recv(handle, pid, frametime_ns, 0)
}

/// 检查是否监控指定PID
/// 返回：1=是，0=否，负数=错误码
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
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
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
pub extern "C" fn frame_analyzer_get_last_error(_handle: FrameAnalyzerHandle) -> *const c_char {
    init_error_buffer();
    let error = unsafe {
        LAST_ERROR.as_ref().and_then(|b| b.lock().ok()).map(|s| s.clone()).unwrap_or_default()
    };
    // 静态缓冲区存储错误信息（线程安全简化版）
    static mut BUF: [u8; 256] = [0; 256];
    unsafe {
        let bytes = error.as_bytes();
        let len = bytes.len().min(255);
        BUF[..len].copy_from_slice(&bytes[..len]);
        BUF[len] = 0; // 终止符
        BUF.as_ptr() as *const c_char
    }
}

/// 获取版本号
#[unsafe(no_mangle)] // 替换为 unsafe(no_mangle) 解决编译错误
pub extern "C" fn frame_analyzer_get_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION_MAJOR"), ".", env!("CARGO_PKG_VERSION_MINOR"), ".", env!("CARGO_PKG_VERSION_PATCH")).as_ptr() as *const c_char
}

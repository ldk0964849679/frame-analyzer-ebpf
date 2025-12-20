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

use std::io;

use aya::{EbpfError, maps::MapError, programs::ProgramError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AnalyzerError>;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    /// 封装aya的核心eBPF错误
    #[error(transparent)]
    EbpfError(#[from] EbpfError),

    /// 封装eBPF程序加载/附着错误
    #[error(transparent)]
    BpfProgramError(#[from] ProgramError),

    /// 封装eBPF映射表操作错误（移除重复的MapError定义）
    #[error(transparent)]
    BpfMapError(#[from] MapError),

    /// 封装IO操作错误
    #[error(transparent)]
    IOError(#[from] io::Error),

    /// 目标应用进程未找到
    #[error("Target application with specified PID not found")]
    AppNotFound,

    /// Uprobe/USDT探针附着失败（补充安卓eBPF常用错误）
    #[error("Failed to attach uprobe to target process: {0}")]
    UprobeAttachError(String),

    /// 从eBPF映射表读取帧数据失败
    #[error("Failed to read frame data from eBPF map: {0}")]
    FrameDataReadError(String),

    /// 安卓权限不足（补充安卓平台特有错误）
    #[error("Insufficient permissions on Android (need root or CAP_BPF)")]
    AndroidPermissionDenied,
}

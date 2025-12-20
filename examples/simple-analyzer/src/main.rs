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

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use clap::Parser;
use frame_analyzer::Analyzer;
use libc::{c_int, pid_t}; // 显式导入需要的libc类型，避免未定义
use ctrlc; // 补充ctrlc的导入

/// Simple frame analyzer, print frametime on the screen
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The pid of the target application
    #[arg(short, long)]
    pid: i32,
}

// 封装安卓进程检查函数，提升代码可读性
unsafe fn check_process_exists(pid: pid_t) -> Result<()> {
    if libc::kill(pid, 0) == -1 {
        let errno = *libc::__errno_location(); // 获取安卓系统的错误码
        return Err(anyhow::anyhow!(
            "Target process {pid} does not exist (errno: {errno})"
        ));
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse(); // 变量名修正为args，符合rust命名规范
    let pid = args.pid;

    // 安卓平台检查目标进程是否存在，避免附着无效PID
    unsafe {
        check_process_exists(pid as pid_t)
            .with_context(|| format!("Failed to check process {pid}"))?;
    }

    let mut analyzer = Analyzer::new().with_context(|| "Failed to create Analyzer")?;
    analyzer.attach_app(pid).with_context(|| format!("Failed to attach to pid {pid}"))?;

    let running = Arc::new(AtomicBool::new(true));

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::Release);
            println!("\nReceived exit signal, stopping analyzer...");
        })
        .with_context(|| "Failed to set Ctrl+C handler")?;
    }

    let mut buffer = VecDeque::with_capacity(120);
    println!("Started analyzing process {pid}, press Ctrl+C to exit...");

    while running.load(Ordering::Acquire) {
        if let Some((recv_pid, frametime)) = analyzer.recv() {
            // 过滤非目标PID的帧数据，避免干扰
            if recv_pid != pid {
                continue;
            }

            println!("Frametime: {frametime:?}, PID: {recv_pid}");
            
            if buffer.len() >= buffer.capacity() { // 使用capacity替代硬编码120，提升可维护性
                buffer.pop_back();
            }
            buffer.push_front(frametime);

            // 当缓冲区满时计算平均FPS
            if buffer.len() == buffer.capacity() {
                let total_ns: f64 = buffer
                    .iter()
                    .copied()
                    .map(|d| d.as_nanos() as f64)
                    .sum();
                let avg_ns = total_ns / buffer.len() as f64; // 修复变量名错误：avgs_ns -> avg_ns
                let fps = 1_000_000_000.0 / avg_ns;
                
                println!("Average FPS (last 120 frames): {fps:.2}");
                buffer.clear(); // 计算后清空缓冲区，重新累计
            }
        } else {
            // 无数据时短暂休眠，减少CPU占用
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    println!("Analyzer stopped successfully");
    Ok(())
}

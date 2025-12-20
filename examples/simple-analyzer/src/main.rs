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

use anyhow::Result;
use clap::Parser;
use frame_analyzer::Analyzer;
// 新增libc依赖，用于安卓平台进程检查
use libc;

/// Simple frame analyzer, print frametime on the screen
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The pid of the target application
    #[arg(short, long)]
    pid: i32,
}

fn main() -> Result<()> {
    let arg = Args::parse();
    let pid = arg.pid;

    // 安卓平台检查目标进程是否存在，避免附着无效PID
    unsafe {
        if libc::kill(pid as libc::pid_t, 0) == -1 {
            return Err(anyhow::anyhow!("Target process {pid} does not exist"));
        }
    }

    let mut analyzer = Analyzer::new()?;
    analyzer.attach_app(pid)?;

    let running = Arc::new(AtomicBool::new(true));

    {
        let running = running.clone();
        // 修复：添加ctrlc依赖的导入（原代码漏引）
        ctrlc::set_handler(move || {
            running.store(false, Ordering::Release);
        })?;
    }

    let mut buffer = VecDeque::with_capacity(120);

    while running.load(Ordering::Acquire) {
        if let Some((pid, frametime)) = analyzer.recv() {
            println!("frametime: {frametime:?}, pid: {pid}");
            if buffer.len() >= 120 {
                buffer.pop_back();
            }
            buffer.push_front(frametime);
            if buffer.len() == 120 {
                // 修复：Duration不支持直接除法，转为纳秒浮点值计算帧率
                let total_ns = buffer.iter()
                    .copied()
                    .map(|d| d.as_nanos() as f64)
                    .sum::<f64>();
                let avgs_ns = total_ns / buffer.len() as f64;
                let fps = 1_000_000_000.0 / avg_ns;
                // 优化：保留两位小数输出帧率，更易读
                println!("Average FPS: {fps:.2}");
            }
        }
    }

    Ok(())
}

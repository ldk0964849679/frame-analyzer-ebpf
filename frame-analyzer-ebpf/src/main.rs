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

#![no_std]
#![no_main]
#![allow(clippy::unused_unit)] // 抑制aya-ebpf宏的未使用单元警告

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
    BpfContext,
};

use frame_analyzer_ebpf_common::FrameSignal;

// 适配aya-ebpf 0.1.1：RingBuf使用默认构造，容量通过map配置（该版本with_byte_size未实现）
#[map]
static RING_BUF: RingBuf = RingBuf::new(0); // 0为占位，实际容量由用户态加载时指定

#[uprobe]
pub fn frame_analyzer_ebpf(ctx: ProbeContext) -> u32 {
    match try_frame_analyzer_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_frame_analyzer_ebpf(mut ctx: ProbeContext) -> Result<u32, u32> {
    // 修复：ProbeContext.arg在0.1.1中返回Result，而非Option
    let arg0 = ctx.arg::<usize>(0).map_err(|_| 1)?; // 错误码1：参数获取失败

    // 修复：RingBuf.reserve在0.1.1中返回Result，而非Option
    let mut entry = RING_BUF.reserve::<FrameSignal>().map_err(|_| 2)?; // 错误码2：缓冲区满

    // 安全调用bpf_ktime_get_ns（eBPF内核辅助函数，无未定义行为）
    let ktime_ns = bpf_ktime_get_ns();

    // 写入帧信号数据并提交
    entry.write(FrameSignal::new(ktime_ns, arg0));
    entry.submit();

    Ok(0)
}

// 优化panic_handler：使用eBPF友好的自旋循环，避免编译器优化掉空循环
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe {
            aya_ebpf::helpers::bpf_ktime_get_ns(); // 调用内核辅助函数，防止循环被优化
            core::hint::spin_loop();
        }
    }
}

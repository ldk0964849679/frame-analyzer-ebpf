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

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
    BpfContext,
};

use frame_analyzer_ebpf_common::FrameSignal;

// 修复：RingBuf容量使用常量定义，移除无效的第二个参数（0），符合aya-ebpf 0.1.1规范
const RING_BUF_SIZE: u32 = 0x1000;
#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE);

#[uprobe]
pub fn frame_analyzer_ebpf(ctx: ProbeContext) -> u32 {
    match try_frame_analyzer_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_frame_analyzer_ebpf(mut ctx: ProbeContext) -> Result<u32, u32> {
    // 修复1：错误处理ctx.arg获取失败的情况，避免unwrap()导致eBPF程序崩溃
    let arg0 = ctx.arg::<usize>(0).ok_or(1)?; // 错误码1表示参数获取失败

    // 修复2：拆分RingBuf.reserve和数据写入，添加错误处理
    let mut entry = RING_BUF.reserve::<FrameSignal>().ok_or(2)?; // 错误码2表示缓冲区满
    let ktime_ns = unsafe { bpf_ktime_get_ns() };

    entry.write(FrameSignal::new(ktime_ns, arg0));
    entry.submit();

    Ok(0)
}

// 修复3：完善panic_handler，避免未定义行为
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::hint::spin_loop() };
    }
}

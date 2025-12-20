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
use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::{ProgramError, UProbe},
};

use crate::{ebpf::load_bpf, error::AnalyzerError, error::Result};

pub struct UprobeHandler {
    bpf: Ebpf,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        // 修复：完善卸载错误的日志提示（可替换为项目日志库）
        if let Err(e) = self.get_program().and_then(|p| p.unload()) {
            eprintln!("Failed to unload uprobe program: {e}");
        }
    }
}

impl UprobeHandler {
    pub fn attach_app(pid: i32) -> Result<Self> {
        let mut bpf = load_bpf()?;

        // 修复1：替换unwrap()，添加程序查找失败的错误处理
        let program = bpf.program_mut("frame_analyzer_ebpf")
            .ok_or_else(|| AnalyzerError::BpfProgramError(ProgramError::NotFound))?;
        let program: &mut UProbe = program.try_into()?;

        program.load()?;

        // 尝试挂载第一个符号
        let attach_result = program.attach(
            Some("_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi"),
            0,
            "/system/lib64/libgui.so",
            Some(pid),
        );

        // 挂载失败则尝试第二个符号，并保留具体错误信息
        if let Err(e1) = attach_result {
            program.attach(
                Some("_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE"),
                0,
                "/system/lib64/libgui.so",
                Some(pid),
            ).map_err(|e2| AnalyzerError::UprobeAttachError(format!(
                "Failed to attach both symbols: first {e1}, second {e2}"
            )))?;
        }

        Ok(Self { bpf })
    }

    pub fn ring(&mut self) -> Result<RingBuf<&mut MapData>> {
        // 修复2：替换unwrap()，添加Map查找失败的错误处理
        let ring_map = self.bpf.map_mut("RING_BUF")
            .ok_or_else(|| AnalyzerError::BpfMapError("RING_BUF not found".into()))?;
        let ring: RingBuf<&mut MapData> = RingBuf::try_from(ring_map)?;

        Ok(ring)
    }

    fn get_program(&mut self) -> Result<&mut UProbe> {
        // 修复3：统一程序查找的错误处理逻辑，与attach_app保持一致
        let program = self.bpf.program_mut("frame_analyzer_ebpf")
            .ok_or_else(|| AnalyzerError::BpfProgramError(ProgramError::NotFound))?;
        let program: &mut UProbe = program.try_into()?;

        Ok(program)
    }
}

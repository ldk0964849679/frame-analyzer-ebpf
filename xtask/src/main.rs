use anyhow::Result;
use clap::Parser;
use std::process::Command;

#[derive(Parser)]
enum Command {
    BuildEbpf,
}

fn main() -> Result<()> {
    let cmd = Command::parse();
    match cmd {
        Command::BuildEbpf => build_ebpf()?,
    }
    Ok(())
}

fn build_ebpf() -> Result<()> {
    // 直接调用rustc编译eBPF程序，适配aya-ebpf 0.1.1
    Command::new("cargo")
        .args([
            "build",
            "--target", "bpfel-unknown-none",
            "--manifest-path", "frame-analyzer-ebpf/Cargo.toml",
            "--release",
        ])
        .status()?;
    Ok(())
}

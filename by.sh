#!/bin/bash
set -e

# 创建cargo配置文件启用build-std
mkdir -p .cargo
cat > .cargo/config.toml << EOF
[unstable]
build-std = ["core"]
build-std-features = ["compiler-builtins-mem"]
EOF

# 关键：删除disable-redzone，仅保留eBPF兼容参数
export RUSTFLAGS="-C linker=bpf-linker -C link-arg=--target=bpfel-unknown-none -C link-arg=--cpu=generic --cfg aya_ebpf -C target-feature=+alu32 -C force-frame-pointers=off"

# 切换Nightly工具链
rustup override set nightly

# 编译eBPF程序
cargo build --target bpfel-unknown-none --release -p frame-analyzer-ebpf

# 验证产物
echo -e "\n编译完成，eBPF字节码路径："
ls -l target/bpfel-unknown-none/release/frame_analyzer_ebpf.bpf.o

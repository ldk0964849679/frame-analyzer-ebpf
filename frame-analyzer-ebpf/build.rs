fn main() {
    // 使用aya-tool编译eBPF程序，适配aya-ebpf 0.1.1版本
    aya_tool::build_ebpf(
        "./src/main.rs",    // eBPF程序入口文件
        "bpfel-unknown-none",// 目标架构
        false,              // 是否开启调试模式（false为release编译）
    )
    .unwrap_or_else(|e| {
        // 自定义错误提示，方便定位编译问题
        eprintln!("Failed to build eBPF program with aya-tool: {e}");
        std::process::exit(1);
    });
}

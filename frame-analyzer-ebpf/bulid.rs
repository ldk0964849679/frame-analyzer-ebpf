fn main() {
    aya_ebpf_builder::build_ebpf::<()>(
        "./src/main.rs",
        &["-C", "opt-level=3"],
        "bpfel-unknown-none",
        None,
    )
    .unwrap();
}

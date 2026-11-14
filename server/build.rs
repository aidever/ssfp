// 编译 bpf/syn_rewrite.bpf.c 为 BPF 目标文件，供 ebpf.rs 用 include_bytes! 嵌入。
use std::process::Command;

fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    let src = "bpf/syn_rewrite.bpf.c";
    println!("cargo:rerun-if-changed={src}");
    // 用宿主机的内核头文件（asm/ 在多架构目录下）
    let arch_inc = format!("-I/usr/include/{}-linux-gnu", std::env::consts::ARCH);
    let st = Command::new(std::env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
        .args(["-O2", "-g", "-target", "bpf", &arch_inc, "-c", src, "-o"])
        .arg(format!("{out}/syn_rewrite.o"))
        .status()
        .expect("需要 clang 来编译 eBPF 程序");
    assert!(st.success(), "编译 eBPF 程序失败");
}

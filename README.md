# hide-me

## 使用 pahole 查看内核数据结构

```shell
pahole -C task_struct | grep tgid
```

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run -- --ppid 123456
```

## pid 与 tgid 的说明与过滤方法（虽然本次基本没用上）

[如何在 BPF 程序中正确地按照 PID 过滤？](https://www.ebpf.top/post/ebpf_prog_pid_filter/)

## 如何查看系统调用参数

```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format

cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_getdents64/format
```

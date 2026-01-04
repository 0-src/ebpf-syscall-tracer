use aya::{
    maps::RingBuf,
    programs::TracePoint,
};
#[rustfmt::skip]
use log::debug;
use syscall_tracer_common::{EventKind, TraceEvent};
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/syscall-tracer"
    )))?;

    let program: &mut TracePoint = ebpf.program_mut("syscall_tracer").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let program: &mut TracePoint = ebpf.program_mut("trace_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut poll = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

    println!("{:<5} {:>8} {:>8} {:<16} PATH", "KIND", "PID", "UID", "COMM");
    tokio::spawn(async move {
        loop {
            let Ok(mut guard) = poll.readable_mut().await else {
                break;
            };
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                print_trace_event(&item);
            }
            guard.clear_ready();
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn print_trace_event(raw: &[u8]) {
    if raw.len() < core::mem::size_of::<TraceEvent>() {
        return;
    }
    // SAFETY: `raw` comes from the EVENTS ring buffer, which only ever holds
    // `TraceEvent` records written by the ebpf program (see syscall-tracer-ebpf).
    let event = unsafe { &*(raw.as_ptr() as *const TraceEvent) };
    let kind = match event.kind {
        k if k == EventKind::Exec as u8 => "EXEC",
        k if k == EventKind::Write as u8 => "WRITE",
        _ => "?",
    };
    let comm = core::str::from_utf8(&event.comm)
        .unwrap_or("")
        .trim_end_matches('\0');
    let path = core::str::from_utf8(&event.path[..event.path_len as usize]).unwrap_or("<invalid utf8>");
    println!("{:<5} {:>8} {:>8} {:<16} {}", kind, event.pid, event.uid, comm, path);
}

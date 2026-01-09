mod detection;
mod jsonlog;
mod tui;

use std::sync::mpsc::Sender;

use aya::{
    maps::RingBuf,
    programs::TracePoint,
};
#[rustfmt::skip]
use log::debug;
use syscall_tracer_common::{EventKind, TraceEvent};
use tokio::io::{Interest, unix::AsyncFd};

use detection::{
    DropperDetector, PersistenceWriteDetector, ProcFsFdKind, ProcFsParentLookup, PtraceDetector,
    ReverseShellDetector, SelfReplaceDetector,
};
use jsonlog::JsonLog;
use tui::DisplayEvent;

/// A write immediately followed by an exec of the same path, within this
/// window, is flagged as a dropper.
const DROPPER_WINDOW_NS: u64 = 2_000_000_000; // 2s

/// A process unlinking its own binary, then re-exec'ing the same path,
/// within this window, is flagged as a self-replace.
const SELF_REPLACE_WINDOW_NS: u64 = 2_000_000_000; // 2s

const JSON_LOG_PATH: &str = "syscall-tracer.jsonl";

struct Detectors {
    dropper: DropperDetector,
    self_replace: SelfReplaceDetector,
    ptrace: PtraceDetector<ProcFsParentLookup>,
    reverse_shell: ReverseShellDetector<ProcFsFdKind>,
    persistence: PersistenceWriteDetector,
}

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

    let program: &mut TracePoint = ebpf.program_mut("trace_unlinkat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_unlinkat")?;

    let program: &mut TracePoint = ebpf.program_mut("trace_unlink").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_unlink")?;

    let program: &mut TracePoint = ebpf.program_mut("trace_ptrace").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_ptrace")?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut poll = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

    let mut json_log = JsonLog::open(JSON_LOG_PATH)?;

    let (tx, rx) = std::sync::mpsc::channel::<DisplayEvent>();

    println!("All probes attached. Logging to {JSON_LOG_PATH}. Launching UI...");

    tokio::spawn(async move {
        let mut detectors = Detectors {
            dropper: DropperDetector::new(DROPPER_WINDOW_NS),
            self_replace: SelfReplaceDetector::new(SELF_REPLACE_WINDOW_NS),
            ptrace: PtraceDetector::new(ProcFsParentLookup),
            reverse_shell: ReverseShellDetector::new(ProcFsFdKind),
            persistence: PersistenceWriteDetector::new(),
        };
        loop {
            let Ok(mut guard) = poll.readable_mut().await else {
                break;
            };
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                handle_trace_event(&item, &mut detectors, &mut json_log, &tx);
            }
            guard.clear_ready();
        }
    });

    // Blocking: crossterm's event polling is synchronous, so the TUI runs on
    // its own thread rather than as an async task.
    tokio::task::spawn_blocking(move || tui::run(rx)).await??;

    // `ebpf` is still in scope here and drops on return, detaching the probes.
    Ok(())
}

fn handle_trace_event(raw: &[u8], detectors: &mut Detectors, json_log: &mut JsonLog, tx: &Sender<DisplayEvent>) {
    if raw.len() < core::mem::size_of::<TraceEvent>() {
        return;
    }
    // SAFETY: `raw` comes from the EVENTS ring buffer, which only ever holds
    // `TraceEvent` records written by the ebpf program (see syscall-tracer-ebpf).
    let event = unsafe { &*(raw.as_ptr() as *const TraceEvent) };
    let Some(kind) = EventKind::from_u8(event.kind) else {
        return;
    };
    let comm = core::str::from_utf8(&event.comm)
        .unwrap_or("")
        .trim_end_matches('\0');
    let path = core::str::from_utf8(&event.path[..event.path_len as usize]).unwrap_or("<invalid utf8>");

    let kind_label = match kind {
        EventKind::Exec => "EXEC",
        EventKind::Write => "WRITE",
        EventKind::Unlink => "UNLINK",
        EventKind::Ptrace => "PTRACE",
    };
    let event_text = if kind == EventKind::Ptrace {
        format!(
            "{:<6} {:>8} {:>8} {:<16} target_pid={}",
            kind_label, event.pid, event.uid, comm, event.target_pid
        )
    } else {
        format!("{:<6} {:>8} {:>8} {:<16} {}", kind_label, event.pid, event.uid, comm, path)
    };
    let _ = tx.send(DisplayEvent::Trace {
        kind: kind_label,
        text: event_text,
    });
    json_log.log_event(kind_label, event.pid, event.uid, comm, path, event.target_pid);

    if let Some(alert) = detectors.dropper.observe(kind, event.pid, event.uid, path, event.ktime_ns) {
        let text = format!(
            "pid={} uid={} wrote then exec'd {} ({}ms later)",
            alert.pid, alert.uid, alert.path, alert.delta_ms
        );
        json_log.log_alert("dropper", alert.pid, alert.uid, &alert.path, text.clone());
        let _ = tx.send(DisplayEvent::Alert { rule: "dropper", text });
    }

    if let Some(alert) = detectors
        .self_replace
        .observe(kind, event.pid, event.uid, path, event.ktime_ns)
    {
        let text = format!(
            "pid={} uid={} unlinked then re-exec'd {} ({}ms later)",
            alert.pid, alert.uid, alert.path, alert.delta_ms
        );
        json_log.log_alert("self-replace", alert.pid, alert.uid, &alert.path, text.clone());
        let _ = tx.send(DisplayEvent::Alert {
            rule: "self-replace",
            text,
        });
    }

    if kind == EventKind::Ptrace {
        if let Some(alert) = detectors.ptrace.observe(event.pid, event.uid, event.target_pid) {
            let text = format!(
                "pid={} uid={} attached to unrelated pid {}",
                alert.tracer_pid, alert.tracer_uid, alert.target_pid
            );
            json_log.log_alert("ptrace", alert.tracer_pid, alert.tracer_uid, "", text.clone());
            let _ = tx.send(DisplayEvent::Alert { rule: "ptrace", text });
        }
    }

    if kind == EventKind::Exec {
        if let Some(alert) = detectors.reverse_shell.observe(event.pid, event.uid, path) {
            let text = format!("pid={} uid={} {} has a socket on stdin/stdout", alert.pid, alert.uid, alert.path);
            json_log.log_alert("reverse-shell", alert.pid, alert.uid, &alert.path, text.clone());
            let _ = tx.send(DisplayEvent::Alert {
                rule: "reverse-shell",
                text,
            });
        }
    }

    if kind == EventKind::Write {
        if let Some(alert) = detectors.persistence.observe(event.pid, event.uid, path) {
            let text = format!(
                "pid={} uid={} wrote {} ({})",
                alert.pid,
                alert.uid,
                alert.path,
                alert.category.label()
            );
            json_log.log_alert("persistence", alert.pid, alert.uid, &alert.path, text.clone());
            let _ = tx.send(DisplayEvent::Alert {
                rule: "persistence",
                text,
            });
        }
    }
}

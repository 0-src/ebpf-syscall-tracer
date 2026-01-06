#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use syscall_tracer_common::{COMM_LEN, EventKind, PATH_LEN, TraceEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Syscall tracepoint records store the raw syscall args as consecutive 8-byte
// slots starting right after the 8-byte common header + 4-byte __syscall_nr
// (padded to 8), regardless of each arg's declared C type. Offsets below are
// read from /sys/kernel/debug/tracing/events/syscalls/<name>/format (x86_64).

// sys_enter_execve(filename, argv, envp): filename is arg0.
const EXECVE_FILENAME_OFFSET: usize = 16;

// sys_enter_openat(dfd, filename, flags, mode): filename is arg1, flags is arg2.
const OPENAT_FILENAME_OFFSET: usize = 24;
const OPENAT_FLAGS_OFFSET: usize = 32;
const O_CREAT: i64 = 0o100;

// sys_enter_unlinkat(dfd, pathname, flag): pathname is arg1.
const UNLINKAT_PATHNAME_OFFSET: usize = 24;

// sys_enter_unlink(pathname): pathname is arg0. Legacy syscall (nr 87 on
// x86_64) — still what glibc's unlink() issues directly on at least some
// libc/kernel combos, rather than routing through unlinkat like open() does
// through openat(). Trace both to not miss it.
const UNLINK_PATHNAME_OFFSET: usize = 16;

// sys_enter_ptrace(request, pid, addr, data): request is arg0, target pid is arg1.
const PTRACE_REQUEST_OFFSET: usize = 16;
const PTRACE_PID_OFFSET: usize = 24;
// Only these two requests actually attach to an *existing* process; everything
// else (PEEK/POKE/CONT/... or PTRACE_TRACEME, which a child issues on itself)
// either requires an existing attach already or is the ordinary, benign
// debugger-launches-its-own-child pattern.
const PTRACE_ATTACH: i64 = 16;
const PTRACE_SEIZE: i64 = 0x4206;

#[tracepoint]
pub fn syscall_tracer(ctx: TracePointContext) -> u32 {
    match try_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let path_ptr = unsafe {
        ctx.read_at::<*const u8>(EXECVE_FILENAME_OFFSET)
            .map_err(|_| 1u32)?
    };
    emit(EventKind::Exec, path_ptr)
}

#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    match try_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_openat(ctx: TracePointContext) -> Result<u32, u32> {
    // Only a creating open is interesting here (a brand new file being
    // written); plain reads/writes of existing files are noise for the
    // dropper signal this feeds.
    let flags = unsafe { ctx.read_at::<i64>(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)? };
    if flags & O_CREAT == 0 {
        return Ok(0);
    }

    let path_ptr = unsafe {
        ctx.read_at::<*const u8>(OPENAT_FILENAME_OFFSET)
            .map_err(|_| 1u32)?
    };
    emit(EventKind::Write, path_ptr)
}

#[tracepoint]
pub fn trace_unlinkat(ctx: TracePointContext) -> u32 {
    match try_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_unlinkat(ctx: TracePointContext) -> Result<u32, u32> {
    let path_ptr = unsafe {
        ctx.read_at::<*const u8>(UNLINKAT_PATHNAME_OFFSET)
            .map_err(|_| 1u32)?
    };
    emit(EventKind::Unlink, path_ptr)
}

#[tracepoint]
pub fn trace_unlink(ctx: TracePointContext) -> u32 {
    match try_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_unlink(ctx: TracePointContext) -> Result<u32, u32> {
    let path_ptr = unsafe {
        ctx.read_at::<*const u8>(UNLINK_PATHNAME_OFFSET)
            .map_err(|_| 1u32)?
    };
    emit(EventKind::Unlink, path_ptr)
}

#[tracepoint]
pub fn trace_ptrace(ctx: TracePointContext) -> u32 {
    match try_ptrace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ptrace(ctx: TracePointContext) -> Result<u32, u32> {
    let request = unsafe { ctx.read_at::<i64>(PTRACE_REQUEST_OFFSET).map_err(|_| 1u32)? };
    if request != PTRACE_ATTACH && request != PTRACE_SEIZE {
        return Ok(0);
    }

    let target_pid = unsafe { ctx.read_at::<i64>(PTRACE_PID_OFFSET).map_err(|_| 1u32)? };
    emit_ptrace(target_pid as u32)
}

fn emit(kind: EventKind, path_ptr: *const u8) -> Result<u32, u32> {
    let mut event = TraceEvent {
        kind: kind as u8,
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        comm: [0u8; COMM_LEN],
        path: [0u8; PATH_LEN],
        path_len: 0,
        target_pid: 0,
    };

    event.comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    let path = unsafe { bpf_probe_read_user_str_bytes(path_ptr, &mut event.path).map_err(|_| 1u32)? };
    event.path_len = path.len() as u32;

    if let Some(mut entry) = EVENTS.reserve::<TraceEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

fn emit_ptrace(target_pid: u32) -> Result<u32, u32> {
    let mut event = TraceEvent {
        kind: EventKind::Ptrace as u8,
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        comm: [0u8; COMM_LEN],
        path: [0u8; PATH_LEN],
        path_len: 0,
        target_pid,
    };

    event.comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    if let Some(mut entry) = EVENTS.reserve::<TraceEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

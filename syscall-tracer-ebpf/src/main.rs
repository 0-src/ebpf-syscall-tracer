#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use syscall_tracer_common::{COMM_LEN, ExecEvent, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Offset of `const char *filename` in the sys_enter_execve tracepoint record, per
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format (x86_64: 8-byte
// common header + 4-byte __syscall_nr + 4-byte padding).
const FILENAME_OFFSET: usize = 16;

#[tracepoint]
pub fn syscall_tracer(ctx: TracePointContext) -> u32 {
    match try_syscall_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_syscall_tracer(ctx: TracePointContext) -> Result<u32, u32> {
    let mut event = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        comm: [0u8; COMM_LEN],
        filename: [0u8; PATH_LEN],
        filename_len: 0,
    };

    event.comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    let filename_ptr = unsafe { ctx.read_at::<*const u8>(FILENAME_OFFSET).map_err(|_| 1u32)? };
    let filename = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename).map_err(|_| 1u32)?
    };
    event.filename_len = filename.len() as u32;

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
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

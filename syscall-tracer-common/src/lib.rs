#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

/// A single execve(2) call, captured at the syscalls:sys_enter_execve tracepoint.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN],
    pub filename_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

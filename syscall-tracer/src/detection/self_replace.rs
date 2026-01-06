use std::collections::HashMap;

use syscall_tracer_common::EventKind;

/// A process unlinking its own on-disk binary, then re-exec'ing the same
/// path within the window: the file underneath that path changed out from
/// under the running image. Used to replace a binary in place while it's
/// running, or to remove the original from disk without stopping.
pub struct SelfReplaceDetector {
    window_ns: u64,
    // pid -> path it last exec'd, so an unlink can be checked against "is
    // this process deleting the file it's currently running as".
    current_exe: HashMap<u32, (String, u64)>,
    // pid -> (path, ktime_ns) of a self-unlink still waiting for a re-exec.
    pending_self_unlink: HashMap<u32, (String, u64)>,
}

pub struct SelfReplaceAlert {
    pub pid: u32,
    pub uid: u32,
    pub path: String,
    pub delta_ms: u64,
}

impl SelfReplaceDetector {
    pub fn new(window_ns: u64) -> Self {
        Self {
            window_ns,
            current_exe: HashMap::new(),
            pending_self_unlink: HashMap::new(),
        }
    }

    /// Feed one decoded event. Returns `Some(SelfReplaceAlert)` if this event
    /// completes a self-unlink→re-exec pattern within the window.
    pub fn observe(&mut self, kind: EventKind, pid: u32, uid: u32, path: &str, ktime_ns: u64) -> Option<SelfReplaceAlert> {
        match kind {
            EventKind::Exec => {
                let alert = match self.pending_self_unlink.remove(&pid) {
                    Some((unlink_path, unlink_ktime)) if unlink_path == path => {
                        let delta_ns = ktime_ns.saturating_sub(unlink_ktime);
                        (delta_ns <= self.window_ns).then(|| SelfReplaceAlert {
                            pid,
                            uid,
                            path: path.to_owned(),
                            delta_ms: delta_ns / 1_000_000,
                        })
                    }
                    _ => None,
                };
                self.current_exe.insert(pid, (path.to_owned(), ktime_ns));
                self.prune(ktime_ns);
                alert
            }
            EventKind::Unlink => {
                if let Some((exe_path, _)) = self.current_exe.get(&pid) {
                    if exe_path == path {
                        self.pending_self_unlink.insert(pid, (path.to_owned(), ktime_ns));
                    }
                }
                None
            }
            EventKind::Write | EventKind::Ptrace => None,
        }
    }

    /// Bound memory: forget which binary a pid is running once it's been
    /// quiet for a while (long past any plausible self-replace window).
    fn prune(&mut self, now_ns: u64) {
        let ttl_ns = self.window_ns.max(60_000_000_000); // at least 60s
        self.current_exe
            .retain(|_, &mut (_, ts)| now_ns.saturating_sub(ts) <= ttl_ns);
        let window_ns = self.window_ns;
        self.pending_self_unlink
            .retain(|_, &mut (_, ts)| now_ns.saturating_sub(ts) <= window_ns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_SEC_NS: u64 = 1_000_000_000;

    #[test]
    fn flags_self_unlink_then_reexec_within_window() {
        let mut d = SelfReplaceDetector::new(2 * ONE_SEC_NS);
        assert!(d.observe(EventKind::Exec, 100, 0, "/opt/agent", 0).is_none());
        assert!(d.observe(EventKind::Unlink, 100, 0, "/opt/agent", 100).is_none());
        let alert = d
            .observe(EventKind::Exec, 100, 0, "/opt/agent", ONE_SEC_NS)
            .expect("unlink->reexec of own path within window should alert");
        assert_eq!(alert.path, "/opt/agent");
    }

    #[test]
    fn ignores_unlink_of_a_different_file() {
        let mut d = SelfReplaceDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Exec, 100, 0, "/opt/agent", 0);
        d.observe(EventKind::Unlink, 100, 0, "/tmp/scratch", 100);
        assert!(d.observe(EventKind::Exec, 100, 0, "/opt/agent", 200).is_none());
    }

    #[test]
    fn ignores_unlink_by_an_unrelated_process() {
        let mut d = SelfReplaceDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Exec, 100, 0, "/opt/agent", 0);
        // pid 200 has never exec'd /opt/agent, so its unlink of that path
        // isn't a self-unlink.
        d.observe(EventKind::Unlink, 200, 0, "/opt/agent", 100);
        assert!(d.observe(EventKind::Exec, 200, 0, "/opt/agent", 200).is_none());
    }

    #[test]
    fn ignores_reexec_outside_window() {
        let mut d = SelfReplaceDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Exec, 100, 0, "/opt/agent", 0);
        d.observe(EventKind::Unlink, 100, 0, "/opt/agent", 100);
        assert!(d.observe(EventKind::Exec, 100, 0, "/opt/agent", 10 * ONE_SEC_NS).is_none());
    }

    #[test]
    fn plain_reexec_without_unlink_does_not_alert() {
        let mut d = SelfReplaceDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Exec, 100, 0, "/opt/agent", 0);
        assert!(d.observe(EventKind::Exec, 100, 0, "/opt/agent", 100).is_none());
    }
}

use std::collections::HashMap;

use syscall_tracer_common::EventKind;

/// Write→exec of the same path by the same pid, within the window: something
/// was written to disk and immediately run. Classic dropper shape.
pub struct DropperDetector {
    window_ns: u64,
    recent_writes: HashMap<(u32, String), u64>,
}

pub struct DropperAlert {
    pub pid: u32,
    pub uid: u32,
    pub path: String,
    pub delta_ms: u64,
}

impl DropperDetector {
    pub fn new(window_ns: u64) -> Self {
        Self {
            window_ns,
            recent_writes: HashMap::new(),
        }
    }

    /// Feed one decoded event. Returns `Some(DropperAlert)` if this event
    /// completes a write→exec pattern within the window.
    pub fn observe(&mut self, kind: EventKind, pid: u32, uid: u32, path: &str, ktime_ns: u64) -> Option<DropperAlert> {
        match kind {
            EventKind::Write => {
                self.recent_writes.insert((pid, path.to_owned()), ktime_ns);
                self.prune(ktime_ns);
                None
            }
            EventKind::Exec => {
                let write_ktime = self.recent_writes.remove(&(pid, path.to_owned()))?;
                let delta_ns = ktime_ns.saturating_sub(write_ktime);
                (delta_ns <= self.window_ns).then(|| DropperAlert {
                    pid,
                    uid,
                    path: path.to_owned(),
                    delta_ms: delta_ns / 1_000_000,
                })
            }
        }
    }

    /// Drop write records older than the window so a pid/path that's never
    /// exec'd doesn't stay resident forever.
    fn prune(&mut self, now_ns: u64) {
        let window_ns = self.window_ns;
        self.recent_writes
            .retain(|_, &mut ts| now_ns.saturating_sub(ts) <= window_ns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_SEC_NS: u64 = 1_000_000_000;

    #[test]
    fn flags_write_then_exec_within_window() {
        let mut d = DropperDetector::new(2 * ONE_SEC_NS);
        assert!(d.observe(EventKind::Write, 100, 0, "/tmp/x", 0).is_none());
        let alert = d
            .observe(EventKind::Exec, 100, 0, "/tmp/x", ONE_SEC_NS / 2)
            .expect("write->exec within window should alert");
        assert_eq!(alert.delta_ms, 500);
        assert_eq!(alert.path, "/tmp/x");
    }

    #[test]
    fn ignores_exec_outside_window() {
        let mut d = DropperDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Write, 100, 0, "/tmp/x", 0);
        assert!(d.observe(EventKind::Exec, 100, 0, "/tmp/x", 5 * ONE_SEC_NS).is_none());
    }

    #[test]
    fn ignores_exec_of_a_path_never_written() {
        let mut d = DropperDetector::new(ONE_SEC_NS);
        assert!(d.observe(EventKind::Exec, 100, 0, "/usr/bin/ls", 0).is_none());
    }

    #[test]
    fn does_not_correlate_across_pids() {
        let mut d = DropperDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Write, 100, 0, "/tmp/x", 0);
        assert!(d.observe(EventKind::Exec, 200, 0, "/tmp/x", 100).is_none());
    }

    #[test]
    fn fires_once_per_write() {
        let mut d = DropperDetector::new(ONE_SEC_NS);
        d.observe(EventKind::Write, 100, 0, "/tmp/x", 0);
        assert!(d.observe(EventKind::Exec, 100, 0, "/tmp/x", 100).is_some());
        assert!(d.observe(EventKind::Exec, 100, 0, "/tmp/x", 200).is_none());
    }
}

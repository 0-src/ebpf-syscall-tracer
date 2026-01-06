/// Resolves a pid's parent pid, so a `PTRACE_ATTACH`/`PTRACE_SEIZE` can be
/// checked against "is the tracer actually this process's parent" (the
/// ordinary debugger-launches-its-own-child pattern) rather than an
/// unrelated process reaching in.
pub trait ParentPidLookup {
    fn parent_pid(&self, pid: u32) -> Option<u32>;
}

/// Real lookup via `/proc/<pid>/status`'s `PPid:` field.
pub struct ProcFsParentLookup;

impl ParentPidLookup for ProcFsParentLookup {
    fn parent_pid(&self, pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|rest| rest.trim().parse().ok())
    }
}

pub struct PtraceAlert {
    pub tracer_pid: u32,
    pub tracer_uid: u32,
    pub target_pid: u32,
}

/// A `PTRACE_ATTACH`/`PTRACE_SEIZE` where the tracer isn't the target's
/// parent: cross-process ptrace, the shape used for credential dumping and
/// process injection. Stateless — each attach is checked against live
/// process ancestry, not correlated against prior events.
pub struct PtraceDetector<L: ParentPidLookup> {
    lookup: L,
}

impl<L: ParentPidLookup> PtraceDetector<L> {
    pub fn new(lookup: L) -> Self {
        Self { lookup }
    }

    /// Call only for PTRACE_ATTACH / PTRACE_SEIZE events (the ebpf side
    /// already filters to just those requests). If ancestry can't be
    /// resolved at all (e.g. the target already exited), that fails secure:
    /// treated as unrelated rather than silently ignored.
    pub fn observe(&self, tracer_pid: u32, tracer_uid: u32, target_pid: u32) -> Option<PtraceAlert> {
        if tracer_pid == target_pid {
            return None;
        }
        match self.lookup.parent_pid(target_pid) {
            Some(ppid) if ppid == tracer_pid => None,
            _ => Some(PtraceAlert {
                tracer_pid,
                tracer_uid,
                target_pid,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct FakeLookup(HashMap<u32, u32>);

    impl ParentPidLookup for FakeLookup {
        fn parent_pid(&self, pid: u32) -> Option<u32> {
            self.0.get(&pid).copied()
        }
    }

    #[test]
    fn flags_attach_to_unrelated_process() {
        let mut ancestry = HashMap::new();
        ancestry.insert(500, 400); // pid 500's real parent is 400
        let d = PtraceDetector::new(FakeLookup(ancestry));
        let alert = d.observe(999, 0, 500).expect("999 is not 500's parent");
        assert_eq!(alert.target_pid, 500);
    }

    #[test]
    fn ignores_parent_tracing_own_child() {
        let mut ancestry = HashMap::new();
        ancestry.insert(500, 400);
        let d = PtraceDetector::new(FakeLookup(ancestry));
        assert!(d.observe(400, 0, 500).is_none());
    }

    #[test]
    fn ignores_self_trace() {
        let d = PtraceDetector::new(FakeLookup(HashMap::new()));
        assert!(d.observe(100, 0, 100).is_none());
    }

    #[test]
    fn flags_when_target_ancestry_cannot_be_resolved() {
        let d = PtraceDetector::new(FakeLookup(HashMap::new()));
        let alert = d
            .observe(999, 0, 12345)
            .expect("unresolvable ancestry should fail secure, not be ignored");
        assert_eq!(alert.target_pid, 12345);
    }
}

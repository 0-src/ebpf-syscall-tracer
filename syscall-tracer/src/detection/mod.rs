pub mod dropper;
pub mod persistence;
pub mod ptrace;
pub mod reverse_shell;
pub mod self_replace;

pub use dropper::DropperDetector;
pub use persistence::PersistenceWriteDetector;
pub use ptrace::{ProcFsParentLookup, PtraceDetector};
pub use reverse_shell::{ProcFsFdKind, ReverseShellDetector};
pub use self_replace::SelfReplaceDetector;

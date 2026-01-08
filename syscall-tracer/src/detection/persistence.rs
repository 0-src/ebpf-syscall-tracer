const CRON_PREFIXES: &[&str] = &[
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
];
const CRON_EXACT: &[&str] = &["/etc/crontab"];

const SYSTEMD_PREFIXES: &[&str] = &[
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "/run/systemd/system/",
];
const SYSTEMD_USER_INFIX: &str = "/.config/systemd/user/";

const SHELL_RC_BASENAMES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".cshrc",
    ".tcshrc",
];
const SHELL_RC_EXACT: &[&str] = &["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"];
const SHELL_RC_PROFILE_D_PREFIX: &str = "/etc/profile.d/";

#[derive(Debug, PartialEq, Eq)]
pub enum PersistenceCategory {
    Cron,
    Systemd,
    ShellRc,
}

impl PersistenceCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Cron => "cron",
            Self::Systemd => "systemd",
            Self::ShellRc => "shell-rc",
        }
    }
}

pub struct PersistenceAlert {
    pub pid: u32,
    pub uid: u32,
    pub path: String,
    pub category: PersistenceCategory,
}

/// A write into a known persistence location: cron dirs, systemd unit
/// paths, or shell rc files. Stateless path classification — no timing
/// correlation, since the write itself is already the whole signal.
pub struct PersistenceWriteDetector;

impl PersistenceWriteDetector {
    pub fn new() -> Self {
        Self
    }

    /// Call only for Write events.
    pub fn observe(&self, pid: u32, uid: u32, path: &str) -> Option<PersistenceAlert> {
        let category = classify(path)?;
        Some(PersistenceAlert {
            pid,
            uid,
            path: path.to_owned(),
            category,
        })
    }
}

fn classify(path: &str) -> Option<PersistenceCategory> {
    if CRON_PREFIXES.iter().any(|p| path.starts_with(p)) || CRON_EXACT.contains(&path) {
        return Some(PersistenceCategory::Cron);
    }
    if SYSTEMD_PREFIXES.iter().any(|p| path.starts_with(p)) || path.contains(SYSTEMD_USER_INFIX) {
        return Some(PersistenceCategory::Systemd);
    }
    if SHELL_RC_EXACT.contains(&path) {
        return Some(PersistenceCategory::ShellRc);
    }
    if path.starts_with(SHELL_RC_PROFILE_D_PREFIX) && path.ends_with(".sh") {
        return Some(PersistenceCategory::ShellRc);
    }
    let basename = path.rsplit('/').next().unwrap_or(path);
    if SHELL_RC_BASENAMES.contains(&basename) {
        return Some(PersistenceCategory::ShellRc);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_cron_d_write() {
        let d = PersistenceWriteDetector::new();
        let alert = d.observe(100, 0, "/etc/cron.d/backdoor").expect("cron.d write should alert");
        assert_eq!(alert.category, PersistenceCategory::Cron);
    }

    #[test]
    fn flags_cron_spool_write() {
        let d = PersistenceWriteDetector::new();
        let alert = d.observe(100, 1000, "/var/spool/cron/crontabs/rob").unwrap();
        assert_eq!(alert.category, PersistenceCategory::Cron);
    }

    #[test]
    fn flags_systemd_unit_write() {
        let d = PersistenceWriteDetector::new();
        let alert = d.observe(100, 0, "/etc/systemd/system/backdoor.service").unwrap();
        assert_eq!(alert.category, PersistenceCategory::Systemd);
    }

    #[test]
    fn flags_systemd_user_unit_write() {
        let d = PersistenceWriteDetector::new();
        let alert = d
            .observe(100, 1000, "/home/rob/.config/systemd/user/backdoor.service")
            .unwrap();
        assert_eq!(alert.category, PersistenceCategory::Systemd);
    }

    #[test]
    fn flags_bashrc_write_regardless_of_home_dir() {
        let d = PersistenceWriteDetector::new();
        let alert = d.observe(100, 1000, "/home/alice/.bashrc").unwrap();
        assert_eq!(alert.category, PersistenceCategory::ShellRc);
    }

    #[test]
    fn flags_etc_profile_d_script() {
        let d = PersistenceWriteDetector::new();
        let alert = d.observe(100, 0, "/etc/profile.d/backdoor.sh").unwrap();
        assert_eq!(alert.category, PersistenceCategory::ShellRc);
    }

    #[test]
    fn ignores_unrelated_path() {
        let d = PersistenceWriteDetector::new();
        assert!(d.observe(100, 1000, "/tmp/payload").is_none());
    }

    #[test]
    fn does_not_loosely_substring_match_rc_names() {
        let d = PersistenceWriteDetector::new();
        // basename must match exactly, not just contain "bashrc"
        assert!(d.observe(100, 1000, "/tmp/notbashrc.txt").is_none());
    }
}

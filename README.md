# Host Telemetry & Drift Auditor

A lightweight, zero-dependency Python security auditing tool for Linux hosts. Inspects kernel-level privilege surfaces, active network socket listeners, and sensitive file integrity, then detects configuration drift against known-good baselines.

## Features
- **Privilege Surface Collector:** Audits target directories for SUID (`04000`), SGID (`02000`), and non-sticky world-writable files.
- **Network Socket Telemetry:** Parses `/proc/net/tcp` directly to map active `TCP_LISTEN` (`0x0A`) sockets without relying on external binaries (`netstat`/`ss`).
- **Sensitive File Integrity:** Tracks POSIX permission bits, ownership UID/GID, and SHA-256 digests for critical authentication files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`).
- **Drift Engine:** Computes state deltas between a baseline snapshot and live telemetry, returning exit code `1` when unauthorized changes occur.

## Installation
```bash
git clone [https://github.com/Akira-8/host-drift-auditor.git](https://github.com/Akira-8/host-drift-auditor.git)
cd host-drift-auditor
pip install .
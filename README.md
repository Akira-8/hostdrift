cat > README.md << 'EOF'
# hostdrift

[![CI](https://github.com/Akira-8/HostDrift/actions/workflows/ci.yml/badge.svg)](https://github.com/Akira-8/HostDrift/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)

**Know when your Linux host changes.**
Snapshot a known-good state, then detect drift in privilege surfaces, listening ports, and critical auth files. No agents, no `netstat`/`ss`, no dependencies.

> Linux only (reads `/proc`). Run with `sudo` to read `/etc/shadow`.

## Why hostdrift
Tools like AIDE, Wazuh, and osquery are powerful but need installation, configuration, or a server. hostdrift is one small Python package you can drop on a box, run in seconds, and wire into cron or CI. Exit code `1` means drift was found.

## Features
- **Privilege surface:** SUID (`04000`), SGID (`02000`), and non-sticky world-writable files
- **Listening sockets:** parses `/proc/net/tcp` for `TCP_LISTEN` (`0x0A`) without external binaries
- **Sensitive file integrity:** permissions, UID/GID, and SHA-256 for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`
- **Drift engine:** diffs a baseline against live state and exits `1` on unauthorized change
- **JSON output** for every command, easy to pipe into other tools

## Install
```bash
git clone https://github.com/Akira-8/HostDrift.git
cd HostDrift
pip install .
```
Once published to PyPI: `pipx install hostdrift`

## Usage
```bash
hostdrift scan                          # one-off audit, prints JSON
hostdrift baseline -o baseline.json     # save a known-good snapshot
hostdrift audit -b baseline.json        # compare live state to the baseline
```
Add `--dirs /opt /srv` to any command to scan extra directories (default: `/bin /usr/bin /usr/local/bin /tmp`).

Exit codes: `0` clean, `1` drift detected, `2` baseline file not found.

### Example: a new SUID binary appears
```
$ hostdrift audit -b baseline.json
{
  "drift_detected": true,
  "alerts": {
    "new_suid_binaries": ["/tmp/helper"],
    "removed_suid_binaries": [],
    "new_listening_ports": [],
    "closed_listening_ports": [],
    "modified_sensitive_files": []
  }
}
$ echo $?
1
```

## Run it on a schedule
```bash
0 * * * * hostdrift audit -b /var/lib/hostdrift/baseline.json > /dev/null || echo "Drift on $(hostname)" | mail -s "hostdrift alert" you@example.com
```

## Limitations
- IPv4 TCP only for now (IPv6 and UDP are on the roadmap)
- Only new SUID binaries, new listeners, and modified sensitive files trigger exit code `1`; removals are reported but do not
- A baseline stored on the audited host can be altered by an attacker with root. Store it off-host or checksum it.
- Detects change, not intent. Review drift, don't assume it's malicious.

## Roadmap
- [ ] IPv6 and UDP listeners
- [ ] Config file with allowlists
- [ ] cron, `authorized_keys`, and systemd persistence checks
- [ ] SARIF output
- [ ] systemd timer example

## Contributing
Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License
MIT

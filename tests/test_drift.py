from hostdrift.collectors.network import NetworkSocketCollector
from hostdrift.diff import DriftEngine


def test_no_drift_when_identical():
    state = {
        "suid_binaries": [{"path": "/usr/bin/sudo"}],
        "active_listeners": [{"protocol": "tcp", "bind_address": "0.0.0.0:22"}],
        "sensitive_files": [{"path": "/etc/passwd", "permissions": "0644", "sha256": "a"}],
    }
    report = DriftEngine().compute_drift(state, state)
    assert report["drift_detected"] is False


def test_detects_new_suid_binary():
    base = {"suid_binaries": [{"path": "/usr/bin/sudo"}]}
    now = {"suid_binaries": [{"path": "/usr/bin/sudo"}, {"path": "/tmp/evil"}]}
    report = DriftEngine().compute_drift(base, now)
    assert report["drift_detected"] is True
    assert report["alerts"]["new_suid_binaries"] == ["/tmp/evil"]


def test_detects_new_listener():
    base = {"active_listeners": []}
    now = {"active_listeners": [{"protocol": "tcp", "bind_address": "0.0.0.0:4444"}]}
    report = DriftEngine().compute_drift(base, now)
    assert report["alerts"]["new_listening_ports"] == ["tcp:0.0.0.0:4444"]


def test_detects_modified_sensitive_file():
    base = {"sensitive_files": [{"path": "/etc/sudoers", "permissions": "0440", "sha256": "a"}]}
    now = {"sensitive_files": [{"path": "/etc/sudoers", "permissions": "0440", "sha256": "b"}]}
    report = DriftEngine().compute_drift(base, now)
    assert report["drift_detected"] is True
    assert report["alerts"]["modified_sensitive_files"][0]["content_modified"] is True


def test_decode_address_port():
    # 0100007F:0016 -> 127.0.0.1:22 (little-endian hex, as in /proc/net/tcp)
    assert NetworkSocketCollector()._decode_address_port("0100007F:0016") == "127.0.0.1:22"

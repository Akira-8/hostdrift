import json
import os
import sys

# Add src to the Python search path
sys.path.insert(0, os.path.abspath("src"))

from host_auditor.collectors.suid import PrivilegeSurfaceCollector
from host_auditor.collectors.network import NetworkSocketCollector
from host_auditor.collectors.integrity import SensitiveFileCollector

print("[*] Running Collectors...")

suid_collector = PrivilegeSurfaceCollector(target_directories=["/bin", "/usr/bin", "/tmp"])
net_collector = NetworkSocketCollector()
int_collector = SensitiveFileCollector()

findings = {}
findings.update(suid_collector.audit())
findings.update(net_collector.audit())
findings.update(int_collector.audit())

print(json.dumps(findings, indent=2))
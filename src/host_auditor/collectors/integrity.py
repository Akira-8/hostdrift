"""Audits file permissions on sensitive operating system files."""

import os
import stat
from typing import Dict, List


class SensitiveFileCollector:
    SENSITIVE_TARGETS = [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
    ]

    def audit(self) -> Dict[str, List[Dict[str, str]]]:
        results = []

        for target in self.SENSITIVE_TARGETS:
            if not os.path.exists(target):
                continue

            try:
                st = os.stat(target)
                mode_octal = oct(stat.S_IMODE(st.st_mode))
                results.append({
                    "path": target,
                    "permissions": mode_octal,
                    "owner_uid": str(st.st_uid),
                    "owner_gid": str(st.st_gid),
                })
            except (PermissionError, FileNotFoundError):
                continue

        return {"sensitive_files": results}
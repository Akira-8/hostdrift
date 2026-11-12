from typing import Any, Dict, List, Set


class DriftEngine:
    @staticmethod
    def _extract_paths(items: List[Dict[str, Any]]) -> Set[str]:
        return {item["path"] for item in items if "path" in item}

    @staticmethod
    def _extract_listeners(items: List[Dict[str, Any]]) -> Set[str]:
        return {f"{item['protocol']}:{item['bind_address']}" for item in items if "bind_address" in item}

    def compute_drift(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        # 1. SUID & SGID Binary Drift
        baseline_suid = self._extract_paths(baseline.get("suid_binaries", []))
        current_suid = self._extract_paths(current.get("suid_binaries", []))

        new_suid = sorted(list(current_suid - baseline_suid))
        removed_suid = sorted(list(baseline_suid - current_suid))

        # 2. Network Socket Listener Drift
        baseline_listeners = self._extract_listeners(baseline.get("active_listeners", []))
        current_listeners = self._extract_listeners(current.get("active_listeners", []))

        new_listeners = sorted(list(current_listeners - baseline_listeners))
        closed_listeners = sorted(list(baseline_listeners - current_listeners))

        # 3. Sensitive File Integrity & Permission Drift
        file_modifications = []
        baseline_files = {f["path"]: f for f in baseline.get("sensitive_files", [])}

        for item in current.get("sensitive_files", []):
            path = item["path"]
            if path in baseline_files:
                base_item = baseline_files[path]
                perm_changed = base_item.get("permissions") != item.get("permissions")
                hash_changed = (
                    "sha256" in base_item
                    and "sha256" in item
                    and base_item["sha256"] != item["sha256"]
                )
                if perm_changed or hash_changed:
                    file_modifications.append({
                        "path": path,
                        "baseline_permissions": base_item.get("permissions"),
                        "current_permissions": item.get("permissions"),
                        "content_modified": hash_changed,
                    })

        drift_detected = bool(new_suid or new_listeners or file_modifications)

        return {
            "drift_detected": drift_detected,
            "alerts": {
                "new_suid_binaries": new_suid,
                "removed_suid_binaries": removed_suid,
                "new_listening_ports": new_listeners,
                "closed_listening_ports": closed_listeners,
                "modified_sensitive_files": file_modifications,
            },
        }
"""SUID/SGID and World-Writable file collector."""

import os
import stat
from typing import Dict, List, Set


class PrivilegeSurfaceCollector:
    def __init__(self, target_directories: List[str] = None):
        self.target_directories = target_directories or [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/etc",
            "/opt",
            "/tmp",
        ]

    def audit(self) -> Dict[str, List[Dict[str, str]]]:
        suid_binaries = []
        sgid_binaries = []
        world_writable = []

        seen_inodes: Set[tuple] = set()

        for base_path in self.target_directories:
            if not os.path.exists(base_path):
                continue

            for root, dirs, files in os.walk(base_path, followlinks=False):
                for file_name in files:
                    file_path = os.path.join(root, file_name)

                    try:
                        file_stat = os.lstat(file_path)
                    except (PermissionError, FileNotFoundError):
                        continue

                    inode_key = (file_stat.st_dev, file_stat.st_ino)
                    if inode_key in seen_inodes:
                        continue
                    seen_inodes.add(inode_key)

                    mode = file_stat.st_mode

                    if mode & stat.S_ISUID:
                        suid_binaries.append({
                            "path": file_path,
                            "owner_uid": str(file_stat.st_uid),
                            "permissions": oct(stat.S_IMODE(mode)),
                        })

                    if mode & stat.S_ISGID:
                        sgid_binaries.append({
                            "path": file_path,
                            "owner_gid": str(file_stat.st_gid),
                        })

                    if (not stat.S_ISLNK(mode)) and (mode & stat.S_IWOTH):
                        world_writable.append({
                            "path": file_path,
                            "permissions": oct(stat.S_IMODE(mode)),
                            "owner_uid": str(file_stat.st_uid),
                        })

        return {
            "suid_binaries": sorted(suid_binaries, key=lambda x: x["path"]),
            "sgid_binaries": sorted(sgid_binaries, key=lambda x: x["path"]),
            "world_writable_files": sorted(world_writable, key=lambda x: x["path"]),
        }
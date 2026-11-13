"""Direct /proc/net network socket collector."""

import socket
import struct
from typing import Dict, List


class NetworkSocketCollector:
    TCP_LISTEN_STATE = "0A"

    def _decode_address_port(self, hex_addr: str) -> str:
        ip_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        packed_ip = struct.pack("<I", int(ip_hex, 16))
        ip = socket.inet_ntoa(packed_ip)
        return f"{ip}:{port}"

    def audit(self) -> Dict[str, List[Dict[str, str]]]:
        listeners = []
        proc_tcp = "/proc/net/tcp"

        try:
            with open(proc_tcp, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (FileNotFoundError, PermissionError):
            return {"active_listeners": []}

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            local_address_hex = parts[1]
            state_hex = parts[3]
            inode = parts[9] if len(parts) > 9 else "0"

            if state_hex == self.TCP_LISTEN_STATE:
                endpoint = self._decode_address_port(local_address_hex)
                listeners.append({
                    "protocol": "tcp",
                    "bind_address": endpoint,
                    "inode": inode,
                })

        return {
            "active_listeners": sorted(listeners, key=lambda x: x["bind_address"])
        }
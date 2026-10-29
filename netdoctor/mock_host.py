"""Host giả lập (mock) để demo/test toàn bộ luồng mà không cần máy thật.

Mô phỏng một VM đang gặp đồng thời các sự cố:
- Disk đầy 94%
- eth1 DOWN (NO-CARRIER)
- nginx.service failed
- journalctl/auth.log đầy cảnh báo OOM + brute-force SSH

Các lệnh sửa chữa tương ứng sẽ "chữa" được trạng thái, để node verify_fix
trả về passed=True — chứng minh vòng lặp chẩn đoán → sửa → kiểm tra chạy đúng.
"""

from __future__ import annotations

from .config import HostEntry
from .ssh_client import RunResult

_DFM_OUTPUT = """\
Filesystem     Type  Size  Used Avail Use% Mounted on
/dev/vda1      ext4   40G   38G  1.2G  94% /
tmpfs          tmpfs  7.9G     0  7.9G   0% /dev/shm
"""

_DFM_FIXED = """\
Filesystem     Type  Size  Used Avail Use% Mounted on
/dev/vda1      ext4   40G   15G   23G  41% /
tmpfs          tmpfs  7.9G     0  7.9G   0% /dev/shm
"""

_FREE_OUTPUT = """\
               total        used        free      shared  buff/cache   available
Mem:            15Gi       9.8Gi       1.2Gi       512Mi       4.5Gi       5.0Gi
Swap:          2.0Gi       1.1Gi       924Mi
"""

_FREE_FIXED = """\
               total        used        free      shared  buff/cache   available
Mem:            15Gi       7.1Gi       3.9Gi       256Mi       4.5Gi       7.4Gi
Swap:          2.0Gi        64Mi       1.9Gi
"""

_IP_LINK_OUTPUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
3: eth1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN
"""

_IP_LINK_FIXED = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
"""

_FAILED_UNITS_BROKEN = "nginx.service loaded failed failed A high performance web server\n"

_JOURNAL_ERR_BROKEN = """\
Oct 11 22:30:11 vm-web-01 kernel: Out of memory: Killed process 1871 (php-fpm) total-vm:1048576kB, anon-rss:524288kB
Oct 11 22:31:44 vm-web-01 kernel: oom-killer: GESP score 1042
Oct 11 22:33:02 vm-web-01 systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE
Oct 11 22:33:02 vm-web-01 systemd[1]: Failed to start A high performance web server.
Oct 11 22:35:19 vm-web-01 kernel: eth1: Link is Down
Oct 11 22:36:07 vm-web-01 sshd[2911]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2
Oct 11 22:38:55 vm-web-01 kernel: EXT4-fs (vda1): warning: mounting fs with errors, running e2fsck is recommended
"""

_JOURNAL_ERR_FIXED = """\
Oct 11 22:44:01 vm-web-01 systemd[1]: Started A high performance web server.
Oct 11 22:44:05 vm-web-01 kernel: eth1: Link is Up 1000 Mbps full duplex
"""

_AUTH_LOG_BROKEN = """\
Oct 11 22:36:07 vm-web-01 sshd[2911]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2
Oct 11 22:36:08 vm-web-01 sshd[2913]: Failed password for invalid user admin from 203.0.113.45 port 51240 ssh2
Oct 11 22:36:09 vm-web-01 sshd[2915]: Failed password for root from 203.0.113.45 port 51244 ssh2
Oct 11 22:37:10 vm-web-01 sshd[2940]: Accepted password for admin from 10.0.0.5 port 44122 ssh2
"""

class MockHostClient:
    """Triển khai giao diện HostClient bằng dữ liệu giả lập."""

    def __init__(self, entry: HostEntry | None = None):
        entry = entry or HostEntry(name="mock-demo", host="127.0.0.1", mock=True)
        self.entry = entry
        self.name = entry.name
        self.target = f"mock://{entry.name}"
        # Trạng thái "sức khoẻ" của host giả lập:
        self.disk_fixed = False
        self.link_fixed = False
        self.nginx_fixed = False
        self.mem_fixed = False

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        cmd = command.strip()

        # --- các lệnh "sửa chữa" thay đổi trạng thái host ---
        if "journalctl --vacuum" in cmd or "apt-get clean" in cmd:
            self.disk_fixed = True
            return RunResult(ok=True, output="Vacuuming done, freed 23G\n", exit_code=0)
        if "systemctl restart nginx" in cmd:
            self.nginx_fixed = True
            return RunResult(ok=True, output="", exit_code=0)
        if "ip link set eth1 up" in cmd:
            self.link_fixed = True
            return RunResult(ok=True, output="", exit_code=0)
        if "swapon" in cmd or "fallocate -l" in cmd:
            self.mem_fixed = True
            return RunResult(ok=True, output="", exit_code=0)

        # --- lệnh read-only trả về dữ liệu theo trạng thái hiện tại ---
        if cmd.startswith("df -hT") or cmd.startswith("df -h "):
            return RunResult(
                ok=True, output=_DFM_FIXED if self.disk_fixed else _DFM_OUTPUT
            )
        if cmd.startswith("df -i"):
            return RunResult(ok=True, output="Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/vda1 2621440 180000 2441440 7% /\n")
        if cmd.startswith("free -h"):
            return RunResult(ok=True, output=_FREE_FIXED if self.mem_fixed else _FREE_OUTPUT)
        if cmd.startswith("swapon --show"):
            return RunResult(ok=True, output="" if self.mem_fixed else "/swapfile file 2G file\n")
        if cmd.startswith("ip -br link"):
            return RunResult(ok=True, output=_IP_LINK_FIXED if self.link_fixed else _IP_LINK_OUTPUT)
        if cmd.startswith("ip route"):
            return RunResult(ok=True, output="default via 192.168.122.1 dev eth0 proto static\n10.0.1.0/24 dev eth1 scope link\n")
        if "ping" in cmd:
            return RunResult(ok=True, output="2 packets transmitted, 2 received, 0% packet loss\nrtt min/avg/max/mdev = 0.312/0.418/0.524/0.106 ms\n")
        if cmd.startswith("systemctl list-units --failed"):
            return RunResult(ok=True, output="" if self.nginx_fixed else _FAILED_UNITS_BROKEN)
        if cmd.startswith("systemctl is-system-running"):
            state = "running" if (self.nginx_fixed and self.link_fixed) else "degraded"
            return RunResult(ok=True, output=state + "\n")
        return self._dispatch(cmd)

    def _dispatch(self, cmd: str) -> RunResult:
        """Phân loại các lệnh read-only còn lại."""
        if cmd.startswith("systemctl is-active"):
            unit = cmd.split()[-1]
            if unit.startswith("nginx") and not self.nginx_fixed:
                return RunResult(ok=False, output="inactive\n", exit_code=3)
            return RunResult(ok=True, output="active\n", exit_code=0)
        if cmd.startswith("journalctl") and "-p err" in cmd:
            healthy = self.disk_fixed and self.nginx_fixed
            return RunResult(ok=True, output=_JOURNAL_ERR_FIXED if healthy else _JOURNAL_ERR_BROKEN)
        if cmd.startswith("journalctl"):
            return RunResult(ok=True, output=_JOURNAL_ERR_BROKEN)
        if "auth.log" in cmd and "grep" in cmd:
            return RunResult(ok=True, output="0\n" if self.disk_fixed else "42\n")
        if "auth.log" in cmd:
            return RunResult(ok=True, output=_AUTH_LOG_BROKEN)
        if cmd.startswith("ip -br addr"):
            eth1 = "10.0.1.10/24" if self.link_fixed else ""
            state = "UP" if self.link_fixed else "DOWN"
            return RunResult(
                ok=True,
                output=(
                    "lo               UNKNOWN        127.0.0.1/8 ::1/128\n"
                    "eth0             UP             192.168.122.10/24\n"
                    f"eth1             {state}           {eth1}\n"
                ),
            )
        if cmd.startswith("uptime"):
            return RunResult(ok=True, output=" 22:41:03 up 12 days,  4:03,  2 users,  load average: 4.12, 3.55, 2.98\n")
        if cmd.startswith("uname"):
            return RunResult(ok=True, output="Linux vm-web-01 6.8.0-generic x86_64 GNU/Linux\n")
        if cmd.startswith("cat /proc/loadavg"):
            return RunResult(ok=True, output="4.12 3.55 2.98 3/412 1871\n")
        if cmd == "nproc":
            return RunResult(ok=True, output="4\n")
        if cmd.startswith("cat /etc/resolv.conf"):
            return RunResult(ok=True, output="nameserver 192.168.122.1\n")
        if cmd.startswith("ss "):
            return RunResult(ok=True, output="Netid State  Recv-Q Send-Q Local Address:Port\ntcp   LISTEN 0      511    0.0.0.0:22         0.0.0.0:*\n")
        if cmd.startswith("ps aux"):
            return RunResult(ok=True, output="USER         PID %CPU %MEM    VSZ   RSS COMMAND\nwww-data   1871  6.2  8.1 1048576 524288 php-fpm\n")
        if cmd.startswith("dmesg"):
            return RunResult(ok=True, output="dmesg: no recent messages\n" if self.disk_fixed else _JOURNAL_ERR_BROKEN)
        if cmd.startswith("lastb"):
            return RunResult(ok=True, output="admin  ssh:notty 203.0.113.45 Mon Oct 11 22:36 - 22:36  (00:00)\n")
        if cmd.startswith("last "):
            return RunResult(ok=True, output="admin pts/0 10.0.0.5 Mon Oct 11 22:37   still logged in\n")
        if cmd.startswith("fail2ban-client"):
            return RunResult(ok=False, error="Unit fail2ban.service is not loaded.", exit_code=1)
        return RunResult(ok=True, output="(mock output)\n", exit_code=0)

    def read_file(self, path: str, max_lines: int = 200) -> RunResult:
        if "auth.log" in path:
            return RunResult(ok=True, output=_AUTH_LOG_BROKEN)
        if "syslog" in path or "messages" in path:
            return RunResult(ok=True, output=_JOURNAL_ERR_BROKEN)
        return RunResult(ok=True, output="(mock file content)\n")

    def close(self) -> None:
        return None


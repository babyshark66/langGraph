"""An toàn lệnh: denylist lệnh phá huỷ + phân loại mức rủi ro.

Nguyên tắc:
- Lệnh CRITICAL (phá huỷ dữ liệu / làm chết hệ thống) bị CHẶN vĩnh viễn.
- Lệnh HIGH chỉ được thực thi khi có phê duyệt rõ ràng.
- Mọi lệnh trước khi chạy đều phải đi qua ``check_command``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .state import RiskLevel

# Các mẫu tuyệt đối không được phép chạy (dạng CRITICAL + blocked).
_DENY_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+){1,2}(/|~|\$HOME|\.\.)\S*(\s|$)", "Xoá recursive hệ thống"),
    (r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+\*", "rm -rf wildcard"),
    (r"\bmkfs(\.[a-z0-9]+)?\b", "Format ổ cứng"),
    (r"\bdd\b.*\bof=/dev/", "Ghi thẳng vào ổ cứng bằng dd"),
    (r"\b(wipefs|blkdiscard)\b", "Xoá chữ ký/zero ổ cứng"),
    (r"\bshred\b.*(/dev/|/)", "Shred thiết bị/đường dẫn hệ thống"),
    (r">\s*/dev/(sd|nvme|vd|hd|xvd)", "Ghi đè thiết bị block"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb"),
    (r"\b(iptables|ip6tables)\s+(-[a-zA-Z]+\s+)*-F\b", "Flush toàn bộ firewall"),
    (r"\bnft\s+(flush|delete\s+table)", "Xoá ruleset nftables"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "Tắt/máy lại hệ thống"),
    (r"\binit\s+[06]\b", "Chuyển runlevel tắt/máy lại"),
    (r"\bchmod\s+(-[a-zA-Z]+\s+)*[0-7]{3,4}\s+/\s*$", "chmod toàn bộ cây /"),
    (r"\bchmod\s+-R\s+777\s+/", "chmod -R 777 trên /"),
    (r"\buserdel\s+(-[a-zA-Z]+\s+)*-[rm]\b", "Xoá user vĩnh viễn"),
    (r"\bmkswap\b.*/dev/", "mkswap trên thiết bị"),
    (r"\bcryptsetup\s+(erase|luksErase|close)\b", "Phá vùng mã hoá"),
    (r"\b(sfdisk|fdisk|parted|partprobe)\b.*\b(del|rm|rm-part)\b", "Xoá phân vùng"),
    (r">\s*/(etc/(passwd|shadow|sudoers)|boot/)", "Ghi đè file hệ thống quan trọng"),
    (r"\bmv\s+/dev/null\s+/", "mv /dev/null đè cây thư mục"),
]

# Từ khoá HIGH: sửa chữa mạnh, cần phê duyệt.
_HIGH_PATTERNS: list[str] = [
    r"\bsystemctl\s+(restart|stop|disable|mask|isolate|kill)\b",
    r"\bservice\s+\S+\s+(restart|stop)\b",
    r"\bsysctl\s+-w\s+kernel\.",
    r"\bmodprobe\s+-r\b",
    r"\b(umount|mount)\s+/",
    r"\b(swapon|swapoff)\b",
    r"\b(apt|apt-get|yum|dnf|pacman)\s+(remove|purge|autoremove|dist-upgrade|full-upgrade)\b",
    r"\bkill(-9)?\s+(-9\s+)?(1|-1)\b",
    r"\bchown\s+-R\b.*/",
    r"\b(fallocate|truncate)\s.*\b(swapfile|/dev/)\b",
    r"\becho\s+.*>\s*/proc/",
    r"\bifdown\b|\bifconfig\s+\S+\s+down\b",
    r"\brename\b|\bhostnamectl\s+set-hostname\b",
]

# Từ khoá MEDIUM: sửa chữa thông thường, chấp nhận được khi đã phê duyệt.
_MEDIUM_PATTERNS: list[str] = [
    r"\bsystemctl\s+(start|reload|reenable|daemon-reload)\b",
    r"\bsystemctl\s+--now\s+enable\b",
    r"\bjournalctl\s+--vacuum",
    r"\b(apt|apt-get)\s+(update|upgrade|install|autoclean|clean)\b",
    r"\btruncate\s+-s\s+0\s+/var/log/",
    r"\blogrotate\s+",
    r"\bip\s+link\s+set\s+\S+\s+(up|down)\b",
    r"\bip\s+(addr|route)\s+(add|del)\b",
    r"\bnmcli\b",
    r"\budevadm\s+trigger\b",
    r"\bsysctl\s+-w\s+net\.",
    r"\b(ufw|firewall-cmd|nft)\b",
    r"\bfail2ban-client\b",
    r"\btimedatectl\b|\bchronyc\b|\bntpdate\b",
    r"\bupdate-rc\.d\b|\bchkconfig\b",
    r"\brpc\.nfsd\b|\bexportfs\b",
]

# Mẫu read-only rõ ràng → LOW (dù có chứa từ khoá ở trên trong tham số).
_READONLY_PATTERNS: list[str] = [
    r"^\s*(sudo\s+)?(cat|ls|head|tail|less|more|wc|grep|egrep|rg|awk|sed\s+-n|find\s+\S+\s+-name|stat|du|df|free|uptime|date|hostname|id|whoami|uname|ps|top\s+-bn1|ss|netstat|ip\s+(-br\s+)?(a|addr|r|route|link)|ping|traceroute|mtr|dig|nslookup|host|curl\s+(-[a-zA-Z]+\s+)*(--head|-I|-s\s+\S*\s*-o\s*\S*)?|wget\s+--spider|systemctl\s+(status|is-active|is-enabled|is-system-running|list-units|list-timers|show|cat)|journalctl(?!\s+--vacuum)|dmesg|lsblk|lsof|mount\b(?!.*\s-/)|swapon\s+--show|sensors|vmstat|iostat|mpstat|sar|last|lastb|w\b|fuser|getent|openssl\s+version|sysctl(?!\s+-w)|nft\s+list|iptables\s+(-[a-zA-Z]+\s+)*-S\b|ufw\s+status|sestatus|auditctl\s+-l|blkid|file|readlink|mdadm\s+--detail|zpool\s+status|smartctl\s+-a)\b",
]


@dataclass
class SafetyVerdict:
    risk: RiskLevel
    blocked: bool = False
    reason: str = ""


def _strip_sudo(command: str) -> str:
    return re.sub(r"^\s*sudo\s+", "", command.strip())


def classify_command(command: str) -> SafetyVerdict:
    """Phân loại rủi ro và xác định lệnh có bị chặn hay không."""
    cmd = command.strip()
    core = _strip_sudo(cmd)

    for pattern, reason in _DENY_PATTERNS:
        if re.search(pattern, core, flags=re.IGNORECASE):
            return SafetyVerdict(RiskLevel.CRITICAL, blocked=True, reason=reason)

    # HIGH/MEDIUM trước read-only: `ip link set ...` không được coi là read-only
    for pattern in _HIGH_PATTERNS:
        if re.search(pattern, core, flags=re.IGNORECASE):
            return SafetyVerdict(RiskLevel.HIGH, reason="Lệnh sửa chữa mạnh")

    for pattern in _MEDIUM_PATTERNS:
        if re.search(pattern, core, flags=re.IGNORECASE):
            return SafetyVerdict(RiskLevel.MEDIUM, reason="Lệnh sửa chữa thông thường")

    for pattern in _READONLY_PATTERNS:
        if re.match(pattern, core, flags=re.IGNORECASE):
            return SafetyVerdict(RiskLevel.LOW)

    # Không nhận diện được → coi là MEDIUM (vẫn cần phê duyệt).
    return SafetyVerdict(RiskLevel.MEDIUM, reason="Không phân loại được, mặc định MEDIUM")


def is_safe_to_run(command: str, allow_high: bool = True) -> SafetyVerdict:
    """Trả về verdict; ``blocked=True`` nghĩa là tuyệt đối không chạy."""
    verdict = classify_command(command)
    if verdict.blocked:
        return verdict
    if verdict.risk is RiskLevel.HIGH and not allow_high:
        return SafetyVerdict(
            RiskLevel.HIGH, blocked=True, reason="Lệnh HIGH cần allow_high=True"
        )
    return verdict

"""Phân tích heuristic (không cần LLM): parse số liệu hệ thống + trích tín hiệu log.

Các hàm ở đây chạy được cả khi không có API key — vừa là "bộ não dự phòng"
vừa là đường kiểm chứng chéo với kết luận của LLM.
"""

from __future__ import annotations

import re

from .state import Fact, LogSignal, Severity


def find_fact(facts: list[Fact], name: str) -> Fact | None:
    for fact in facts:
        if fact.name == name:
            return fact
    return None


def parse_disk_usage(facts: list[Fact]) -> list[tuple[str, int]]:
    """Trả về [(mount_point, use_percent)] từ output ``df -hT``."""
    fact = find_fact(facts, "disk")
    if fact is None or not fact.ok:
        return []
    results: list[tuple[str, int]] = []
    for line in fact.output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 7 and parts[-2].endswith("%"):
            try:
                results.append((parts[-1], int(parts[-2].rstrip("%"))))
            except ValueError:
                continue
    return results


def parse_inode_usage(facts: list[Fact]) -> list[tuple[str, int]]:
    fact = find_fact(facts, "inodes")
    if fact is None or not fact.ok:
        return []
    results: list[tuple[str, int]] = []
    for line in fact.output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[-2].endswith("%"):
            try:
                results.append((parts[-1], int(parts[-2].rstrip("%"))))
            except ValueError:
                continue
    return results


def _to_gb(token: str) -> float:
    m = re.match(r"([\d.]+)([KMGTP]?)", token)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2)
    return {"K": val / 1024, "M": val / 1024, "G": val, "T": val * 1024}.get(unit, val)


def parse_mem(facts: list[Fact]) -> tuple[float, float, float]:
    """Trả về (used_gb, available_gb, swap_used_gb) từ ``free -h``."""
    fact = find_fact(facts, "memory")
    if fact is None or not fact.ok:
        return (0.0, 0.0, 0.0)
    used = avail = swap_used = 0.0
    for line in fact.output.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0].startswith("Mem:") and len(parts) >= 4:
            used = _to_gb(parts[2])
            avail = _to_gb(parts[6]) if len(parts) >= 7 else _to_gb(parts[3])
        elif parts[0].startswith("Swap:") and len(parts) >= 3:
            swap_used = _to_gb(parts[2])
    return (used, avail, swap_used)


def parse_failed_units(facts: list[Fact]) -> list[str]:
    fact = find_fact(facts, "failed_units")
    if fact is None or not fact.ok:
        return []
    units: list[str] = []
    for line in fact.output.splitlines():
        parts = line.split()
        if parts and (parts[0].endswith((".service", ".socket", ".target"))):
            units.append(parts[0])
    return sorted(set(units))


def parse_down_links(facts: list[Fact]) -> list[str]:
    fact = find_fact(facts, "links")
    if fact is None or not fact.ok:
        return []
    down: list[str] = []
    for line in fact.output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].rstrip(":").isdigit():
            name = parts[1].rstrip(":")
            if name == "lo":
                continue
            if "DOWN" in line or "NO-CARRIER" in line:
                down.append(name)
    return down


def ping_ok(facts: list[Fact]) -> bool | None:
    fact = find_fact(facts, "ping_gateway")
    if fact is None:
        return None
    if not fact.ok:
        return False
    return "0% packet loss" in fact.output

# --------------------------------------------------------------------- #
#                            TÍN HIỆU TỪ LOG                            #
# --------------------------------------------------------------------- #

_LOG_RULES: list[tuple[str, re.Pattern[str], Severity, str]] = [
    ("oom", re.compile(r"out of memory|oom-?killer|memory cgroup out of memory", re.I),
     Severity.CRITICAL, "Kernel giết process do cạn kiệt bộ nhớ (OOM)"),
    ("io-error", re.compile(r"i/o error|medium error|critical target error", re.I),
     Severity.CRITICAL, "Lỗi I/O trên ổ đĩa/thiết bị lưu trữ"),
    ("ro-fs", re.compile(r"read-only file system|remounted as read-only", re.I),
     Severity.CRITICAL, "Filesystem bị chuyển sang read-only (bảo vệ sau lỗi)"),
    ("fs-errors", re.compile(r"ext4-fs.*error|xfs.*error|mounting fs with errors", re.I),
     Severity.ERROR, "Filesystem có lỗi cần kiểm tra (e2fsck/xfs_repair)"),
    ("link-down", re.compile(r"link is down|no-carrier|network is (un)?reachable", re.I),
     Severity.ERROR, "Mất liên kết mạng (link down)"),
    ("nic-reset", re.compile(r"reset adapter|tx timeout|hung task", re.I),
     Severity.WARNING, "NIC/adapter mạng bất ổn (reset/timeout)"),
    ("bruteforce", re.compile(r"failed password|authentication failure|invalid user", re.I),
     Severity.ERROR, "Có dấu hiệu dò mật khẩu SSH (brute-force)"),
    ("service-fail", re.compile(r"failed to start|main process exited|entered failed state", re.I),
     Severity.ERROR, "Service thất bại khi khởi động/chạy"),
    ("segfault", re.compile(r"segfault|general protection fault|kernel panic", re.I),
     Severity.CRITICAL, "Process/kernel gặp lỗi nghiêm trọng (segfault/panic)"),
    ("time-sync", re.compile(r"time has been changed|ntp.*offset|unsynchronised", re.I),
     Severity.WARNING, "Đồng hồ hệ thống bất thường (lệch giờ)"),
    ("cert-expiry", re.compile(r"(certificate|ssl).*(expired|expiring)", re.I),
     Severity.WARNING, "Chứng chỉ TLS sắp hết hạn/đã hết hạn"),
]

# kind chỉ cần 1 tín hiệu đại diện (không lặp hàng trăm dòng)
_SINGLETON_KINDS = {
    "oom", "io-error", "ro-fs", "fs-errors", "link-down",
    "nic-reset", "segfault", "time-sync", "cert-expiry", "service-fail",
}


def extract_log_signals(source: str, text: str, max_signals: int = 40) -> list[LogSignal]:
    """Quét text log theo rule -> danh sách tín hiệu (đã khử trùng lặp)."""
    signals: list[LogSignal] = []
    seen: set[str] = set()
    brute_count = 0
    for line in text.splitlines():
        for kind, pattern, severity, detail in _LOG_RULES:
            if not pattern.search(line):
                continue
            if kind == "bruteforce":
                brute_count += 1
            if kind in _SINGLETON_KINDS and kind in seen:
                break
            seen.add(kind)
            signals.append(
                LogSignal(
                    source=source, kind=kind, severity=severity,
                    detail=detail, evidence=line.strip()[:300],
                )
            )
            break
        if len(signals) >= max_signals and brute_count:
            break
    if brute_count:
        signals = [s for s in signals if s.kind != "bruteforce"]
        signals.append(
            LogSignal(
                source=source, kind="bruteforce", severity=Severity.ERROR,
                detail=f"Phát hiện {brute_count} dòng đăng nhập SSH thất bại trong mẫu log",
                evidence=next(
                    (ln.strip() for ln in text.splitlines()
                     if re.search(r"failed password|authentication failure", ln, re.I)),
                    "",
                )[:300],
            )
        )
    return signals


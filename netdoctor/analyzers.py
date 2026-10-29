"""Tổng hợp chẩn đoán + kế hoạch sửa chữa bằng rule (không cần LLM).

``heuristic_diagnose`` ghép số liệu hệ thống + tín hiệu log thành Diagnosis.
``heuristic_plan`` chuyển Diagnosis thành RepairPlan với các bước read-mostly,
mỗi bước đều có verify_command để đối chiếu sau khi chạy.
"""

from __future__ import annotations

from .heuristics import (
    parse_disk_usage,
    parse_failed_units,
    parse_inode_usage,
    parse_mem,
    parse_down_links,
    ping_ok,
)
from .state import Diagnosis, Finding, LogSignal, RepairPlan, RepairStep, RiskLevel, Severity

_SEVERITY_ORDER = ["info", "warning", "error", "critical"]


def heuristic_diagnose(facts, signals: list[LogSignal]) -> Diagnosis:
    """Sinh Diagnosis từ facts + tín hiệu log theo rule."""
    findings: list[Finding] = []

    # --- disk / inode ---
    for mount, pct in parse_disk_usage(facts):
        if pct >= 95:
            findings.append(Finding(
                id=f"disk-full:{mount}", title=f"Ổ đĩa {mount} đầy {pct}%",
                severity=Severity.CRITICAL,
                detail=f"Phân vùng {mount} sử dụng {pct}% — gần như không còn chỗ ghi.",
                suggested_fixes=["journalctl --vacuum-size=200M", "apt-get clean"],
            ))
        elif pct >= 90:
            findings.append(Finding(
                id=f"disk-high:{mount}", title=f"Ổ đĩa {mount} sắp đầy ({pct}%)",
                severity=Severity.WARNING,
                detail=f"Phân vùng {mount} sử dụng {pct}% — nên dọn dẹp chủ động.",
                suggested_fixes=["journalctl --vacuum-size=100M"],
            ))
    for mount, pct in parse_inode_usage(facts):
        if pct >= 90:
            findings.append(Finding(
                id=f"inode-full:{mount}", title=f"Inode {mount} sắp cạn ({pct}%)",
                severity=Severity.WARNING,
                detail=f"Inode trên {mount} dùng {pct}% — nhiều file nhỏ rác.",
                suggested_fixes=[],
            ))

    # --- bộ nhớ / swap ---
    _used, avail, swap_used = parse_mem(facts)
    if avail and avail < 0.5:
        findings.append(Finding(
            id="mem-critical", title="Bộ nhớ khả dụng dưới 500MB",
            severity=Severity.CRITICAL,
            detail=f"Chỉ còn {avail:.2f}GB khả dụng.",
            suggested_fixes=[],
        ))
    if swap_used >= 1.5:
        findings.append(Finding(
            id="swap-heavy", title="Swap đang được dùng nhiều",
            severity=Severity.WARNING,
            detail=f"Swap đã dùng {swap_used:.1f}GB — dấu hiệu áp lực bộ nhớ.",
            suggested_fixes=[],
        ))

    # --- systemd ---
    for unit in parse_failed_units(facts):
        findings.append(Finding(
            id=f"unit-failed:{unit}", title=f"Service {unit} đang failed",
            severity=Severity.ERROR,
            detail=f"systemctl báo {unit} ở trạng thái failed.",
            suggested_fixes=[f"systemctl restart {unit}"],
        ))

    # --- mạng ---
    for link in parse_down_links(facts):
        findings.append(Finding(
            id=f"link-down:{link}", title=f"Interface {link} đang DOWN",
            severity=Severity.ERROR,
            detail=f"Interface {link} không có liên kết (DOWN/NO-CARRIER).",
            suggested_fixes=[f"ip link set {link} up"],
        ))
    if ping_ok(facts) is False:
        findings.append(Finding(
            id="gw-unreachable", title="Không ping được default gateway",
            severity=Severity.ERROR,
            detail="Không thể tới gateway mặc định — mất đường ra ngoài.",
            suggested_fixes=[],
        ))

    # --- tín hiệu log ---
    for sig in signals:
        if sig.kind in ("oom", "io-error", "ro-fs", "segfault", "service-fail", "fs-errors"):
            findings.append(Finding(
                id=f"log:{sig.kind}:{sig.source}", title=sig.detail,
                severity=sig.severity, detail=f"Tín hiệu '{sig.kind}' trong {sig.source}.",
                evidence=sig.evidence, suggested_fixes=[],
            ))
        elif sig.kind == "bruteforce":
            findings.append(Finding(
                id=f"log:bruteforce:{sig.source}", title="Dấu hiệu brute-force SSH",
                severity=Severity.WARNING, detail=sig.detail,
                evidence=sig.evidence, suggested_fixes=["ufw limit 22/tcp"],
            ))

    if not findings:
        return Diagnosis(
            summary="Hệ thống hoạt động bình thường, không phát hiện vấn đề.",
            confidence=0.85, findings=[],
            recommendations=["Tiếp tục giám sát định kỳ."],
        )

    worst = max(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))
    return Diagnosis(
        summary=(f"Phát hiện {len(findings)} vấn đề; nghiêm trọng nhất: "
                 f"[{worst.severity.value}] {worst.title}."),
        root_cause=worst.detail, confidence=0.7, findings=findings,
        recommendations=["Xem lại log chi tiết và xác nhận nguyên nhân gốc trước khi mở rộng sửa chữa."],
    )


def heuristic_plan(diagnosis: Diagnosis) -> RepairPlan:
    """Chuyển chẩn đoán thành kế hoạch sửa chữa các bước read-mostly."""
    steps: list[RepairStep] = []
    seen: set[str] = set()
    for finding in diagnosis.findings:
        for i, cmd in enumerate(finding.suggested_fixes):
            if cmd in seen:
                continue
            seen.add(cmd)
            risk = (
                RiskLevel.MEDIUM
                if "systemctl restart" in cmd or cmd.startswith("ufw")
                else RiskLevel.LOW
            )
            verify = None
            if cmd.startswith("systemctl restart"):
                verify = f"systemctl is-active {cmd.rsplit(' ', 1)[-1]}"
            elif cmd.startswith("ip link set"):
                iface = cmd.split()[-2]
                verify = f"ip -br link show {iface}"
            steps.append(RepairStep(
                id=f"{finding.id}-{i}", description=f"Xử lý: {finding.title}",
                command=cmd, risk=risk, timeout=60,
                continue_on_error=True, verify_command=verify,
            ))
    return RepairPlan(
        title="Kế hoạch sửa chữa (heuristic)",
        rationale="Các bước an toàn, read-mostly, dựa trên rule; cần xác nhận trước khi chạy.",
        steps=steps,
    )

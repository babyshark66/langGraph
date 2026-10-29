"""Các node của LangGraph: thu thập → phân tích → chẩn đoán → sửa → kiểm tra."""

from __future__ import annotations

import logging

from . import analyzers, heuristics, safety
from .state import (
    AgentState,
    CommandResult,
    Diagnosis,
    Fact,
    Finding,
    LogSignal,
    RepairPlan,
    RepairStep,
    Severity,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# Bộ lệnh thu thập read-only (an toàn — không sửa gì trên host)
BASE_CHECKS: list[tuple[str, str]] = [
    ("uptime", "uptime"),
    ("disk", "df -hT -x tmpfs -x devtmpfs"),
    ("inodes", "df -i -x tmpfs -x devtmpfs"),
    ("memory", "free -h"),
    ("processes", "ps aux --sort=-%mem | head -15"),
    ("ports", "ss -tulnp"),
    ("links", "ip -br link"),
    ("addrs", "ip -br addr"),
    ("routes", "ip route"),
    ("resolv", "cat /etc/resolv.conf"),
    ("failed_units", "systemctl list-units --failed --no-legend"),
    ("sys_running", "systemctl is-system-running"),
    ("login", "who"),
]

LOG_CHECKS: list[tuple[str, str]] = [
    ("journal_err", "journalctl -p err -n 200 --no-pager -o short"),
    ("journal_warn", "journalctl -p warning -n 120 --no-pager -o short"),
    ("dmesg_err", "dmesg --level=err,crit,alert,emerg 2>/dev/null | tail -80"),
    ("auth_log", "tail -n 200 /var/log/auth.log"),
    ("syslog", "tail -n 200 /var/log/syslog"),
    ("last_logins", "last -n 25"),
]


def _run_check(client, name: str, command: str, timeout: int) -> Fact:
    verdict = safety.classify_command(command)
    if verdict.blocked:
        return Fact(name=name, command=command, ok=False, error=f"bị chặn: {verdict.reason}")
    try:
        result = client.run(command, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — không để lỗi SSH làm sập graph
        return Fact(name=name, command=command, ok=False, error=str(exc))
    return Fact(
        name=name, command=command, ok=result.ok,
        output=(result.output or "")[:8000], error=result.error or None,
    )


def collect_facts_node(client, timeout: int = 60):
    """Node: SSH chạy các lệnh read-only để chụp trạng thái hệ thống."""

    def node(state: AgentState) -> dict:
        facts: list[Fact] = []
        for name, cmd in BASE_CHECKS:
            facts.append(_run_check(client, name, cmd, timeout))
        gw_cmd = (
            "GW=$(ip route | awk '/default/ {print $3; exit}'); "
            "[ -n \"$GW\" ] && ping -c2 -W2 \"$GW\" || echo 'no-gateway'"
        )
        facts.append(_run_check(client, "ping_gateway", gw_cmd, timeout))
        return {"facts": facts}

    return node


def collect_logs_node(client, timeout: int = 60):
    """Node: đọc log hệ thống và trích tín hiệu bất thường (rule-based)."""

    def node(state: AgentState) -> dict:
        logs: list[LogSignal] = []
        for name, cmd in LOG_CHECKS:
            if safety.classify_command(cmd).blocked:
                continue
            try:
                result = client.run(cmd, timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Không đọc được %s: %s", name, exc)
                continue
            if (result.output or "").strip():
                logs.extend(heuristics.extract_log_signals(name, result.output))
        return {"log_signals": logs[:80]}

    return node


def diagnose_node(llm):
    """Node: sinh Diagnosis — dùng LLM nếu có, không thì heuristic."""

    def node(state: AgentState) -> dict:
        facts = state.get("facts", [])
        signals = state.get("log_signals", [])
        diagnosis: Diagnosis | None = None

        if llm is not None:
            try:
                diagnosis = _llm_diagnose(llm, state.get("host_name", "?"), facts, signals)
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM chẩn đoán lỗi, fallback heuristic: %s", exc)

        if diagnosis is None:
            diagnosis = analyzers.heuristic_diagnose(facts, signals)

        iterations = state.get("iterations", 0) + 1
        return {"diagnosis": diagnosis, "iterations": iterations}

    return node


def _llm_diagnose(llm, host: str, facts, signals) -> Diagnosis | None:
    """Gọi LLM với structured output để chẩn đoán."""
    from pydantic import BaseModel, Field

    class LLMDiagnosis(BaseModel):
        summary: str = Field(description="Tóm tắt tình trạng host (1-2 câu tiếng Việt)")
        root_cause: str = Field(default="", description="Nguyên nhân gốc nếu xác định được")
        problem_ids: list[str] = Field(
            default_factory=list,
            description="Dạng 'disk-full:/var', 'unit-failed:nginx.service', 'log:oom:journal_err'...",
        )
        need_more_info: bool = Field(default=False, description="Cần thu thập thêm thông tin?")
        extra_commands: list[str] = Field(
            default_factory=list, description="Lệnh read-only cần chạy thêm (nếu need_more_info)"
        )
        recommendations: list[str] = Field(default_factory=list, description="Khuyến nghị an toàn")

    fact_lines = "\n".join(
        f"[{f.name}] ok={f.ok}\n{(f.output or f.error or '')[:1500]}" for f in facts
    )
    signal_lines = "\n".join(
        f"- ({s.kind}/{s.severity.value}) {s.detail} | {s.evidence[:200]}" for s in signals
    ) or "(không có)"
    prompt = (
        "Bạn là chuyên gia SRE. Phân tích số liệu hệ thống và tín hiệu log "
        f"của host '{host}' dưới đây, rồi kết luận.\n\n"
        f"=== SỐ LIỆU HỆ THỐNG ===\n{fact_lines}\n\n"
        f"=== TÍN HIỆU LOG ===\n{signal_lines}\n\n"
        "Chỉ trả về structured output. problem_ids phải dùng các dạng: "
        "disk-full:<mount>, inode-full:<mount>, unit-failed:<unit>, "
        "link-down:<iface>, gw-unreachable, mem-critical, swap-heavy, "
        "log:oom:<nguồn>, log:bruteforce:<nguồn>, log:io-error:<nguồn>."
    )
    structured = llm.with_structured_output(LLMDiagnosis)
    raw = structured.invoke(prompt)
    data = raw.model_dump() if hasattr(raw, "model_dump") else dict(raw)

    # Khôi phục finding đầy đủ từ heuristic (giữ evidence/detail)
    base = analyzers.heuristic_diagnose(facts, signals)
    by_id = {f.id: f for f in base.findings}
    findings = [
        by_id.get(fid, Finding(id=fid, title=fid, severity=Severity.WARNING, detail="(từ LLM)"))
        for fid in data.get("problem_ids", [])
    ]
    return Diagnosis(
        summary=data.get("summary", base.summary),
        root_cause=data.get("root_cause", ""),
        confidence=0.8,
        findings=findings or base.findings,
        need_more_info=bool(data.get("need_more_info")),
        extra_commands=list(data.get("extra_commands", []))[:5],
        recommendations=list(data.get("recommendations", [])),
    )


def plan_node(llm):
    """Node: lập RepairPlan — LLM nếu có, không thì heuristic."""

    def node(state: AgentState) -> dict:
        diagnosis: Diagnosis = state.get("diagnosis") or Diagnosis()
        plan: RepairPlan | None = None

        if llm is not None and diagnosis.findings:
            try:
                plan = _llm_plan(llm, diagnosis)
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM lập kế hoạch lỗi, fallback heuristic: %s", exc)

        if plan is None:
            plan = analyzers.heuristic_plan(diagnosis)

        # Lọc bước nguy hiểm — không bao giờ đưa vào kế hoạch
        safe_steps = []
        for step in plan.steps:
            verdict = safety.classify_command(step.command)
            if verdict.blocked:
                logger.warning("Bỏ bước %s — lệnh bị chặn: %s", step.id, verdict.reason)
                continue
            step.risk = verdict.risk
            safe_steps.append(step)
        plan.steps = safe_steps
        return {"plan": plan}

    return node


def _llm_plan(llm, diagnosis: Diagnosis) -> RepairPlan | None:
    from pydantic import BaseModel, Field

    class LLMStep(BaseModel):
        description: str = Field(description="Mô tả bước (tiếng Việt)")
        command: str = Field(description="Đúng MỘT lệnh shell, read-mostly, KHÔNG phá huỷ")
        continue_on_error: bool = Field(default=False)

    class LLMPlan(BaseModel):
        title: str
        rationale: str = ""
        steps: list[LLMStep] = Field(default_factory=list)

    findings_txt = "\n".join(
        f"- [{f.severity.value}] {f.id}: {f.title} | gợi ý: {f.suggested_fixes}"
        for f in diagnosis.findings
    )
    prompt = (
        "Lập kế hoạch sửa chữa AN TOÀN cho các vấn đề sau. Chỉ dùng lệnh read-mostly "
        "hoặc sửa chữa không phá huỷ: systemctl restart <svc>, journalctl --vacuum-*, "
        "apt-get clean, ip link set <if> up, ufw limit ..., sysctl -w net.*. "
        "TUYỆT ĐỐI không dùng: rm -rf, mkfs, dd of=/dev/*, iptables -F, shutdown/reboot.\n\n"
        f"VẤN ĐỀ:\n{findings_txt}\n\nChỉ trả về structured output."
    )
    structured = llm.with_structured_output(LLMPlan)
    raw = structured.invoke(prompt)
    data = raw.model_dump() if hasattr(raw, "model_dump") else dict(raw)
    return RepairPlan(
        title=data.get("title", "Kế hoạch sửa chữa"),
        rationale=data.get("rationale", ""),
        steps=[
            RepairStep(
                id=f"llm-{i}", description=s.get("description", ""),
                command=s.get("command", ""), risk=safety.classify_command(s.get("command", "")).risk,
                continue_on_error=bool(s.get("continue_on_error")),
            )
            for i, s in enumerate(data.get("steps", []))
            if s.get("command")
        ],
    )


def approval_node():
    """Node: human-in-the-loop — dừng graph, chờ người dùng phê duyệt kế hoạch.

    Dùng ``interrupt()`` của LangGraph; giá trị trả về của ``interrupt`` là
    quyết định của người dùng (dict {approved: bool, reason: str}).
    Auto-approve nếu state.auto_approve=True.
    """

    def node(state: AgentState) -> dict:
        plan: RepairPlan | None = state.get("plan")
        if plan is None or not plan.steps:
            return {"approval": {"approved": False, "reason": "không có kế hoạch"}}

        if state.get("auto_approve"):
            return {"approval": {"approved": True, "reason": "auto-approve"}}

        from langgraph.types import interrupt

        payload = {
            "title": plan.title,
            "rationale": plan.rationale,
            "steps": [
                {"id": s.id, "risk": s.risk.value, "description": s.description, "command": s.command}
                for s in plan.steps
            ],
        }
        decision = interrupt(payload)
        return {"approval": decision}

    return node


def execute_node(client, timeout: int = 120):
    """Node: thực thi từng bước trong RepairPlan đã được phê duyệt.

    - Chạy tuần tự, dừng khi bước fail (trừ khi continue_on_error=True).
    - Chặn mọi lệnh bị safety module đánh dấu blocked (phòng thủ lần nữa).
    """

    def node(state: AgentState) -> dict:
        approval = state.get("approval") or {}
        plan: RepairPlan | None = state.get("plan")
        results: list[CommandResult] = []

        if not approval.get("approved") or plan is None:
            return {"results": results}

        for step in plan.steps:
            verdict = safety.classify_command(step.command)
            if verdict.blocked:
                results.append(CommandResult(
                    step_id=step.id, command=step.command, ok=False,
                    error=f"bị chặn: {verdict.reason}",
                ))
                if not step.continue_on_error:
                    break
                continue

            try:
                res = client.run(step.command, timeout=step.timeout or timeout)
            except Exception as exc:  # noqa: BLE001
                results.append(CommandResult(
                    step_id=step.id, command=step.command, ok=False, error=str(exc),
                ))
                if not step.continue_on_error:
                    break
                continue

            results.append(CommandResult(
                step_id=step.id, command=step.command, ok=res.ok,
                exit_code=res.exit_code, output=(res.output or "")[:4000],
                error=res.error or "",
            ))
            if not res.ok and not step.continue_on_error:
                break

        return {"results": results}

    return node


def verify_node(client, timeout: int = 60):
    """Node: chạy lại các check read-only để xác nhận sự cố đã được xử lý."""

    def node(state: AgentState) -> dict:
        facts: list[Fact] = []
        for name, cmd in BASE_CHECKS:
            facts.append(_run_check(client, name, cmd, timeout))

        old: Diagnosis = state.get("diagnosis") or Diagnosis()
        new_signals: list[LogSignal] = []
        # Chỉ quét log mức ERR — log warning cũ vẫn còn dòng nên không dùng để verify
        for name, cmd in LOG_CHECKS:
            if name not in ("journal_err", "dmesg_err"):
                continue
            if safety.classify_command(cmd).blocked:
                continue
            try:
                res = client.run(cmd, timeout=timeout)
            except Exception:  # noqa: BLE001
                continue
            if (res.output or "").strip():
                new_signals.extend(heuristics.extract_log_signals(name, res.output))

        fresh = analyzers.heuristic_diagnose(facts, new_signals)
        old_ids = {f.id for f in old.findings}
        still_broken = [f.id for f in fresh.findings if f.id in old_ids]
        resolved = sorted(old_ids - set(still_broken))

        passed = not still_broken
        summary = (
            "Toàn bộ vấn đề đã được xử lý ✅"
            if passed
            else f"Còn {len(still_broken)} vấn đề chưa xử lý: {', '.join(still_broken)}"
        )
        verification = VerificationResult(
            passed=passed, summary=summary, remaining_issues=still_broken,
        )
        return {"verification_facts": facts, "verification": verification,
                "diagnosis": fresh if not passed else old}

    return node


_SEV_BADGE = {
    "critical": "🔴", "error": "🟠", "warning": "🟡", "info": "🔵",
}


def report_node():
    """Node: dựng báo cáo Markdown cuối cùng."""

    def node(state: AgentState) -> dict:
        from datetime import datetime

        host = state.get("host_name", "?")
        dx: Diagnosis = state.get("diagnosis") or Diagnosis()
        plan: RepairPlan | None = state.get("plan")
        approval = state.get("approval") or {}
        results: list[CommandResult] = state.get("results", [])
        ver: VerificationResult | None = state.get("verification")

        lines = [
            f"# 🩺 Báo cáo chẩn đoán & sửa chữa — {host}",
            f"_Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
            "",
            f"## 1. Tóm tắt",
            f"{dx.summary}",
        ]
        if dx.root_cause:
            lines += ["", f"**Nguyên nhân gốc:** {dx.root_cause}"]
        lines += ["", "## 2. Các vấn đề phát hiện"]
        if dx.findings:
            for f in dx.findings:
                badge = _SEV_BADGE.get(f.severity.value, "⚪")
                lines.append(f"- {badge} **{f.title}** (`{f.id}`) — {f.detail}")
                if f.evidence:
                    lines.append(f"  - Bằng chứng: `{f.evidence[:160]}`")
        else:
            lines.append("- Không phát hiện vấn đề.")

        if plan and plan.steps:
            lines += ["", f"## 3. Kế hoạch sửa chữa — {plan.title}", plan.rationale]
            for s in plan.steps:
                lines.append(f"- [{s.risk.value}] `{s.command}` — {s.description}")

        if results:
            lines += ["", "## 4. Kết quả thực thi"]
            for r in results:
                mark = "✅" if r.ok else "❌"
                lines.append(f"- {mark} `{r.command}`" + (f" — {r.error}" if not r.ok else ""))

        if ver is not None:
            lines += ["", "## 5. Kiểm tra sau sửa", ver.summary]
            for issue in ver.remaining_issues:
                lines.append(f"- ⚠️ còn lại: `{issue}`")

        if dx.recommendations:
            lines += ["", "## Khuyến nghị"]
            lines += [f"- {r}" for r in dx.recommendations]

        report_md = "\n".join(lines)
        return {"report_md": report_md}

    return node


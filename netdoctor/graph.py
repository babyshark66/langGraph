"""Xây dựng LangGraph: lắp các node thành graph chẩn đoán & sửa chữa.

Luồng chính:
    START → collect_facts → collect_logs → diagnose
        ├─ (cần thêm thông tin & iterations < max) → collect_facts   [loop]
        ├─ (remediate=True & có vấn đề) → plan → approval → execute → verify → report
        └─ (không remediate / không vấn đề) → report → END
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from .nodes import (
    approval_node,
    collect_facts_node,
    collect_logs_node,
    diagnose_node,
    execute_node,
    plan_node,
    report_node,
    verify_node,
)
from .state import AgentState, Diagnosis


def _route_after_diagnose(state: AgentState) -> str:
    """Quyết định bước tiếp theo sau khi chẩn đoán."""
    dx: Diagnosis | None = state.get("diagnosis")
    iterations = state.get("iterations", 1)
    max_iter = state.get("max_iterations", 2)

    if dx is None:
        return "report"

    # LLM/agent cần thêm thông tin → quay lại thu thập (có giới hạn vòng lặp)
    if dx.need_more_info and dx.extra_commands and iterations < max_iter:
        return "collect_more"

    has_problem = bool(dx.findings)
    wants_fix = bool(state.get("remediate"))
    if has_problem and wants_fix:
        return "plan"
    return "report"


def _route_after_approval(state: AgentState) -> str:
    approval = state.get("approval") or {}
    plan = state.get("plan")
    if approval.get("approved") and plan and plan.steps:
        return "execute"
    return "report"


def _extra_collect_node(client, timeout: int = 60):
    """Node chạy bổ sung các lệnh read-only do diagnose yêu cầu."""

    def node(state: AgentState) -> dict:
        dx: Diagnosis | None = state.get("diagnosis")
        extra = (dx.extra_commands if dx else []) or []
        from .nodes import _run_check

        new_facts = [
            _run_check(client, f"extra-{i}", cmd, timeout)
            for i, cmd in enumerate(extra[:5])
        ]
        return {"facts": new_facts}

    return node


def build_graph(client, llm=None, checkpointer: Any = None, timeout: int = 60):
    """Lập graph NetDoctor đã compile.

    - ``client``: HostClient (SSHSession hoặc MockHostClient).
    - ``llm``: ChatOpenAI hoặc None (heuristic).
    - ``checkpointer``: ví dụ InMemorySaver() để bật human-in-the-loop.
    """
    sg = StateGraph(AgentState)
    sg.add_node("collect_facts", collect_facts_node(client, timeout))
    sg.add_node("collect_logs", collect_logs_node(client, timeout))
    sg.add_node("diagnose", diagnose_node(llm))
    sg.add_node("collect_more", _extra_collect_node(client, timeout))
    sg.add_node("plan", plan_node(llm))
    sg.add_node("approval", approval_node())
    sg.add_node("execute", execute_node(client, timeout))
    sg.add_node("verify", verify_node(client, timeout))
    sg.add_node("report", report_node())

    sg.add_edge(START, "collect_facts")
    sg.add_edge("collect_facts", "collect_logs")
    sg.add_edge("collect_logs", "diagnose")
    sg.add_conditional_edges(
        "diagnose",
        _route_after_diagnose,
        {
            "collect_more": "collect_more",
            "plan": "plan",
            "report": "report",
        },
    )
    # Sau khi thu thêm info → quay lại logs/diagnose để tổng hợp lại
    sg.add_edge("collect_more", "collect_logs")
    sg.add_edge("plan", "approval")
    sg.add_conditional_edges(
        "approval",
        _route_after_approval,
        {"execute": "execute", "report": "report"},
    )
    sg.add_edge("execute", "verify")
    sg.add_edge("verify", "report")
    sg.add_edge("report", END)

    return sg.compile(checkpointer=checkpointer)

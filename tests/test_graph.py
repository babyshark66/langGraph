"""Test tích luỹ graph NetDoctor end-to-end với host mock (offline)."""

from langgraph.checkpoint.memory import InMemorySaver

from netdoctor.config import HostEntry
from netdoctor.graph import build_graph
from netdoctor.mock_host import MockHostClient


def _make_app():
    client = MockHostClient(HostEntry(name="mock-demo", host="127.0.0.1", mock=True))
    app = build_graph(client, llm=None, checkpointer=InMemorySaver(), timeout=30)
    return client, app


def test_full_remediation_flow():
    client, app = _make_app()
    initial = {
        "host_name": "mock-demo",
        "remediate": True,
        "auto_approve": True,
        "offline": True,
        "max_iterations": 2,
    }
    result = app.invoke(initial, {"configurable": {"thread_id": "t1"}})

    # 1) chẩn đoán ra vấn đề
    dx = result["diagnosis"]
    ids = {f.id for f in dx.findings}
    assert any(i.startswith("disk") for i in ids), ids
    assert any("nginx" in i for i in ids), ids
    assert any(i.startswith("link-down") for i in ids), ids

    # 2) kế hoạch không chứa lệnh bị chặn
    plan = result["plan"]
    assert plan.steps, "kế hoạch không được rỗng"
    from netdoctor.safety import classify_command

    for step in plan.steps:
        assert not classify_command(step.command).blocked

    # 3) thực thi thành công toàn bộ
    assert result["results"] and all(r.ok for r in result["results"])

    # 4) verify đạt
    assert result["verification"].passed is True

    # 5) host mock đã "khỏe"
    assert client.disk_fixed and client.nginx_fixed and client.link_fixed

    # 6) có báo cáo markdown
    assert "Báo cáo chẩn đoán" in result["report_md"]


def test_diagnose_only_no_remediate():
    _, app = _make_app()
    result = app.invoke(
        {"host_name": "mock-demo", "remediate": False, "offline": True},
        {"configurable": {"thread_id": "t2"}},
    )
    assert result["diagnosis"].findings
    assert "plan" not in result or not result.get("plan") or not result["plan"].steps
    assert "report_md" in result
    # không thực thi lệnh nào
    assert not result.get("results")


def test_human_approval_interrupt_flow():
    _, app = _make_app()
    cfg = {"configurable": {"thread_id": "t3"}}
    initial = {
        "host_name": "mock-demo", "remediate": True,
        "auto_approve": False, "offline": True,
    }
    result = app.invoke(initial, cfg)
    # graph dừng chờ phê duyệt
    assert result.get("__interrupt__")
    assert not result.get("results")

    # người dùng từ chối → không thực thi
    from langgraph.types import Command

    result2 = app.invoke(
        Command(resume={"approved": False, "reason": "test"}), cfg
    )
    assert not result2.get("results")
    assert "report_md" in result2

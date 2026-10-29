#!/usr/bin/env python3
"""NetDoctor CLI — tự động chẩn đoán & sửa chữa hệ thống mạng/VM qua SSH.

Ví dụ:
    python main.py list-hosts
    python main.py run --host vm-web-01 --remediate --offline
    python main.py run --host mock-demo --remediate --auto-approve
    python main.py logs --host vm-web-01
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from netdoctor.config import Settings, load_hosts
from netdoctor.graph import build_graph
from netdoctor.llm import build_llm
from netdoctor.ssh_client import build_client

console = Console()


def _cmd_list_hosts(_args) -> int:
    hosts = load_hosts()
    table = Table(title="Danh sách host trong hosts.yaml")
    for col in ("Tên", "Địa chỉ", "User", "Tags", "Mock"):
        table.add_column(col)
    for h in hosts.values():
        table.add_row(h.name, f"{h.host}:{h.port}", h.username, ", ".join(h.tags), "✅" if h.mock else "")
    console.print(table)
    return 0


def _run(args, remediate: bool) -> int:
    settings = Settings()
    hosts = load_hosts()
    if args.host not in hosts:
        console.print(f"[red]Host '{args.host}' không có trong {settings.hosts_file}[/red]")
        return 2
    entry = hosts[args.host]
    mock = args.mock or entry.mock
    client = build_client(entry, delay=settings.command_delay, mock=mock)
    llm = build_llm(settings, offline=args.offline)

    from langgraph.checkpoint.memory import InMemorySaver

    app = build_graph(client, llm=llm, checkpointer=InMemorySaver(), timeout=entry.command_timeout)

    initial = {
        "host_name": entry.name,
        "remediate": remediate,
        "auto_approve": getattr(args, "auto_approve", False),
        "offline": args.offline or llm is None,
        "max_iterations": args.max_iterations,
    }
    config = {"configurable": {"thread_id": f"{entry.name}-{args.run_id}"}}

    console.print(f"[bold green]▶ Chạy NetDoctor cho [cyan]{entry.name}[/cyan] "
                  f"({'mock' if mock else client.target})[/bold green]")
    result = app.invoke(initial, config)

    # Nếu graph dừng tại approval (interrupt) → hỏi người dùng tương tác
    while result.get("__interrupt__"):
        state_snapshot = app.get_state(config)
        plan = state_snapshot.values.get("plan")
        _print_plan(plan)
        answer = console.input(
            "[yellow]Bạn có muốn thực thi kế hoạch này? (y/N):[/yellow] "
        ).strip().lower()
        approved = answer in ("y", "yes")
        from langgraph.types import Command

        result = app.invoke(
            Command(resume={"approved": approved, "reason": "user"}), config
        )

    report = result.get("report_md", "")
    if report:
        console.print(Markdown(report))
        out_dir = Path(settings.reports_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{entry.name}.md"
        out_path.write_text(report, encoding="utf-8")
        console.print(f"\n[green]📄 Báo cáo đã lưu:[/green] {out_path}")
    try:
        client.close()
    except Exception:  # noqa: BLE001
        pass
    return 0


def _print_plan(plan) -> None:
    if plan is None:
        console.print("[red]Không có kế hoạch.[/red]")
        return
    table = Table(title=f"Kế hoạch: {plan.title}")
    for col in ("ID", "Mức rủi ro", "Lệnh", "Mô tả"):
        table.add_column(col)
    for s in plan.steps:
        table.add_row(s.id, s.risk.value, s.command, s.description)
    console.print(table)


def _cmd_run(args) -> int:
    return _run(args, remediate=args.remediate)


def _cmd_logs(args) -> int:
    args.remediate = False
    return _run(args, remediate=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netdoctor",
        description="Agent LangGraph chẩn đoán & sửa chữa hệ thống mạng/VM qua SSH.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-hosts", help="Liệt kê host trong hosts.yaml")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--host", required=True, help="Tên host trong hosts.yaml")
        p.add_argument("--offline", action="store_true", help="Không dùng LLM (chỉ heuristic)")
        p.add_argument("--mock", action="store_true", help="Dùng host giả lập (không SSH thật)")
        p.add_argument("--max-iterations", type=int, default=2, help="Số vòng thu thập tối đa")
        p.add_argument("--run-id", default="1", help="ID của lần chạy (cho checkpointer)")

    p_run = sub.add_parser("run", help="Chẩn đoán (và tuỳ chọn sửa chữa)")
    add_common(p_run)
    p_run.add_argument("--remediate", action="store_true", help="Cho phép lập kế hoạch + sửa chữa")
    p_run.add_argument("--auto-approve", action="store_true", help="Bỏ qua human approval")
    p_run.set_defaults(func=_cmd_run)

    p_logs = sub.add_parser("logs", help="Chỉ phân tích log (không remediate)")
    add_common(p_logs)
    p_logs.set_defaults(func=_cmd_logs)

    p_list = sub.choices["list-hosts"]
    p_list.set_defaults(func=_cmd_list_hosts)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

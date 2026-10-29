"""Schema dữ liệu dùng chung cho toàn bộ graph (state + models)."""

from __future__ import annotations

import operator
from enum import Enum
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Fact(BaseModel):
    """Kết quả một lệnh thu thập thông tin read-only qua SSH."""

    name: str
    command: str
    ok: bool = True
    output: str = ""
    error: str | None = None


class LogSignal(BaseModel):
    """Tín hiệu bất thường rút ra từ log (rule-based)."""

    source: str
    kind: str
    severity: Severity = Severity.WARNING
    detail: str = ""
    evidence: str = ""


class Finding(BaseModel):
    """Một vấn đề được phát hiện."""

    id: str
    title: str
    severity: Severity = Severity.WARNING
    detail: str = ""
    evidence: str = ""
    suggested_fixes: list[str] = Field(default_factory=list)


class Diagnosis(BaseModel):
    """Kết luận chẩn đoán của agent."""

    summary: str = ""
    root_cause: str = ""
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    need_more_info: bool = False
    extra_commands: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class RepairStep(BaseModel):
    """Một bước trong kế hoạch sửa chữa (mỗi bước 1 lệnh)."""

    id: str
    description: str
    command: str
    risk: RiskLevel = RiskLevel.MEDIUM
    timeout: int = 60
    continue_on_error: bool = False
    verify_command: str | None = None


class RepairPlan(BaseModel):
    """Kế hoạch sửa chữa cần được phê duyệt trước khi thực thi."""

    title: str
    rationale: str = ""
    steps: list[RepairStep] = Field(default_factory=list)


class CommandResult(BaseModel):
    """Kết quả thực thi một bước sửa chữa."""

    step_id: str
    command: str
    ok: bool
    exit_code: int | None = None
    output: str = ""
    error: str = ""


class VerificationResult(BaseModel):
    """Kết quả kiểm tra lại sau khi sửa chữa."""

    passed: bool
    summary: str = ""
    remaining_issues: list[str] = Field(default_factory=list)


class ApprovalDecision(BaseModel):
    """Quyết định phê duyệt của con người (human-in-the-loop)."""

    approved: bool = False
    comment: str = ""


class AgentState(TypedDict, total=False):
    """Trạng thái dùng chung của graph NetDoctor.

    Các trường có reducer ``operator.add`` sẽ tích luỹ qua các vòng lặp
    (ví dụ agent yêu cầu bổ sung thông tin rồi quay lại collect).
    """

    # --- đầu vào ---
    host_name: str
    remediate: bool  # cho phép lập kế hoạch + sửa chữa
    auto_approve: bool  # bỏ qua bước human approval (chỉ dùng khi tự tin)
    offline: bool  # không dùng LLM, chỉ heuristic
    max_iterations: int
    reports_dir: str
    command_timeout: int

    # --- dữ liệu trung gian ---
    facts: Annotated[list[Fact], operator.add]
    log_signals: Annotated[list[LogSignal], operator.add]
    verification_facts: Annotated[list[Fact], operator.add]
    diagnosis: Diagnosis | None
    iterations: int
    plan: RepairPlan | None
    approval: ApprovalDecision | None
    results: Annotated[list[CommandResult], operator.add]
    verification: VerificationResult | None

    # --- đầu ra ---
    report_md: str
    report_path: str
    errors: Annotated[list[str], operator.add]

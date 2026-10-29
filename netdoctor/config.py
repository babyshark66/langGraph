"""Cấu hình ứng dụng: biến môi trường (.env) + file hosts.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Cấu hình tổng thể, đọc từ biến môi trường có tiền tố NETDOCTOR_."""

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="NETDOCTOR_", extra="ignore"
    )

    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str | None = None

    hosts_file: str = "configs/hosts.yaml"
    reports_dir: str = "logs/reports"

    command_delay: float = 0.3
    connect_timeout: int = 10
    command_timeout: int = 60


class HostEntry(BaseModel):
    """Một host/VM trong hosts.yaml."""

    name: str
    host: str
    port: int = 22
    username: str = "root"
    auth: str = "password"  # password | key | none
    password: str | None = None
    key_file: str | None = None
    tags: list[str] = Field(default_factory=list)
    sudo: bool = False
    connect_timeout: int = 10
    command_timeout: int = 60
    max_retries: int = 2
    mock: bool = False
    checks: list[str] = Field(default_factory=list)  # lệnh read-only riêng


def load_hosts(path: str | Path | None = None) -> dict[str, HostEntry]:
    """Đọc hosts.yaml -> {tên host: HostEntry}."""
    path = Path(path or Settings().hosts_file)
    if not path.exists():
        raise FileNotFoundError(
            f"Không tìm thấy file cấu hình host: {path}. "
            "Hãy tạo file theo configs/hosts.yaml mẫu."
        )
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults = raw.get("defaults") or {}
    hosts: dict[str, HostEntry] = {}
    for item in raw.get("hosts") or []:
        merged = {**defaults, **item}
        entry = HostEntry(**merged)
        hosts[entry.name] = entry
    return hosts

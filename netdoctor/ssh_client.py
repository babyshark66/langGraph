"""Lớp kết nối SSH (paramiko) với retry, timeout và chặn lệnh nguy hiểm."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import HostEntry
from .safety import classify_command

logger = logging.getLogger(__name__)


@dataclass
class RunResult:
    ok: bool
    output: str = ""
    error: str = ""
    exit_code: int | None = None


class HostClient(Protocol):
    """Giao diện chung mà mọi node dùng để tương tác với host mục tiêu."""

    name: str
    target: str

    def run(self, command: str, timeout: int | None = None) -> RunResult: ...

    def read_file(self, path: str, max_lines: int = 200) -> RunResult: ...

    def close(self) -> None: ...


class BlockedCommandError(RuntimeError):
    """Lệnh bị safety module chặn — không bao giờ rời khỏi máy cục bộ."""


class SSHSession:
    """Một phiên SSH tới host/VM mục tiêu.

    - Mọi lệnh đều phải qua ``classify_command`` (chặn CRITICAL).
    - Có delay giữa các lệnh để không làm nghẽn host mục tiêu.
    - Tự retry khi kết nối rớt (thử tối đa ``max_retries`` lần).
    """

    def __init__(self, entry: HostEntry, delay: float = 0.3):
        self.entry = entry
        self.name = entry.name
        self.target = f"ssh://{entry.username}@{entry.host}:{entry.port}"
        self.delay = delay
        self._client = None
        self._connected = False

    def connect(self) -> None:
        """Mở kết nối SSH (an toàn khi gọi lặp lại)."""
        if self._connected:
            return
        import paramiko

        last_err: Exception | None = None
        for attempt in range(1, self.entry.max_retries + 2):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                kwargs: dict = {
                    "hostname": self.entry.host,
                    "port": self.entry.port,
                    "username": self.entry.username,
                    "timeout": self.entry.connect_timeout,
                    "banner_timeout": self.entry.connect_timeout,
                    "allow_agent": True,
                    "look_for_keys": True,
                }
                if self.entry.auth == "key" and self.entry.key_file:
                    kwargs["key_filename"] = str(Path(self.entry.key_file).expanduser())
                elif self.entry.auth == "password":
                    kwargs["password"] = self.entry.password
                client.connect(**kwargs)
                self._client = client
                self._connected = True
                return
            except Exception as exc:  # noqa: BLE001 — retry mọi lỗi kết nối
                last_err = exc
                client.close()
                logger.warning(
                    "SSH attempt %d/%d tới %s thất bại: %s",
                    attempt,
                    self.entry.max_retries + 1,
                    self.entry.host,
                    exc,
                )
                time.sleep(min(2**attempt, 8))
        raise ConnectionError(f"Không thể kết nối SSH tới {self.target}: {last_err}")

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        """Chạy một lệnh trên host. Tự chặn lệnh nguy hiểm trước khi gửi."""
        verdict = classify_command(command)
        if verdict.blocked:
            return RunResult(
                ok=False,
                error=f"BỊ CHẶN ({verdict.reason}): {command}",
                exit_code=None,
            )

        self.connect()
        assert self._client is not None
        timeout = timeout or self.entry.command_timeout
        effective = command
        if self.entry.sudo and not command.strip().startswith("sudo "):
            effective = f"sudo -n {command}"

        try:
            _, stdout, stderr = self._client.exec_command(
                effective, timeout=timeout, get_pty=False
            )
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            code = stdout.channel.recv_exit_status()
        except Exception as exc:  # noqa: BLE001
            self._connected = False
            return RunResult(ok=False, error=f"SSH exec lỗi: {exc}")

        if self.delay > 0:
            time.sleep(self.delay)  # giãn cách, tránh làm nghẽn host

        if code != 0:
            return RunResult(ok=False, output=out, error=err.strip(), exit_code=code)
        return RunResult(ok=True, output=out, error=err.strip(), exit_code=0)

    def read_file(self, path: str, max_lines: int = 200) -> RunResult:
        """Đọc tối đa ``max_lines`` dòng đầu của file trên host (read-only)."""
        safe_path = path.replace("'", "")
        return self.run(f"head -n {int(max_lines)} '{safe_path}'")

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None
                self._connected = False

    def __enter__(self) -> "SSHSession":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def build_client(entry: HostEntry, delay: float = 0.3, mock: bool = False):
    """Tạo client: MockHostClient nếu ``mock``/``entry.mock``, ngược lại SSH."""
    if mock or entry.mock:
        from .mock_host import MockHostClient

        return MockHostClient(entry)
    return SSHSession(entry, delay=delay)


__all__ = ["RunResult", "HostClient", "SSHSession", "BlockedCommandError", "build_client"]


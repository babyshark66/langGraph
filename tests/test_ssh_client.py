"""Test SSHSession với paramiko giả lập (không cần máy thật)."""

from unittest.mock import MagicMock, patch

import pytest

from netdoctor.config import HostEntry
from netdoctor.ssh_client import SSHSession


def _entry(**kw) -> HostEntry:
    base = dict(name="t", host="192.0.2.10", username="root", auth="password", password="x")
    base.update(kw)
    return HostEntry(**base)


def _fake_exec(output: bytes = b"ok\n", err: bytes = b"", code: int = 0):
    stdout = MagicMock()
    stdout.read.return_value = output
    stdout.channel.recv_exit_status.return_value = code
    stderr = MagicMock()
    stderr.read.return_value = err
    return (None, stdout, stderr)


@patch("paramiko.SSHClient")
def test_run_captures_output(mock_ssh):
    session = SSHSession(_entry(), delay=0)
    session.run("df -h")
    mock_ssh.return_value.exec_command.assert_called_once()
    sent = mock_ssh.return_value.exec_command.call_args[0][0]
    assert sent == "df -h"


@patch("paramiko.SSHClient")
def test_blocked_command_never_reaches_transport(mock_ssh):
    session = SSHSession(_entry(), delay=0)
    result = session.run("rm -rf /")
    assert result.ok is False
    assert "BỊ CHẶN" in result.error
    mock_ssh.return_value.exec_command.assert_not_called()


@patch("paramiko.SSHClient")
def test_nonzero_exit_is_failure(mock_ssh):
    mock_ssh.return_value.exec_command.return_value = _fake_exec(err=b"boom", code=3)
    session = SSHSession(_entry(), delay=0)
    result = session.run("systemctl is-active nginx")
    assert result.ok is False
    assert result.exit_code == 3


@patch("time.sleep")
@patch("paramiko.SSHClient")
def test_connect_retries_then_succeeds(mock_ssh, _sleep):
    # lần 1 lỗi, lần 2 thành công
    mock_ssh.return_value.connect.side_effect = [ConnectionError("net"), None]
    session = SSHSession(_entry(max_retries=2), delay=0)
    session.connect()
    assert session._connected is True
    assert mock_ssh.return_value.connect.call_count == 2


@patch("paramiko.SSHClient")
def test_sudo_is_prepended_when_enabled(mock_ssh):
    session = SSHSession(_entry(sudo=True), delay=0)
    session.run("systemctl restart nginx")
    sent = mock_ssh.return_value.exec_command.call_args[0][0]
    assert sent.startswith("sudo -n ")

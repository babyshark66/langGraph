"""Test module safety: chặn lệnh nguy hiểm + phân loại rủi ro."""

import pytest

from netdoctor.safety import classify_command, is_safe_to_run
from netdoctor.state import RiskLevel


@pytest.mark.parametrize(
    "cmd",
    [
        "rm -rf /",
        "rm -rf ~",
        "sudo rm -rf /var",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        "shutdown -h now",
        "reboot",
        ":(){ :|:& };:",
        "iptables -F",
        "wipefs -a /dev/sda",
        "> /dev/sda",
    ],
)
def test_dangerous_commands_blocked(cmd):
    verdict = classify_command(cmd)
    assert verdict.blocked is True
    assert verdict.risk is RiskLevel.CRITICAL


@pytest.mark.parametrize(
    "cmd,risk",
    [
        ("df -h", RiskLevel.LOW),
        ("free -h", RiskLevel.LOW),
        ("systemctl status nginx", RiskLevel.LOW),
        ("journalctl -p err -n 100", RiskLevel.LOW),
        ("ip -br addr", RiskLevel.LOW),
        ("cat /var/log/auth.log", RiskLevel.LOW),
        ("systemctl restart nginx", RiskLevel.HIGH),
        ("systemctl stop nginx", RiskLevel.HIGH),
        ("journalctl --vacuum-size=200M", RiskLevel.MEDIUM),
        ("apt-get clean", RiskLevel.MEDIUM),
        ("ip link set eth1 up", RiskLevel.MEDIUM),
    ],
)
def test_risk_classification(cmd, risk):
    assert classify_command(cmd).risk is risk


def test_is_safe_to_run_blocks_high_when_not_allowed():
    assert is_safe_to_run("systemctl restart nginx", allow_high=False).blocked is True
    assert is_safe_to_run("systemctl restart nginx", allow_high=True).blocked is False


def test_sudo_prefix_is_stripped_for_analysis():
    # sudo không được coi là "đọc file" nếu lệnh con nguy hiểm
    verdict = classify_command("sudo mkfs.ext4 /dev/sdb1")
    assert verdict.blocked is True

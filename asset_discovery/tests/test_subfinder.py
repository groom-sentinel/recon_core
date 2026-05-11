"""subfinder wrapper 단위 테스트 (subprocess mocked)."""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from asset_discovery.subfinder import (
    SubfinderNotInstalledError,
    is_available,
    run_subfinder,
)


def test_run_subfinder_parses_stdout() -> None:
    """subfinder 표준 출력에서 도메인 추출 + 정렬 + 중복 제거."""
    fake_output = MagicMock()
    fake_output.stdout = (
        "api.example.com\n"
        "Admin.example.com\n"  # 대소문자 정규화 확인
        "www.example.com\n"
        "api.example.com\n"  # 중복
        "\n"  # 빈 줄
    )
    with patch("subprocess.run", return_value=fake_output):
        result = run_subfinder("example.com")
    assert result == [
        "admin.example.com",
        "api.example.com",
        "www.example.com",
    ]


def test_run_subfinder_not_installed_raises() -> None:
    """subfinder 바이너리 없으면 SubfinderNotInstalledError."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(SubfinderNotInstalledError):
            run_subfinder("example.com")


def test_run_subfinder_timeout_raises() -> None:
    """타임아웃 시 RuntimeError."""
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="subfinder", timeout=60.0),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            run_subfinder("example.com")


def test_is_available_true_when_subfinder_works() -> None:
    with patch("subprocess.run", return_value=MagicMock()):
        assert is_available() is True


def test_is_available_false_when_not_found() -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert is_available() is False

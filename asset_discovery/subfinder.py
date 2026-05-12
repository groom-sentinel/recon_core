"""subfinder Go binary subprocess wrapper.

subfinder 는 ProjectDiscovery 의 서브도메인 발견 도구.
설치: `brew install subfinder`
"""
from __future__ import annotations

import subprocess


class SubfinderNotInstalledError(RuntimeError):
    """subfinder 바이너리가 PATH 에 없을 때."""


def is_available() -> bool:
    """subfinder 바이너리가 사용 가능한지 확인."""
    try:
        subprocess.run(
            ["subfinder", "-version"],
            capture_output=True,
            timeout=5.0,
            check=True,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False


def run_subfinder(domain: str, timeout: float = 60.0) -> list[str]:
    """시드 도메인에 대해 subfinder 실행, 유니크 서브도메인 리스트 반환.

    Args:
        domain: 시드 도메인 (예: "example.com")
        timeout: subprocess 타임아웃 (초)

    Returns:
        정렬된 유니크 서브도메인 리스트

    Raises:
        SubfinderNotInstalledError: subfinder 바이너리 없음
        RuntimeError: 실행 타임아웃 또는 비정상 종료
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except FileNotFoundError as e:
        raise SubfinderNotInstalledError(
            "subfinder not found. Install with: brew install subfinder"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"subfinder timed out for {domain}") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"subfinder failed for {domain}: {e.stderr}") from e

    lines: list[str] = [
        line.strip().lower()
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    return sorted(set(lines))

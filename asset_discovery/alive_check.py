"""HTTP HEAD 프로브로 호스트가 살아있는지 확인.

HTTPS 먼저 시도 → 실패 시 HTTP 시도.
5xx 미만 응답을 모두 alive 로 간주 (404 도 살아있음 — 서버가 응답한 것이므로).
"""
from __future__ import annotations

import httpx


async def is_alive(domain: str, timeout: float = 5.0) -> bool:
    """HTTPS 또는 HTTP HEAD 요청에 응답하는지 확인.

    Args:
        domain: 도메인 이름 (스킴 없음, 예: "example.com")
        timeout: 요청당 타임아웃 (초)

    Returns:
        둘 중 하나라도 5xx 미만으로 응답하면 True
    """
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,  # 학습 환경: 만료/자체서명 인증서 허용
    ) as client:
        for scheme in ("https", "http"):
            try:
                response = await client.head(f"{scheme}://{domain}")
                if response.status_code < 500:
                    return True
            except (httpx.RequestError, httpx.TimeoutException):
                continue
    return False

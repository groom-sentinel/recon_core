"""crt.sh SSL certificate transparency log query.

crt.sh 는 발급된 SSL 인증서 로그를 공개한 서비스.
회사가 도메인용 인증서를 발급할 때 도메인 이름이 인증서에 박혀서 공개됨.
이를 역으로 이용해 서브도메인을 찾아낸다.
"""
from __future__ import annotations

import httpx
from pydantic import BaseModel, ValidationError


class _CrtShEntry(BaseModel):
    """crt.sh response entry — name_value 필드만 사용 (다른 필드는 무시)."""

    name_value: str | None = None


async def query_crt_sh(domain: str, timeout: float = 30.0) -> list[str]:
    """Query crt.sh and return unique subdomains found in cert logs.

    Args:
        domain: 시드 도메인 (예: "example.com")
        timeout: HTTP 타임아웃 (초)

    Returns:
        정렬된 유니크 서브도메인 리스트. 실패 시 빈 리스트.
    """
    url = "https://crt.sh/"
    params: dict[str, str] = {"q": domain, "output": "json"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(url, params=params)
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError):
            return []

        # response.json() 은 Any (외부 데이터 경계) — 즉시 좁힘
        raw_data = response.json()

    if not isinstance(raw_data, list):
        return []

    subdomains: set[str] = set()
    for raw_entry in raw_data:
        try:
            entry = _CrtShEntry.model_validate(raw_entry)
        except ValidationError:
            continue
        if not entry.name_value:
            continue
        # name_value 는 줄바꿈으로 구분된 여러 도메인일 수 있음
        for line in entry.name_value.split("\n"):
            cleaned: str = line.strip().lower()
            # 와일드카드(*.example.com) 는 제외
            if cleaned and not cleaned.startswith("*."):
                subdomains.add(cleaned)

    return sorted(subdomains)

"""WHOIS query wrapper (python-whois library).

python-whois 는 도메인 등록 정보를 동적 객체로 반환.
필드별 타입이 들쭉날쭉 (str / list[str] / None / datetime / list[datetime])
하므로 boundary 에서 즉시 타입 좁힘.
"""
from __future__ import annotations

from datetime import datetime

import whois  # type: ignore[import-untyped]  # python-whois has no stubs

from asset_discovery.models import WhoisInfo


def _normalize_str(value: object) -> str | None:
    """python-whois 가 str / list[str] / None 으로 섞어 반환 → str | None 으로 좁힘."""
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, str):
            cleaned = first.strip()
            return cleaned or None
    return None


def _normalize_date(value: object) -> datetime | None:
    """python-whois 가 datetime / list[datetime] / None 으로 섞어 반환."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, datetime):
            return first
    return None


def get_whois(domain: str) -> WhoisInfo:
    """WHOIS 조회. 실패 시 빈 WhoisInfo 반환 (예외 안 던짐)."""
    try:
        record = whois.whois(domain)
    except Exception:  # noqa: BLE001 — WHOIS lib raises various unspecified errors
        return WhoisInfo()

    return WhoisInfo(
        org=_normalize_str(getattr(record, "org", None)),
        country=_normalize_str(getattr(record, "country", None)),
        creation_date=_normalize_date(getattr(record, "creation_date", None)),
        registrar=_normalize_str(getattr(record, "registrar", None)),
    )

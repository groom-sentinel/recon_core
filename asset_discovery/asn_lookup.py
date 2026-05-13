"""ASN lookup via ipwhois + 클라우드 제공자 자동 식별.

IPWhois.lookup_rdap() 은 dict[str, Any] 형태로 반환 — boundary 에서 즉시 좁힘.
"""
from __future__ import annotations

from ipwhois import IPWhois  # type: ignore[import-untyped]

from asset_discovery.models import AsnInfo, CloudProvider

# ASN organization 키워드 → 클라우드 제공자 매핑
# 우선순위 순서대로 검사 (AWS 가 GOOGLE 보다 먼저)
_CLOUD_ASN_PATTERNS: tuple[tuple[str, CloudProvider], ...] = (
    ("AMAZON", "aws"),
    ("AWS", "aws"),
    ("GOOGLE", "gcp"),
    ("MICROSOFT", "azure"),
    ("AZURE", "azure"),
    ("CLOUDFLARE", "cloudflare"),
)


def _detect_cloud(asn_org: str | None) -> CloudProvider | None:
    """ASN org 문자열에서 클라우드 제공자 추정."""
    if not asn_org:
        return None
    upper = asn_org.upper()
    for pattern, provider in _CLOUD_ASN_PATTERNS:
        if pattern in upper:
            return provider
    return None


def lookup_asn(ip: str) -> AsnInfo:
    """IP 주소에 대한 ASN 정보 조회. 실패 시 빈 AsnInfo 반환."""
    try:
        result = IPWhois(ip).lookup_rdap(depth=1)
    except Exception:  # noqa: BLE001 — ipwhois 라이브러리 경계
        return AsnInfo()

    # result 는 dict[str, Any] (ipwhois 미타입) — boundary 좁힘
    if not isinstance(result, dict):
        return AsnInfo()

    asn_raw: object = result.get("asn")
    asn: str | None = f"AS{asn_raw}" if isinstance(asn_raw, str) else None

    asn_desc: object = result.get("asn_description")
    asn_org: str | None = asn_desc if isinstance(asn_desc, str) else None

    country_raw: object = result.get("asn_country_code")
    country: str | None = country_raw if isinstance(country_raw, str) else None

    return AsnInfo(
        asn=asn,
        asn_org=asn_org,
        country=country,
        cloud_provider=_detect_cloud(asn_org),
    )

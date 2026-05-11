"""DNS record lookups via dnspython.

A, AAAA, MX, NS, TXT 레코드 종합 조회 + SPF/DMARC 존재 여부 판정.
"""
from __future__ import annotations

import dns.exception
import dns.resolver

from asset_discovery.models import DnsRecords

# DNS 조회 시 정상 처리할 예외들 — 도메인이 응답 없음 / 미존재 / 타임아웃 / 네임서버 실패
_BENIGN_DNS_ERRORS: tuple[type[Exception], ...] = (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


def _make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _resolve_simple(domain: str, rdtype: str, timeout: float = 5.0) -> list[str]:
    """범용 레코드 조회 — str(rdata) 로 변환 + 후행 '.' 제거."""
    resolver = _make_resolver(timeout)
    try:
        answers = resolver.resolve(domain, rdtype)
    except _BENIGN_DNS_ERRORS:
        return []
    return sorted({str(rdata).rstrip(".") for rdata in answers})


def get_a(domain: str, timeout: float = 5.0) -> list[str]:
    return _resolve_simple(domain, "A", timeout)


def get_aaaa(domain: str, timeout: float = 5.0) -> list[str]:
    return _resolve_simple(domain, "AAAA", timeout)


def get_ns(domain: str, timeout: float = 5.0) -> list[str]:
    return _resolve_simple(domain, "NS", timeout)


def get_mx(domain: str, timeout: float = 5.0) -> list[str]:
    """MX 레코드 — 우선순위 정보 유지 (예: '10 mail.example.com')."""
    return _resolve_simple(domain, "MX", timeout)


def get_txt(domain: str, timeout: float = 5.0) -> list[str]:
    """TXT 레코드 — bytes 합쳐서 문자열로 정규화."""
    resolver = _make_resolver(timeout)
    try:
        answers = resolver.resolve(domain, "TXT")
    except _BENIGN_DNS_ERRORS:
        return []

    records: list[str] = []
    for rdata in answers:
        # TXT rdata 는 .strings 속성으로 bytes 튜플 노출 (다른 타입엔 없음)
        strings_attr: object = getattr(rdata, "strings", None)
        if not isinstance(strings_attr, tuple):
            continue
        text: str = "".join(
            s.decode("utf-8", errors="replace")
            for s in strings_attr
            if isinstance(s, bytes)
        )
        if text:
            records.append(text)
    return sorted(records)


def has_dmarc_record(domain: str, timeout: float = 5.0) -> bool:
    """_dmarc.<domain> 에 TXT 레코드 존재하면 True."""
    return bool(get_txt(f"_dmarc.{domain}", timeout))


def get_full_dns(domain: str, timeout: float = 5.0) -> DnsRecords:
    """도메인의 모든 DNS 레코드를 한 객체로 조회."""
    a_records = get_a(domain, timeout)
    aaaa_records = get_aaaa(domain, timeout)
    ns_records = get_ns(domain, timeout)
    mx_records = get_mx(domain, timeout)
    txt_records = get_txt(domain, timeout)

    has_spf: bool = any("v=spf1" in t.lower() for t in txt_records)
    has_dmarc: bool = has_dmarc_record(domain, timeout)

    return DnsRecords(
        a=a_records,
        aaaa=aaaa_records,
        ns=ns_records,
        mx=mx_records,
        txt=txt_records,
        has_spf=has_spf,
        has_dmarc=has_dmarc,
    )

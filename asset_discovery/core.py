"""모든 discovery 서브모듈을 비동기로 통합 실행하는 오케스트레이터.

흐름:
  [Stage 1] 서브도메인 수집 (subfinder + crt.sh, 병렬)
       ↓
  [Stage 2] 각 서브도메인 enrich (alive + DNS + WHOIS + ASN, 병렬)
       ↓
  [출력] list[DiscoveredAsset]
"""
from __future__ import annotations

import asyncio

from asset_discovery import (
    alive_check,
    asn_lookup,
    crt_sh,
    dns_lookup,
    subfinder,
    whois_lookup,
)
from asset_discovery.models import AsnInfo, DiscoveredAsset, DiscoverySource


async def _collect_subfinder(domain: str) -> tuple[DiscoverySource, list[str]]:
    """subfinder 를 asyncio.to_thread 로 비동기 실행."""
    if not subfinder.is_available():
        return ("subfinder", [])
    try:
        results = await asyncio.to_thread(subfinder.run_subfinder, domain)
    except Exception:  # noqa: BLE001 — subfinder 실패는 빈 결과로
        return ("subfinder", [])
    return ("subfinder", results)


async def _collect_crt_sh(domain: str) -> tuple[DiscoverySource, list[str]]:
    """crt.sh API 비동기 호출."""
    results = await crt_sh.query_crt_sh(domain)
    return ("crt.sh", results)


async def discover_assets(
    seed_domain: str,
    *,
    use_subfinder: bool = True,
    use_crt_sh: bool = True,
) -> list[DiscoveredAsset]:
    """시드 도메인에 대해 전체 discovery 파이프라인 실행."""
    # === Stage 1: 서브도메인 수집 (병렬) ===
    collection_tasks: list[asyncio.Task[tuple[DiscoverySource, list[str]]]] = []
    if use_subfinder:
        collection_tasks.append(asyncio.create_task(_collect_subfinder(seed_domain)))
    if use_crt_sh:
        collection_tasks.append(asyncio.create_task(_collect_crt_sh(seed_domain)))

    if not collection_tasks:
        return []

    collected: list[tuple[DiscoverySource, list[str]]] = await asyncio.gather(
        *collection_tasks,
    )

    # 도메인 → 발견 소스 리스트 매핑
    sources_by_sub: dict[str, list[DiscoverySource]] = {}
    for source, subs in collected:
        for sub in subs:
            sources_by_sub.setdefault(sub, []).append(source)

    # 시드 도메인 자체도 항상 포함 (ASM 의 표준 동작)
    seed_lower: str = seed_domain.lower().strip()
    if seed_lower:
        sources_by_sub.setdefault(seed_lower, []).append("manual")

    if not sources_by_sub:
        return []

    # === Stage 2: 각 서브도메인 enrich (병렬) ===
    enrichment_tasks = [
        _enrich_one(sub, sources_by_sub[sub])
        for sub in sources_by_sub
    ]
    assets: list[DiscoveredAsset] = await asyncio.gather(*enrichment_tasks)

    return sorted(assets, key=lambda a: a.domain)


async def _enrich_one(
    domain: str,
    discovered_via: list[DiscoverySource],
) -> DiscoveredAsset:
    """단일 도메인에 대해 alive/DNS/WHOIS 를 병렬로 enrich + IP 가 있으면 ASN."""
    alive_task = alive_check.is_alive(domain)
    dns_task = asyncio.to_thread(dns_lookup.get_full_dns, domain)
    whois_task = asyncio.to_thread(whois_lookup.get_whois, domain)

    is_alive_result, dns, whois_info = await asyncio.gather(
        alive_task, dns_task, whois_task,
    )

    # IP → ASN (DNS A 레코드 첫 번째 사용)
    ip: str | None = dns.a[0] if dns.a else None
    asn_info: AsnInfo
    if ip is not None:
        asn_info = await asyncio.to_thread(asn_lookup.lookup_asn, ip)
    else:
        asn_info = AsnInfo()

    return DiscoveredAsset(
        domain=domain,
        ip=ip,
        discovered_via=discovered_via,
        is_alive=is_alive_result,
        dns=dns,
        whois=whois_info,
        asn_info=asn_info,
    )

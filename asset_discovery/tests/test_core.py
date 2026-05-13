"""core 오케스트레이터 단위 테스트 (모든 하위 모듈 mocked)."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from asset_discovery.core import discover_assets
from asset_discovery.models import AsnInfo, DnsRecords, WhoisInfo


@pytest.mark.asyncio
async def test_discover_assets_merges_two_sources() -> None:
    """subfinder + crt.sh 결과 통합 → 중복 도메인은 양쪽 소스 모두 기록."""
    with (
        patch("asset_discovery.subfinder.is_available", return_value=True),
        patch(
            "asset_discovery.subfinder.run_subfinder",
            return_value=["api.example.com", "www.example.com"],
        ),
        patch(
            "asset_discovery.crt_sh.query_crt_sh",
            new=AsyncMock(return_value=["www.example.com", "admin.example.com"]),
        ),
        patch(
            "asset_discovery.alive_check.is_alive",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "asset_discovery.dns_lookup.get_full_dns",
            return_value=DnsRecords(a=["1.2.3.4"]),
        ),
        patch(
            "asset_discovery.whois_lookup.get_whois",
            return_value=WhoisInfo(org="Example Corp"),
        ),
        patch(
            "asset_discovery.asn_lookup.lookup_asn",
            return_value=AsnInfo(asn="AS12345", cloud_provider="aws"),
        ),
    ):
        assets = await discover_assets("example.com")

    # 4개 도메인: 시드(example.com) + api + www + admin
    domains = [a.domain for a in assets]
    assert sorted(domains) == [
        "admin.example.com", "api.example.com",
        "example.com", "www.example.com",
    ]

    # 시드 자체는 "manual" 로 표시
    seed_asset = next(a for a in assets if a.domain == "example.com")
    assert "manual" in seed_asset.discovered_via

    # www.example.com 양 소스 검증
    www_asset = next(a for a in assets if a.domain == "www.example.com")
    assert set(www_asset.discovered_via) == {"subfinder", "crt.sh"}

    # api.example.com 은 subfinder 만
    api_asset = next(a for a in assets if a.domain == "api.example.com")
    assert api_asset.discovered_via == ["subfinder"]

    # admin.example.com 은 crt.sh 만
    admin_asset = next(a for a in assets if a.domain == "admin.example.com")
    assert admin_asset.discovered_via == ["crt.sh"]

    # 모든 자산에 enrichment 적용됨
    for asset in assets:
        assert asset.ip == "1.2.3.4"
        assert asset.is_alive is True
        assert asset.whois.org == "Example Corp"
        assert asset.asn_info.asn == "AS12345"
        assert asset.asn_info.cloud_provider == "aws"


@pytest.mark.asyncio
async def test_discover_assets_empty_when_all_sources_disabled() -> None:
    """모든 소스 비활성화 시 빈 결과."""
    assets = await discover_assets(
        "example.com",
        use_subfinder=False,
        use_crt_sh=False,
    )
    assert assets == []


@pytest.mark.asyncio
async def test_discover_assets_seed_only_when_no_subdomains_found() -> None:
    """소스가 빈 결과여도 시드 도메인은 enrich 됨."""
    with (
        patch("asset_discovery.subfinder.is_available", return_value=True),
        patch("asset_discovery.subfinder.run_subfinder", return_value=[]),
        patch(
            "asset_discovery.crt_sh.query_crt_sh",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "asset_discovery.alive_check.is_alive",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "asset_discovery.dns_lookup.get_full_dns",
            return_value=DnsRecords(a=["1.2.3.4"]),
        ),
        patch(
            "asset_discovery.whois_lookup.get_whois",
            return_value=WhoisInfo(),
        ),
        patch(
            "asset_discovery.asn_lookup.lookup_asn",
            return_value=AsnInfo(),
        ),
    ):
        assets = await discover_assets("example.com")
    assert len(assets) == 1
    assert assets[0].domain == "example.com"
    assert assets[0].discovered_via == ["manual"]


@pytest.mark.asyncio
async def test_discover_assets_skips_asn_when_no_ip() -> None:
    """DNS A 레코드 없으면 IP/ASN 모두 None."""
    with (
        patch("asset_discovery.subfinder.is_available", return_value=True),
        patch(
            "asset_discovery.subfinder.run_subfinder",
            return_value=["nodns.example.com"],
        ),
        patch(
            "asset_discovery.crt_sh.query_crt_sh",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "asset_discovery.alive_check.is_alive",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "asset_discovery.dns_lookup.get_full_dns",
            return_value=DnsRecords(),  # 모두 빈 결과
        ),
        patch(
            "asset_discovery.whois_lookup.get_whois",
            return_value=WhoisInfo(),
        ),
    ):
        assets = await discover_assets("example.com")

    # nodns.example.com + example.com (시드)
    assert len(assets) == 2
    nodns = next(a for a in assets if a.domain == "nodns.example.com")
    assert nodns.ip is None
    assert nodns.asn_info.asn is None  # ASN lookup 스킵됨


@pytest.mark.asyncio
async def test_discover_assets_skips_subfinder_when_unavailable() -> None:
    """subfinder 미설치 시 crt.sh 만 사용."""
    with (
        patch("asset_discovery.subfinder.is_available", return_value=False),
        patch(
            "asset_discovery.crt_sh.query_crt_sh",
            new=AsyncMock(return_value=["found.example.com"]),
        ),
        patch(
            "asset_discovery.alive_check.is_alive",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "asset_discovery.dns_lookup.get_full_dns",
            return_value=DnsRecords(a=["8.8.8.8"]),
        ),
        patch(
            "asset_discovery.whois_lookup.get_whois",
            return_value=WhoisInfo(),
        ),
        patch(
            "asset_discovery.asn_lookup.lookup_asn",
            return_value=AsnInfo(),
        ),
    ):
        assets = await discover_assets("example.com")

    # found.example.com (crt.sh) + example.com (시드)
    assert len(assets) == 2
    found = next(a for a in assets if a.domain == "found.example.com")
    assert found.discovered_via == ["crt.sh"]
    seed = next(a for a in assets if a.domain == "example.com")
    assert seed.discovered_via == ["manual"]

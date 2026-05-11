"""Pydantic 모델 검증 테스트."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from asset_discovery.models import (
    AsnInfo,
    DiscoveredAsset,
    DnsRecords,
    WhoisInfo,
)


# === DiscoveredAsset ===


def test_discovered_asset_minimal() -> None:
    """도메인만으로도 생성 가능."""
    asset = DiscoveredAsset(domain="example.com")
    assert asset.domain == "example.com"
    assert asset.ip is None
    assert asset.is_alive is False
    assert asset.discovered_via == []


def test_discovered_asset_with_metadata() -> None:
    asset = DiscoveredAsset(
        domain="api.example.com",
        ip="93.184.216.34",
        discovered_via=["subfinder", "crt.sh"],
        is_alive=True,
    )
    assert asset.ip == "93.184.216.34"
    assert "subfinder" in asset.discovered_via


def test_discovered_asset_timestamps_default_now_utc() -> None:
    asset = DiscoveredAsset(domain="example.com")
    assert asset.first_seen.tzinfo == UTC
    assert asset.last_checked.tzinfo == UTC


def test_discovered_asset_serialization_round_trip() -> None:
    original = DiscoveredAsset(
        domain="example.com",
        ip="93.184.216.34",
        discovered_via=["subfinder"],
        is_alive=True,
    )
    json_str: str = original.model_dump_json()
    restored = DiscoveredAsset.model_validate_json(json_str)
    assert restored == original


# === DnsRecords ===


def test_dns_records_default_empty() -> None:
    dns = DnsRecords()
    assert dns.a == []
    assert dns.mx == []
    assert dns.has_spf is False
    assert dns.has_dmarc is False


def test_dns_records_frozen() -> None:
    dns = DnsRecords(a=["1.2.3.4"])
    with pytest.raises(ValidationError):
        dns.a = ["5.6.7.8"]  # type: ignore[misc]


# === WhoisInfo ===


def test_whois_info_optional_fields() -> None:
    whois = WhoisInfo(org="Example Corp", country="US")
    assert whois.org == "Example Corp"
    assert whois.creation_date is None


def test_whois_info_with_datetime() -> None:
    created = datetime(2020, 1, 1, tzinfo=UTC)
    whois = WhoisInfo(creation_date=created)
    assert whois.creation_date == created


# === AsnInfo ===


def test_asn_info_minimal() -> None:
    asn = AsnInfo()
    assert asn.asn is None
    assert asn.cloud_provider is None


def test_asn_info_with_cloud() -> None:
    asn = AsnInfo(asn="AS16509", asn_org="AMAZON-02", cloud_provider="aws")
    assert asn.cloud_provider == "aws"


def test_asn_info_invalid_cloud_provider() -> None:
    """CloudProvider Literal 타입 — 정의되지 않은 값은 거부."""
    with pytest.raises(ValidationError):
        AsnInfo(cloud_provider="oracle")  # type: ignore[arg-type]

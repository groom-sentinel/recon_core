"""ASN lookup 단위 테스트 (ipwhois mocked)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from asset_discovery.asn_lookup import _detect_cloud, lookup_asn


# === _detect_cloud ===


def test_detect_cloud_aws() -> None:
    assert _detect_cloud("AMAZON-02") == "aws"
    assert _detect_cloud("AWS, US") == "aws"


def test_detect_cloud_gcp() -> None:
    assert _detect_cloud("GOOGLE LLC") == "gcp"


def test_detect_cloud_azure() -> None:
    assert _detect_cloud("MICROSOFT-CORP-MSN-AS-BLOCK") == "azure"
    assert _detect_cloud("AZURE-NETWORK") == "azure"


def test_detect_cloud_cloudflare() -> None:
    assert _detect_cloud("CLOUDFLARENET") == "cloudflare"


def test_detect_cloud_unknown_returns_none() -> None:
    assert _detect_cloud("KAKAO-AS") is None
    assert _detect_cloud("KOREA-TELECOM") is None


def test_detect_cloud_none_input() -> None:
    assert _detect_cloud(None) is None
    assert _detect_cloud("") is None


def test_detect_cloud_case_insensitive() -> None:
    assert _detect_cloud("amazon") == "aws"
    assert _detect_cloud("Google Inc") == "gcp"


# === lookup_asn ===


def test_lookup_asn_aws_ip() -> None:
    fake_result: dict[str, object] = {
        "asn": "16509",
        "asn_description": "AMAZON-02, US",
        "asn_country_code": "US",
    }
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = fake_result
    with patch("asset_discovery.asn_lookup.IPWhois", return_value=mock_instance):
        info = lookup_asn("3.5.140.0")
    assert info.asn == "AS16509"
    assert info.asn_org == "AMAZON-02, US"
    assert info.country == "US"
    assert info.cloud_provider == "aws"


def test_lookup_asn_korean_isp() -> None:
    """클라우드 아닌 일반 ISP."""
    fake_result: dict[str, object] = {
        "asn": "4766",
        "asn_description": "KIXS-AS-KR Korea Telecom",
        "asn_country_code": "KR",
    }
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = fake_result
    with patch("asset_discovery.asn_lookup.IPWhois", return_value=mock_instance):
        info = lookup_asn("1.2.3.4")
    assert info.asn == "AS4766"
    assert info.country == "KR"
    assert info.cloud_provider is None  # 클라우드 식별 안 됨


def test_lookup_asn_missing_fields() -> None:
    """일부 필드 누락 시 None."""
    fake_result: dict[str, object] = {"asn": "12345"}  # description, country 없음
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = fake_result
    with patch("asset_discovery.asn_lookup.IPWhois", return_value=mock_instance):
        info = lookup_asn("1.2.3.4")
    assert info.asn == "AS12345"
    assert info.asn_org is None
    assert info.country is None


def test_lookup_asn_exception_returns_empty() -> None:
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.side_effect = RuntimeError("IPWhois failed")
    with patch("asset_discovery.asn_lookup.IPWhois", return_value=mock_instance):
        info = lookup_asn("invalid-ip")
    assert info.asn is None
    assert info.asn_org is None
    assert info.cloud_provider is None


def test_lookup_asn_non_string_asn() -> None:
    """ipwhois 가 가끔 int 반환 → str 아니면 None."""
    fake_result: dict[str, object] = {
        "asn": 16509,  # int, not str
        "asn_description": "AMAZON-02",
    }
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = fake_result
    with patch("asset_discovery.asn_lookup.IPWhois", return_value=mock_instance):
        info = lookup_asn("3.5.140.0")
    assert info.asn is None  # int 라서 None
    assert info.asn_org == "AMAZON-02"
    assert info.cloud_provider == "aws"

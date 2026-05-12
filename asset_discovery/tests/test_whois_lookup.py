"""WHOIS lookup 단위 테스트 (whois.whois mocked)."""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

from asset_discovery.whois_lookup import (
    _normalize_date,
    _normalize_str,
    get_whois,
)


# === _normalize_str ===


def test_normalize_str_from_string() -> None:
    assert _normalize_str("Example Corp") == "Example Corp"


def test_normalize_str_strips_whitespace() -> None:
    assert _normalize_str("  Example  ") == "Example"


def test_normalize_str_from_list_uses_first() -> None:
    assert _normalize_str(["First Org", "Second"]) == "First Org"


def test_normalize_str_empty_string_to_none() -> None:
    assert _normalize_str("") is None
    assert _normalize_str("   ") is None


def test_normalize_str_none() -> None:
    assert _normalize_str(None) is None


def test_normalize_str_non_string_to_none() -> None:
    assert _normalize_str(123) is None
    assert _normalize_str([123]) is None


# === _normalize_date ===


def test_normalize_date_from_datetime() -> None:
    dt = datetime(2020, 1, 1, tzinfo=UTC)
    assert _normalize_date(dt) == dt


def test_normalize_date_from_list() -> None:
    dt = datetime(2020, 1, 1, tzinfo=UTC)
    assert _normalize_date([dt, datetime(2021, 1, 1, tzinfo=UTC)]) == dt


def test_normalize_date_none() -> None:
    assert _normalize_date(None) is None


def test_normalize_date_string_to_none() -> None:
    """문자열은 datetime 이 아니므로 None."""
    assert _normalize_date("2020-01-01") is None


# === get_whois ===


def test_get_whois_full_record() -> None:
    """정상 WHOIS 응답 처리."""
    fake_record = SimpleNamespace(
        org="Example Corp",
        country="US",
        creation_date=datetime(1995, 8, 14, tzinfo=UTC),
        registrar="GoDaddy",
    )
    with patch("whois.whois", return_value=fake_record):
        info = get_whois("example.com")
    assert info.org == "Example Corp"
    assert info.country == "US"
    assert info.creation_date == datetime(1995, 8, 14, tzinfo=UTC)
    assert info.registrar == "GoDaddy"


def test_get_whois_handles_list_values() -> None:
    """python-whois 가 list 로 반환하는 경우."""
    fake_record = SimpleNamespace(
        org=["First Corp", "Second Corp"],
        country=["US"],
        creation_date=[datetime(2000, 1, 1, tzinfo=UTC)],
        registrar="Registrar Inc",
    )
    with patch("whois.whois", return_value=fake_record):
        info = get_whois("example.com")
    assert info.org == "First Corp"
    assert info.country == "US"
    assert info.creation_date == datetime(2000, 1, 1, tzinfo=UTC)


def test_get_whois_missing_attributes() -> None:
    """일부 필드가 None 이거나 누락된 경우."""
    fake_record = SimpleNamespace(org=None, country=None,
                                  creation_date=None, registrar=None)
    with patch("whois.whois", return_value=fake_record):
        info = get_whois("example.com")
    assert info.org is None
    assert info.country is None
    assert info.creation_date is None


def test_get_whois_exception_returns_empty() -> None:
    """python-whois 예외 시 빈 WhoisInfo (예외 전파 X)."""
    with patch("whois.whois", side_effect=Exception("network error")):
        info = get_whois("nonexistent.example")
    assert info.org is None
    assert info.country is None
    assert info.creation_date is None
    assert info.registrar is None

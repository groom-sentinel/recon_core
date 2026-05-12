"""DNS lookup 단위 테스트 (dns.resolver mocked)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver

from asset_discovery.dns_lookup import (
    get_a,
    get_full_dns,
    get_mx,
    get_ns,
    get_txt,
    has_dmarc_record,
)


class _FakeRdata:
    """일반 레코드용 mock — str(rdata) 호출 시 지정된 값을 반환."""

    def __init__(self, value: str) -> None:
        self._value = value

    def __str__(self) -> str:
        return self._value


class _FakeTxtRdata:
    """TXT 레코드용 mock — .strings 속성으로 bytes 튜플 제공."""

    def __init__(self, text: str) -> None:
        self.strings: tuple[bytes, ...] = (text.encode("utf-8"),)


def _make_str_rdatas(values: list[str]) -> list[_FakeRdata]:
    return [_FakeRdata(v) for v in values]


def _make_txt_rdatas(texts: list[str]) -> list[_FakeTxtRdata]:
    return [_FakeTxtRdata(t) for t in texts]


# === get_a ===


def test_get_a_returns_sorted_unique() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = _make_str_rdatas(["5.6.7.8", "1.2.3.4", "1.2.3.4"])
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_a("example.com")
    assert result == ["1.2.3.4", "5.6.7.8"]


def test_get_a_no_answer_returns_empty() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_a("example.com")
    assert result == []


def test_get_a_nxdomain_returns_empty() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_a("nonexistent.example")
    assert result == []


# === get_ns ===


def test_get_ns_strips_trailing_dot() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = _make_str_rdatas([
        "ns1.example.com.", "ns2.example.com."
    ])
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_ns("example.com")
    assert result == ["ns1.example.com", "ns2.example.com"]


# === get_mx ===


def test_get_mx_keeps_priority_format() -> None:
    """MX는 '10 mail.example.com' 형식 유지 (R4 가 파싱)."""
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = _make_str_rdatas([
        "10 mail.example.com.", "20 backup.example.com."
    ])
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_mx("example.com")
    assert result == ["10 mail.example.com", "20 backup.example.com"]


# === get_txt ===


def test_get_txt_decodes_bytes() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = _make_txt_rdatas([
        "v=spf1 include:_spf.google.com ~all"
    ])
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_txt("example.com")
    assert result == ["v=spf1 include:_spf.google.com ~all"]


def test_get_txt_no_answer_returns_empty() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        result = get_txt("example.com")
    assert result == []


# === has_dmarc_record ===


def test_has_dmarc_record_true() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = _make_txt_rdatas(["v=DMARC1; p=reject"])
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        assert has_dmarc_record("example.com") is True


def test_has_dmarc_record_false_when_no_answer() -> None:
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
    with patch("asset_discovery.dns_lookup._make_resolver", return_value=mock_resolver):
        assert has_dmarc_record("example.com") is False


# === get_full_dns ===


def test_get_full_dns_combines_all_records() -> None:
    """get_full_dns 가 모든 레코드 타입을 한 객체로 통합."""
    # 호출 순서: A, AAAA, NS, MX, TXT, _dmarc TXT
    call_count = {"n": 0}
    resolve_results: list[list[_FakeRdata] | list[_FakeTxtRdata] | type[Exception]] = [
        _make_str_rdatas(["1.2.3.4"]),                  # A
        dns.resolver.NoAnswer,                          # AAAA
        _make_str_rdatas(["ns1.example.com."]),         # NS
        _make_str_rdatas(["10 mail.example.com."]),     # MX
        _make_txt_rdatas(["v=spf1 ~all"]),              # TXT
        _make_txt_rdatas(["v=DMARC1; p=none"]),         # _dmarc TXT
    ]

    def fake_resolve(
        domain: str, rdtype: str,
    ) -> list[_FakeRdata] | list[_FakeTxtRdata]:
        idx = call_count["n"]
        call_count["n"] += 1
        result = resolve_results[idx]
        if isinstance(result, type):
            raise result()
        return result

    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = fake_resolve

    with patch(
        "asset_discovery.dns_lookup._make_resolver",
        return_value=mock_resolver,
    ):
        dns_records = get_full_dns("example.com")

    assert dns_records.a == ["1.2.3.4"]
    assert dns_records.aaaa == []
    assert dns_records.ns == ["ns1.example.com"]
    assert dns_records.mx == ["10 mail.example.com"]
    assert dns_records.has_spf is True
    assert dns_records.has_dmarc is True

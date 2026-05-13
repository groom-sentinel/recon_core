"""crt.sh API 클라이언트 테스트 (httpx mocked via respx)."""
from __future__ import annotations

import httpx
import pytest
import respx

from asset_discovery.crt_sh import query_crt_sh


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_parses_entries() -> None:
    """name_value 의 줄바꿈 분리 + 중복 제거 + 정렬."""
    fake_response = [
        {"name_value": "api.example.com\nwww.example.com"},
        {"name_value": "admin.example.com\napi.example.com"},  # api 중복
    ]
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=fake_response)
    )

    result = await query_crt_sh("example.com")

    assert result == ["admin.example.com", "api.example.com", "www.example.com"]


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_filters_wildcards() -> None:
    """*.example.com 와일드카드 엔트리는 제외."""
    fake_response = [
        {"name_value": "*.example.com\nadmin.example.com"},
        {"name_value": "*.api.example.com\napi.example.com"},
    ]
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=fake_response)
    )

    result = await query_crt_sh("example.com")

    assert "admin.example.com" in result
    assert "api.example.com" in result
    assert not any(r.startswith("*.") for r in result)


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_normalizes_case() -> None:
    """대문자 도메인은 소문자로 정규화."""
    fake_response = [
        {"name_value": "Admin.Example.COM"},
    ]
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=fake_response)
    )

    result = await query_crt_sh("example.com")

    assert result == ["admin.example.com"]


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_skips_invalid_entries() -> None:
    """name_value 가 없거나 빈 엔트리는 건너뜀."""
    fake_response = [
        {"name_value": "valid.example.com"},
        {"name_value": None},
        {"name_value": ""},
        {},  # name_value 자체가 없음
    ]
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=fake_response)
    )

    result = await query_crt_sh("example.com")

    assert result == ["valid.example.com"]


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_http_error_returns_empty() -> None:
    """HTTP 5xx 등 에러 시 빈 리스트 반환 (예외 X)."""
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(503)
    )

    result = await query_crt_sh("example.com")

    assert result == []


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_network_error_returns_empty() -> None:
    """네트워크 에러 시 빈 리스트 반환."""
    respx.get("https://crt.sh/").mock(
        side_effect=httpx.ConnectError("network down")
    )

    result = await query_crt_sh("example.com")

    assert result == []


@pytest.mark.asyncio
@respx.mock
async def test_query_crt_sh_non_list_response_returns_empty() -> None:
    """응답이 list 가 아니면 빈 리스트 (방어적 처리)."""
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json={"error": "rate limited"})
    )

    result = await query_crt_sh("example.com")

    assert result == []

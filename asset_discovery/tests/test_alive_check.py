"""alive_check 단위 테스트 (httpx mocked via respx)."""
from __future__ import annotations

import httpx
import pytest
import respx

from asset_discovery.alive_check import is_alive


@pytest.mark.asyncio
@respx.mock
async def test_is_alive_https_200() -> None:
    respx.head("https://example.com").mock(
        return_value=httpx.Response(200)
    )
    assert await is_alive("example.com") is True


@pytest.mark.asyncio
@respx.mock
async def test_is_alive_https_404_still_alive() -> None:
    """404 라도 서버가 응답한 것 = 살아있음."""
    respx.head("https://example.com").mock(
        return_value=httpx.Response(404)
    )
    assert await is_alive("example.com") is True


@pytest.mark.asyncio
@respx.mock
async def test_is_alive_fallback_to_http() -> None:
    """HTTPS 실패 시 HTTP 시도."""
    respx.head("https://example.com").mock(
        side_effect=httpx.ConnectError("no TLS")
    )
    respx.head("http://example.com").mock(
        return_value=httpx.Response(200)
    )
    assert await is_alive("example.com") is True


@pytest.mark.asyncio
@respx.mock
async def test_is_alive_both_fail() -> None:
    respx.head("https://example.com").mock(
        side_effect=httpx.ConnectError("https down")
    )
    respx.head("http://example.com").mock(
        side_effect=httpx.ConnectError("http down")
    )
    assert await is_alive("example.com") is False


@pytest.mark.asyncio
@respx.mock
async def test_is_alive_5xx_treated_as_dead() -> None:
    """5xx 는 서버 장애 → 살아있다고 보기 어려움. HTTP fallback 도 5xx 면 False."""
    respx.head("https://example.com").mock(
        return_value=httpx.Response(503)
    )
    respx.head("http://example.com").mock(
        return_value=httpx.Response(503)
    )
    assert await is_alive("example.com") is False


@pytest.mark.asyncio
@respx.mock
async def test_is_alive_timeout() -> None:
    respx.head("https://example.com").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    respx.head("http://example.com").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    assert await is_alive("example.com") is False

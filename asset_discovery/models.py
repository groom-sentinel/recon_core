"""Asset Discovery 모듈 데이터 모델.

Role 3 의 최종 산출물 정의. Role 4 (Pipeline) 가 이걸 소비해 자산 카드를 만든다.
"""
# NOTE: pydantic v2 사용. `from __future__ import annotations` 사용 X (BaseModel 호환).

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CloudProvider = Literal["aws", "gcp", "azure", "cloudflare", "other"]
DiscoverySource = Literal["subfinder", "crt.sh", "amass", "chaos", "manual"]


class WhoisInfo(BaseModel):
    """WHOIS 조회 결과 (모두 optional)."""

    model_config = ConfigDict(frozen=True)

    org: str | None = None
    country: str | None = None
    creation_date: datetime | None = None
    registrar: str | None = None


class AsnInfo(BaseModel):
    """ASN / 네트워크 정보."""

    model_config = ConfigDict(frozen=True)

    asn: str | None = None  # "AS16509"
    asn_org: str | None = None  # "AMAZON-02"
    country: str | None = None  # "US"
    cloud_provider: CloudProvider | None = None


class DnsRecords(BaseModel):
    """DNS 레코드 종합."""

    model_config = ConfigDict(frozen=True)

    a: list[str] = Field(default_factory=list)  # IPv4
    aaaa: list[str] = Field(default_factory=list)  # IPv6
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False


class DiscoveredAsset(BaseModel):
    """Role 3 의 최종 산출물.

    Role 4 (Pipeline) 가 이 객체와 Scanner / Vuln 결과를 결합해 자산 카드를 만든다.
    """

    # === 식별 ===
    domain: str
    ip: str | None = None

    # === 발견 메타 ===
    discovered_via: list[DiscoverySource] = Field(default_factory=list)
    is_alive: bool = False

    # === DNS ===
    dns: DnsRecords = Field(default_factory=DnsRecords)

    # === WHOIS ===
    whois: WhoisInfo = Field(default_factory=WhoisInfo)

    # === ASN / 네트워크 ===
    asn_info: AsnInfo = Field(default_factory=AsnInfo)

    # === 타임스탬프 ===
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_checked: datetime = Field(default_factory=lambda: datetime.now(UTC))

"""Unified pipeline data models for dashboard and DB storage."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

CloudProvider = Literal["aws", "gcp", "azure", "cloudflare", "other"]
DiscoverySource = Literal["subfinder", "crt.sh", "amass", "chaos", "manual"]
Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]


class WhoisInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    org: Optional[str] = None
    country: Optional[str] = None
    creation_date: Optional[datetime] = None
    registrar: Optional[str] = None


class AsnInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None


class DnsRecords(BaseModel):
    model_config = ConfigDict(extra="ignore")

    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    mx: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    txt: List[str] = Field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False


class HttpInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    server: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    error: Optional[str] = None


class ServiceScanRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: str
    port: int
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    os: Optional[str] = None
    http_info: HttpInfo = Field(default_factory=HttpInfo)
    scanned_at: Optional[datetime] = None


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: str
    port: int
    service: Optional[str] = None
    name: str
    severity: Severity = "unknown"
    cve_ids: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    epss: Optional[float] = None
    source: str
    module: Optional[str] = None
    matched_url: Optional[str] = None
    exploit_result: Optional[Dict[str, object]] = None
    no_vuln_found: bool = False


class AssetDiscoveryRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str
    ip: Optional[str] = None
    discovered_via: List[DiscoverySource] = Field(default_factory=list)
    is_alive: bool = False
    dns: DnsRecords = Field(default_factory=DnsRecords)
    whois: WhoisInfo = Field(default_factory=WhoisInfo)
    asn_info: AsnInfo = Field(default_factory=AsnInfo)
    first_seen: Optional[datetime] = None
    last_checked: Optional[datetime] = None


class DashboardSummary(BaseModel):
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    last_scanned_at: Optional[datetime] = None


class UnifiedAssetRecord(BaseModel):
    """Dashboard and DB friendly unified output per asset."""

    model_config = ConfigDict(extra="ignore")

    asset_key: str
    domain: Optional[str] = None
    ip: Optional[str] = None
    source: List[str] = Field(default_factory=list)
    discovery: Optional[AssetDiscoveryRecord] = None
    scans: List[ServiceScanRecord] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityRecord] = Field(default_factory=list)
    dashboard_summary: DashboardSummary = Field(default_factory=DashboardSummary)
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

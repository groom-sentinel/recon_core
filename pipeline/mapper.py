"""Mapping functions to merge scanner/discovery/vulnerability outputs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pipeline.models import (
    AssetDiscoveryRecord,
    DashboardSummary,
    HttpInfo,
    ServiceScanRecord,
    UnifiedAssetRecord,
    VulnerabilityRecord,
)


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return None
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        for fmt in (None, "%Y-%m-%d %H:%M:%S"):
            try:
                if fmt is None:
                    dt = datetime.fromisoformat(normalized)
                else:
                    dt = datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _severity_text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    lowered = value.strip().lower()
    if lowered in {"critical", "high", "medium", "low", "info"}:
        return lowered
    return "unknown"


def _split_product_version(version_text: str | None) -> tuple[str | None, str | None]:
    """Fallback split because scanner currently emits mixed text in version."""
    if not version_text:
        return (None, None)
    parts = version_text.strip().split()
    if not parts:
        return (None, None)
    if len(parts) == 1:
        return (parts[0], None)
    return (" ".join(parts[:-1]), parts[-1])


def _build_dashboard_summary(record: UnifiedAssetRecord) -> DashboardSummary:
    critical = sum(1 for v in record.vulnerabilities if v.severity == "critical")
    high = sum(1 for v in record.vulnerabilities if v.severity == "high")
    last_scanned_at: datetime | None = None
    for scan in record.scans:
        if scan.scanned_at and (last_scanned_at is None or scan.scanned_at > last_scanned_at):
            last_scanned_at = scan.scanned_at
    return DashboardSummary(
        total_open_ports=len(record.scans),
        total_vulnerabilities=len([v for v in record.vulnerabilities if not v.no_vuln_found]),
        critical_vulnerabilities=critical,
        high_vulnerabilities=high,
        last_scanned_at=last_scanned_at,
    )


def build_unified_records(
    *,
    discovery_results: list[dict[str, Any]],
    scanner_results: list[dict[str, Any]],
    vulnerability_results: list[dict[str, Any]],
) -> list[UnifiedAssetRecord]:
    """
    Merge three branch outputs into unified asset records.

    Inputs:
    - discovery_results: asset_discovery output list
    - scanner_results: scanner/scan_result.json list
    - vulnerability_results: vuln_scanner.scan(...) list
    """
    by_key: dict[str, UnifiedAssetRecord] = {}
    ip_to_domain: dict[str, str] = {}

    # 1) Discovery -> base asset nodes
    for raw in discovery_results:
        if hasattr(raw, "model_dump"):
            raw = raw.model_dump(mode="json")
        discovery = AssetDiscoveryRecord.model_validate(raw)
        key = discovery.domain or discovery.ip
        if key is None:
            continue
        if discovery.ip:
            ip_to_domain[discovery.ip] = discovery.domain
        by_key[key] = UnifiedAssetRecord(
            asset_key=key,
            domain=discovery.domain,
            ip=discovery.ip,
            source=["asset_discovery"],
            discovery=discovery,
        )

    # 2) Scanner -> service scan nodes
    for raw in scanner_results:
        ip = str(raw.get("ip", "")).strip()
        if not ip:
            continue
        key = ip_to_domain.get(ip, ip)
        record = by_key.get(key)
        if record is None:
            record = UnifiedAssetRecord(asset_key=key, ip=ip, source=[])
            by_key[key] = record

        version_raw = raw.get("version")
        product, parsed_version = _split_product_version(
            version_raw if isinstance(version_raw, str) else None
        )
        scan = ServiceScanRecord(
            ip=ip,
            port=int(raw["port"]),
            service=raw.get("service"),
            product=product,
            version=parsed_version,
            os=raw.get("os"),
            http_info=HttpInfo.model_validate(raw.get("http_info", {})),
            scanned_at=_parse_dt(raw.get("scanned_at")),
        )
        record.scans.append(scan)
        if "scanner" not in record.source:
            record.source.append("scanner")

    # 3) Vuln scanner -> vulnerabilities
    for raw in vulnerability_results:
        ip = str(raw.get("ip", "")).strip()
        if not ip:
            continue
        key = ip_to_domain.get(ip, ip)
        record = by_key.get(key)
        if record is None:
            record = UnifiedAssetRecord(asset_key=key, ip=ip, source=[])
            by_key[key] = record

        port = int(raw.get("port", 0))
        service = raw.get("service")
        no_vuln_found = bool(raw.get("no_vuln_found", False))
        vulns = raw.get("vulnerabilities", [])

        if not vulns and no_vuln_found:
            # Keep empty finding as an explicit "no issue" result.
            record.vulnerabilities.append(
                VulnerabilityRecord(
                    ip=ip,
                    port=port,
                    service=service,
                    name="no_vulnerability_detected",
                    source="system",
                    no_vuln_found=True,
                )
            )
        else:
            for vuln in vulns:
                v = VulnerabilityRecord(
                    ip=ip,
                    port=port,
                    service=service,
                    name=str(vuln.get("name", "unknown_vulnerability")),
                    severity=_severity_text(vuln.get("severity")),
                    cve_ids=list(vuln.get("cve_id", [])),
                    cvss_score=vuln.get("cvss_score"),
                    cvss_severity=vuln.get("cvss_severity"),
                    epss=vuln.get("epss"),
                    source=str(vuln.get("source", "unknown")),
                    module=vuln.get("module"),
                    matched_url=vuln.get("matched_url"),
                    exploit_result=vuln.get("result"),
                    no_vuln_found=False,
                )
                record.vulnerabilities.append(v)

        if "vuln_scanner" not in record.source:
            record.source.append("vuln_scanner")

    # 4) Fill derived fields for dashboard
    merged: list[UnifiedAssetRecord] = []
    for record in by_key.values():
        if record.domain is None and record.ip and record.ip in ip_to_domain:
            record.domain = ip_to_domain[record.ip]
        record.dashboard_summary = _build_dashboard_summary(record)
        merged.append(record)

    return sorted(merged, key=lambda r: r.asset_key)

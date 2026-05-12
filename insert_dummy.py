"""더미 데이터 삽입 스크립트 — assets / service_scans / vulnerabilities 각 1건"""

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timezone
from pipeline.repository import MySQLPipelineRepository
from pipeline.models import (
    UnifiedAssetRecord,
    ServiceScanRecord,
    VulnerabilityRecord,
    DashboardSummary,
    HttpInfo,
)

repo = MySQLPipelineRepository()
repo.init_schema()

dummy = UnifiedAssetRecord(
    # ── assets 테이블 ──────────────────────────────────────
    asset_key="scanme.nmap.org",
    domain="scanme.nmap.org",
    ip="45.33.32.156",
    source=["nmap"],
    dashboard_summary=DashboardSummary(
        total_open_ports=1,
        total_vulnerabilities=1,
        critical_vulnerabilities=0,
        high_vulnerabilities=1,
    ),
    ingested_at=datetime.now(timezone.utc),

    # ── service_scans 테이블 ───────────────────────────────
    scans=[
        ServiceScanRecord(
            ip="45.33.32.156",
            port=22,
            service="ssh",
            product="OpenSSH",
            version="8.9p1",
            os="Linux 5.x",
            http_info=HttpInfo(
                server=None,
                status_code=None,
                title=None,
                error=None,
            ),
            scanned_at=datetime.now(timezone.utc),
        )
    ],

    # ── vulnerabilities 테이블 ─────────────────────────────
    vulnerabilities=[
        VulnerabilityRecord(
            ip="45.33.32.156",
            port=22,
            service="ssh",
            name="OpenSSH username enumeration",
            severity="high",
            cve_ids=["CVE-2018-15473"],
            cvss_score=5.3,
            cvss_severity="medium",
            epss=0.012,
            source="nuclei",
            module="ssh-username-enum",
            matched_url=None,
            exploit_result=None,
            no_vuln_found=False,
        )
    ],
)

count = repo.save_unified_records([dummy])
print(f"삽입 완료: {count}개 자산")
print("  assets          → asset_key: scanme.nmap.org")
print("  service_scans   → port 22 (OpenSSH 8.9p1)")
print("  vulnerabilities → CVE-2018-15473 (high)")

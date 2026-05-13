"""MySQL repository for unified recon records using SQLAlchemy + pymysql."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Iterable

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from pipeline.models import UnifiedAssetRecord

load_dotenv()


def _to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    from datetime import timezone as _tz
    # MySQL DATETIME은 timezone offset 미지원 — naive UTC string으로 변환
    if value.tzinfo is not None:
        value = value.astimezone(_tz.utc).replace(tzinfo=None)
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _build_engine() -> Engine:
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "3306")
    name = os.environ.get("DB_NAME", "recon_db")
    user = os.environ.get("DB_USER", "recon")
    password = os.environ.get("DB_PASSWORD", "")
    url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{name}?charset=utf8mb4"
    return create_engine(url, pool_pre_ping=True)


class MySQLPipelineRepository:
    """Persist unified records into MySQL for dashboard queries."""

    def __init__(self, engine: Engine | None = None) -> None:
        self._engine = engine or _build_engine()

    def init_schema(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id   INT AUTO_INCREMENT PRIMARY KEY,
                    asset_key  VARCHAR(512) NOT NULL,
                    domain     VARCHAR(512),
                    ip         VARCHAR(64),
                    source_json            TEXT         NOT NULL,
                    discovery_json         LONGTEXT,
                    dashboard_summary_json TEXT         NOT NULL,
                    ingested_at            DATETIME     NOT NULL,
                    created_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                                ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_asset_key (asset_key)
                ) CHARACTER SET utf8mb4
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS service_scans (
                    scan_id   INT AUTO_INCREMENT PRIMARY KEY,
                    asset_id  INT          NOT NULL,
                    ip        VARCHAR(64)  NOT NULL,
                    port      INT          NOT NULL,
                    service   VARCHAR(128),
                    product   VARCHAR(256),
                    version   VARCHAR(128),
                    os        VARCHAR(256),
                    http_info_json TEXT    NOT NULL,
                    scanned_at     DATETIME,
                    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_scans_asset  (asset_id),
                    INDEX idx_scans_ip_port (ip, port),
                    CONSTRAINT fk_scans_asset
                        FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                ) CHARACTER SET utf8mb4
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id   INT AUTO_INCREMENT PRIMARY KEY,
                    asset_id  INT          NOT NULL,
                    ip        VARCHAR(64)  NOT NULL,
                    port      INT          NOT NULL,
                    service   VARCHAR(128),
                    name      VARCHAR(512) NOT NULL,
                    severity  VARCHAR(32)  NOT NULL,
                    cve_ids_json        TEXT    NOT NULL,
                    cvss_score          DOUBLE,
                    cvss_severity       VARCHAR(32),
                    epss                DOUBLE,
                    source              VARCHAR(128) NOT NULL,
                    module              VARCHAR(256),
                    matched_url         TEXT,
                    exploit_result_json TEXT,
                    no_vuln_found       TINYINT(1) NOT NULL DEFAULT 0,
                    created_at          DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_vulns_asset    (asset_id),
                    INDEX idx_vulns_severity (severity),
                    CONSTRAINT fk_vulns_asset
                        FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                ) CHARACTER SET utf8mb4
            """))

    def save_unified_records(self, records: Iterable[UnifiedAssetRecord]) -> int:
        """Upsert assets and replace their child rows. Returns affected asset count."""
        count = 0
        with self._engine.begin() as conn:
            for record in records:
                asset_id = self._upsert_asset(conn, record)
                self._replace_scans(conn, asset_id, record)
                self._replace_vulnerabilities(conn, asset_id, record)
                count += 1
        return count

    def _upsert_asset(self, conn, record: UnifiedAssetRecord) -> int:
        conn.execute(
            text("""
                INSERT INTO assets
                    (asset_key, domain, ip, source_json, discovery_json,
                     dashboard_summary_json, ingested_at)
                VALUES
                    (:asset_key, :domain, :ip, :source_json, :discovery_json,
                     :dashboard_summary_json, :ingested_at)
                ON DUPLICATE KEY UPDATE
                    domain                 = VALUES(domain),
                    ip                     = VALUES(ip),
                    source_json            = VALUES(source_json),
                    discovery_json         = VALUES(discovery_json),
                    dashboard_summary_json = VALUES(dashboard_summary_json),
                    ingested_at            = VALUES(ingested_at)
            """),
            {
                "asset_key": record.asset_key,
                "domain": record.domain,
                "ip": record.ip,
                "source_json": json.dumps(record.source, ensure_ascii=False),
                "discovery_json": json.dumps(
                    record.discovery.model_dump(mode="json") if record.discovery else None,
                    ensure_ascii=False,
                ),
                "dashboard_summary_json": json.dumps(
                    record.dashboard_summary.model_dump(mode="json"), ensure_ascii=False
                ),
                "ingested_at": _to_iso(record.ingested_at),
            },
        )
        row = conn.execute(
            text("SELECT asset_id FROM assets WHERE asset_key = :key"),
            {"key": record.asset_key},
        ).fetchone()
        if row is None:
            raise RuntimeError(f"Failed to persist asset: {record.asset_key}")
        return int(row[0])

    def _replace_scans(self, conn, asset_id: int, record: UnifiedAssetRecord) -> None:
        conn.execute(
            text("DELETE FROM service_scans WHERE asset_id = :id"),
            {"id": asset_id},
        )
        for scan in record.scans:
            conn.execute(
                text("""
                    INSERT INTO service_scans
                        (asset_id, ip, port, service, product, version, os,
                         http_info_json, scanned_at)
                    VALUES
                        (:asset_id, :ip, :port, :service, :product, :version, :os,
                         :http_info_json, :scanned_at)
                """),
                {
                    "asset_id": asset_id,
                    "ip": scan.ip,
                    "port": scan.port,
                    "service": scan.service,
                    "product": scan.product,
                    "version": scan.version,
                    "os": scan.os,
                    "http_info_json": json.dumps(
                        scan.http_info.model_dump(mode="json"), ensure_ascii=False
                    ),
                    "scanned_at": _to_iso(scan.scanned_at),
                },
            )

    def _replace_vulnerabilities(self, conn, asset_id: int, record: UnifiedAssetRecord) -> None:
        conn.execute(
            text("DELETE FROM vulnerabilities WHERE asset_id = :id"),
            {"id": asset_id},
        )
        for vuln in record.vulnerabilities:
            conn.execute(
                text("""
                    INSERT INTO vulnerabilities
                        (asset_id, ip, port, service, name, severity, cve_ids_json,
                         cvss_score, cvss_severity, epss, source, module, matched_url,
                         exploit_result_json, no_vuln_found)
                    VALUES
                        (:asset_id, :ip, :port, :service, :name, :severity, :cve_ids_json,
                         :cvss_score, :cvss_severity, :epss, :source, :module, :matched_url,
                         :exploit_result_json, :no_vuln_found)
                """),
                {
                    "asset_id": asset_id,
                    "ip": vuln.ip,
                    "port": vuln.port,
                    "service": vuln.service,
                    "name": vuln.name,
                    "severity": vuln.severity,
                    "cve_ids_json": json.dumps(vuln.cve_ids, ensure_ascii=False),
                    "cvss_score": vuln.cvss_score,
                    "cvss_severity": vuln.cvss_severity,
                    "epss": vuln.epss,
                    "source": vuln.source,
                    "module": vuln.module,
                    "matched_url": vuln.matched_url,
                    "exploit_result_json": json.dumps(
                        vuln.exploit_result, ensure_ascii=False
                    ),
                    "no_vuln_found": 1 if vuln.no_vuln_found else 0,
                },
            )


# backward-compat alias
SQLitePipelineRepository = MySQLPipelineRepository

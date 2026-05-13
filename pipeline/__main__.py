"""Pipeline entry point: 전체 recon 파이프라인 실행 및 DB 저장.

사용법:
    python -m pipeline <seed_domain> [--msf-password <pw>]

예시:
    python -m pipeline example.com
    python -m pipeline example.com --msf-password mypassword
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import os

# httpcore/httpx 연결 노이즈 로그 억제 (Connection reset 등 verbose 메시지)
logging.getLogger("httpcore").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)

# vuln_scanner 내부 bare import (nuclei_scanner, msf_scanner, cve_enricher) 해결
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vuln_scanner"))

from dotenv import load_dotenv
load_dotenv()

from asset_discovery.core import discover_assets
from scanner.scanner_main import ScanningEngine
import vuln_scanner as vuln_module

from pipeline.mapper import build_unified_records
from pipeline.repository import MySQLPipelineRepository


def _step(msg: str) -> None:
    print(f"\n{'='*60}\n[PIPELINE] {msg}\n{'='*60}")


async def run_pipeline(seed_domain: str, msf_password: str) -> None:
    repo = MySQLPipelineRepository()
    repo.init_schema()

    # ── Step 1. Asset Discovery ──────────────────────────────────
    _step(f"Step 1 / 3 — Asset Discovery: {seed_domain}")
    try:
        assets = await discover_assets(seed_domain)
    except Exception as e:
        print(f"[!] Asset Discovery 실패: {e}")
        return
    alive = [a for a in assets if a.is_alive]

    # ── 서브도메인 수집 결과 출력 ────────────────────────────────
    print(f"\n  {'도메인':<40} {'IP':<18} {'출처':<24} {'alive'}")
    print(f"  {'-'*40} {'-'*18} {'-'*24} {'-'*5}")
    for a in assets:
        sources = ", ".join(a.discovered_via) if a.discovered_via else "-"
        ip      = a.ip or "-"
        status  = "✓" if a.is_alive else "✗"
        print(f"  {a.domain:<40} {ip:<18} {sources:<24} {status}")

    print(f"\n  총 {len(assets)}개 발견  /  alive {len(alive)}개")

    # alive 판정이 없어도 IP가 있으면 스캔 진행 (HTTP 없는 서비스도 스캔 가능)
    scan_targets = alive if alive else [a for a in assets if a.ip]
    if not scan_targets:
        print("[!] IP를 가진 자산이 없습니다. 파이프라인 종료.")
        return
    if not alive:
        print(f"  [!] HTTP alive 응답 없음 → IP 보유 자산 {len(scan_targets)}개로 스캔 계속 진행")

    ips = list({a.ip for a in scan_targets if a.ip})

    # ── Step 2. Port / Service Scan ──────────────────────────────
    _step(f"Step 2 / 3 — Port Scan ({len(ips)}개 IP)")
    engine = ScanningEngine()
    scan_results = engine.run_scan(ips)
    print(f"  스캔된 포트: {len(scan_results)}개")
    ports = [s['port'] for s in scan_results]
    print(ports)

    if not scan_results:
        print("[!] 열린 포트가 없습니다. 취약점 스캔 생략.")
        vuln_results = []
    else:
        # ── Step 3. Vulnerability Scan ───────────────────────────
        _step(f"Step 3 / 3 — Vulnerability Scan ({len(scan_results)}개 포트)")
        try:
            vuln_results = vuln_module.scan(scan_results, msf_password=msf_password)
        except FileNotFoundError as e:
            print(f"  [!] 외부 도구 미설치로 취약점 스캔 실패: {e.filename}")
            print("      → nuclei: brew install nuclei")
            print("      → metasploit: https://docs.metasploit.com/")
            vuln_results = []
        except Exception as e:
            print(f"  [!] 취약점 스캔 중 오류 발생: {e}")
            vuln_results = []
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in vuln_results)
        print(f"  발견된 취약점: {total_vulns}개")

    # ── 통합 + DB 저장 ────────────────────────────────────────────
    _step("DB 저장")
    records = build_unified_records(
        discovery_results=assets,       # mapper.py에서 model_dump 자동 처리
        scanner_results=scan_results,
        vulnerability_results=vuln_results,
    )
    saved = repo.save_unified_records(records)
    print(f"  저장 완료: {saved}개 자산 → Railway MySQL")


def main() -> None:
    parser = argparse.ArgumentParser(description="Recon Core Pipeline")
    parser.add_argument("domain", help="스캔할 시드 도메인 (예: example.com)")
    parser.add_argument(
        "--msf-password",
        default="password",
        help="Metasploit RPC 비밀번호 (기본값: password)",
    )
    args = parser.parse_args()

    asyncio.run(run_pipeline(args.domain, args.msf_password))


if __name__ == "__main__":
    main()

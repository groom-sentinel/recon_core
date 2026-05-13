"""CLI entry point: python -m asset_discovery.cli example.com"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from asset_discovery.core import discover_assets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asset-discovery",
        description="Asset Discovery & Mapping (Role 3)",
    )
    parser.add_argument("domain", help="시드 도메인 (예: example.com)")
    parser.add_argument(
        "--no-subfinder", dest="use_subfinder",
        action="store_false", default=True,
        help="subfinder 비활성화 (네트워크 느릴 때 유용)",
    )
    parser.add_argument(
        "--no-crt-sh", dest="use_crt_sh",
        action="store_false", default=True,
        help="crt.sh API 비활성화",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과를 JSON 파일로 저장 (생략 시 stdout)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # === argparse Namespace 경계: Any → 구체 타입 좁힘 ===
    domain: str = str(args.domain)
    use_subfinder: bool = bool(args.use_subfinder)
    use_crt_sh: bool = bool(args.use_crt_sh)
    output_arg: object = args.output
    output_path: str | None = (
        str(output_arg) if isinstance(output_arg, str) else None
    )

    if not domain.strip():
        print("Error: empty domain", file=sys.stderr)
        return 2

    print(f"[*] Discovering assets for {domain}...", file=sys.stderr)
    if use_subfinder:
        print("[*] Using subfinder (may take 30-60s)", file=sys.stderr)
    if use_crt_sh:
        print("[*] Using crt.sh API", file=sys.stderr)

    assets = asyncio.run(
        discover_assets(
            domain,
            use_subfinder=use_subfinder,
            use_crt_sh=use_crt_sh,
        )
    )

    alive_count = sum(1 for a in assets if a.is_alive)
    print(
        f"[+] Found {len(assets)} assets ({alive_count} alive)",
        file=sys.stderr,
    )

    # Pydantic 모델 → JSON 직렬화
    payload: list[dict[str, object]] = [
        a.model_dump(mode="json") for a in assets
    ]
    json_str: str = json.dumps(
        payload, ensure_ascii=False, indent=2, default=str,
    )

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
        print(f"[+] Saved to {output_path}", file=sys.stderr)
    else:
        print(json_str)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

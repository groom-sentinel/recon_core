# Asset Discovery Module

> **담당자 3 (Role 3)** — 자산 발견 + DNS/WHOIS/ASN 메타데이터 수집

## 역할

도메인 1개를 받아서 → 해당 회사의 외부 노출 자산을 모두 발견하고, 각 자산에 대해 메타데이터를 채워서 표준 객체로 출력합니다.

```
[입력]  시드 도메인 (예: example.com)
   ↓
[1] subfinder + crt.sh → 서브도메인 수집
[2] 살아있는지 HTTP HEAD 체크
[3] DNS 레코드 조회 (A, MX, NS, SPF, DMARC)
[4] WHOIS 조회 (Org, 국가, 등록일)
[5] ASN 조회 + 클라우드 제공자 식별 (AWS/GCP/Azure)
   ↓
[출력] list[DiscoveredAsset] — Role 4 (Pipeline) 이 소비
```

## 책임 경계

| ✅ 이 모듈이 함 | ❌ 이 모듈이 안 함 |
|--------------|----------------|
| 사실 수집 (DNS/WHOIS/ASN raw data) | 자산 이름 추정 → Role 4 |
| 서브도메인 발견 | 위험도 계산 → Role 4 |
| 살아있는지 확인 | 자산 카드 생성 → Role 4 |
| | 포트 스캔 → Role 1 |
| | CVE 매칭 → Role 2 |

## 사용법

```bash
# 환경 셋업
cd recon_core
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r asset_discovery/requirements.txt
brew install subfinder  # macOS

# 실행
python -m asset_discovery.cli example.com

# JSON 파일로 저장
python -m asset_discovery.cli example.com -o assets.json
```

## 모듈 구성

| 파일 | 책임 |
|------|------|
| `models.py` | Pydantic 데이터 모델 (`DiscoveredAsset` 등) |
| `subfinder.py` | subfinder Go binary wrapper |
| `crt_sh.py` | crt.sh API 클라이언트 (인증서 로그 기반) |
| `dns_lookup.py` | DNS 레코드 종합 조회 (dnspython) |
| `whois_lookup.py` | WHOIS 조회 (python-whois) |
| `asn_lookup.py` | ASN/클라우드 식별 (ipwhois) |
| `alive_check.py` | HTTP HEAD 프로브 |
| `core.py` | async 통합 디스패처 |
| `cli.py` | argparse 진입점 |

## 코드 품질 기준

- **`typing.Any` 금지** — 모든 변수 구체 타입
- **`mypy --strict`** — 0 error 유지
- **외부 라이브러리 경계** (whois, ipwhois) — 즉시 타입 좁힘
- **Python 3.11+ 문법** — `X | None`, `list[int]`, `UTC` from datetime

## 출력 예시

```json
{
  "domain": "api.example.com",
  "ip": "93.184.216.34",
  "discovered_via": ["subfinder", "crt.sh"],
  "is_alive": true,
  "dns": {
    "a": ["93.184.216.34"],
    "mx": ["mail.example.com"],
    "has_spf": true,
    "has_dmarc": false
  },
  "whois": {
    "org": "Example Corporation",
    "country": "US",
    "creation_date": "1995-08-14T04:00:00Z"
  },
  "asn_info": {
    "asn": "AS15133",
    "asn_org": "EDGECAST",
    "country": "US",
    "cloud_provider": null
  },
  "first_seen": "2026-05-11T...",
  "last_checked": "2026-05-11T..."
}
```

## TODO

- [x] models.py + subfinder.py (Day 1)
- [ ] crt_sh.py + dns_lookup.py (Day 2)
- [ ] whois_lookup.py + asn_lookup.py + alive_check.py (Day 3)
- [ ] core.py + cli.py (Day 4)
- [ ] PR to develop (Day 5)

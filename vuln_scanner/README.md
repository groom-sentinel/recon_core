# vuln_scanner

포트 스캔 결과를 받아 취약점 스캔 및 CVE 매핑을 수행하는 모듈입니다.

## 파일 구조

```
vuln_scanner/
├── vuln_scanner.py     # 메인 진입점, 분기 로직
├── nuclei_scanner.py   # nuclei 연동 (웹 취약점)
├── msf_scanner.py      # Metasploit 연동 (서비스 취약점)
└── cve_enricher.py     # NVD/EPSS 기반 CVE 정보 조회
```

## 의존성 설치

### nuclei
```bash
brew install nuclei
nuclei -update-templates
```

### Metasploit
공식 설치 스크립트로 설치:
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

초기화 (최초 1회):
```bash
/opt/metasploit-framework/bin/msfconsole
```

### Python 패키지
```bash
pip install pymetasploit3 requests
```

## 사전 준비

### NVD API Key
NVD API는 API Key 없이 사용 시 rate limit이 있습니다. 무료 발급 후 `cve_enricher.py`의 `NVD_API_KEY`에 설정하세요:
- 발급: https://nvd.nist.gov/developers/request-an-api-key

### Metasploit RPC 서버 실행
vuln_scanner 실행 전에 Metasploit RPC 서버를 먼저 띄워야 합니다:
```bash
/opt/metasploit-framework/bin/msfrpcd -P <password> -p 55553
```

> `msf_scanner.connect(password="<password>")`와 동일한 패스워드를 사용해야 합니다.

## 사용법

포트 스캔 결과(JSON 리스트)를 `scan()`에 넘기면 됩니다:

```python
import vuln_scanner

port_scan_result = [
    {
        "ip": "127.0.0.1",
        "port": 80,
        "service": "http",
        "version": "Apache httpd 2.4.49",
        "http_info": {
            "status_code": 200
        }
    }
]

results = vuln_scanner.scan(port_scan_result, msf_password="password")
vuln_scanner.print_result(results)
```

## 스캔 로직

1. **NVD CPE/키워드 검색** - 서비스 버전 기반으로 해당 버전에 영향을 주는 CVE 목록 조회
2. **nuclei** - `http_info.status_code` 존재 시 조회된 CVE 태그로 필터링하여 웹 취약점 스캔
3. **Metasploit** - 웹 서비스가 아닌 경우 CVE별 익스플로잇 모듈을 찾아 `check()` 실행

## 출력 예시

```
[*] 127.0.0.1:80 (http) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (Apache httpd 2.4.49)
  -> 해당 버전 CVE 50개 발견: CVE-2021-41773, CVE-2021-42013...
  -> nuclei 스캔 중 (CVE 필터 적용)...

============================================================
스캔 결과
============================================================

[127.0.0.1:80] (http)
  검사한 CVE: 50개
  [nuclei] Apache HTTP Server 2.4.49 Path Traversal | 취약 (nuclei 탐지)
    CVE: CVE-2021-41773
    CVSS: 9.8 (CRITICAL) | EPSS: 0.97

[127.0.0.1:3306] (mysql)
  검사한 CVE: 30개
  [metasploit] MySQL yaSSL Buffer Overflow | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2009-4484
    CVSS: 7.5 (-) | EPSS: 0.758
```

## 취약 여부 판단 기준

| 상태 | 설명 |
|------|------|
| 취약 (nuclei 탐지) | nuclei가 실제 응답에서 취약점 확인 |
| 취약 | Metasploit `check()` 결과 vulnerable |
| 취약하지 않음 | Metasploit `check()` 결과 not-vulnerable |
| 잠재적 취약 가능성 있음 (수동 확인 필요) | Metasploit 모듈이 `check()` 미지원 |

## CVE 정보

- **CVSS**: NVD API (https://services.nvd.nist.gov) 조회
- **EPSS**: FIRST API (https://api.first.org) 조회 (0~1, 실제 악용 가능성)

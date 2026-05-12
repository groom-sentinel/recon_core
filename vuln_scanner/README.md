# vuln_scanner

포트 스캔 결과를 받아 취약점 스캔 및 CVE 매핑을 수행하는 모듈입니다.

## 파일 구조

```
vuln_scanner/
├── vuln_scanner.py     # 메인 진입점, 분기 로직
├── nuclei_scanner.py   # nuclei 연동 (웹 취약점)
├── msf_scanner.py      # Metasploit 연동 (서비스 취약점)
└── cve_enricher.py     # CVE ID → CVSS, EPSS 조회
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
pip install python-nmap pymetasploit3 requests
```

## 사전 준비

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
        "product": "Apache httpd",
        "version": "2.4.49",
        "http_info": {
            "status_code": 200
        }
    }
]

results = vuln_scanner.scan(port_scan_result, msf_password="password")
```

## 결과 구조

```json
[
    {
        "ip": "127.0.0.1",
        "port": 80,
        "service": "http",
        "vulnerabilities": [
            {
                "name": "Apache Path Traversal",
                "severity": "critical",
                "cve_id": ["CVE-2021-41773"],
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "epss": 0.97,
                "source": "nuclei"
            }
        ],
        "no_vuln_found": false
    }
]
```

## 스캔 로직

- `http_info.status_code` 존재 → nuclei로 웹 취약점 스캔
- `product` 또는 `version` 존재 → Metasploit으로 서비스 취약점 검색
- 두 조건 모두 해당하면 둘 다 실행 후 결과 합산
- 취약점 없으면 콘솔에 안내 메시지 출력

## CVE 정보

- **CVSS**: NVD API (https://services.nvd.nist.gov) 조회
- **EPSS**: FIRST API (https://api.first.org) 조회
- CVE 정보가 없으면 콘솔에 안내 메시지 출력

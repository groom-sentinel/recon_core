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
[*] 45.33.32.156:22 (ssh) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)
  -> 해당 버전 CVE 33개 발견: CVE-2007-2768, CVE-2008-3844, CVE-2015-5352, CVE-2015-5600, CVE-2015-6563...
  -> Metasploit check 중...

[*] 45.33.32.156:80 (http) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (Apache httpd 2.4.7)
  -> 해당 버전 CVE 50개 발견: CVE-2007-4723, CVE-2009-0796, CVE-2009-2299, CVE-2011-1176, CVE-2011-2688...
  -> nuclei 스캔 중 (CVE 필터 적용)...

[*] 45.33.32.156:9929 (nping-echo) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (Nping echo)
  -> 해당 버전 CVE 0개 발견: 
  -> Metasploit check 중...

[*] 45.33.32.156:31337 (tcpwrapped) 스캔 시작...
  -> 버전 기반 CVE 조회 중... ()
  -> 해당 버전 CVE 0개 발견: 
  -> Metasploit check 중...

[*] 127.0.0.1:80 (http) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (Apache httpd)
  -> 해당 버전 CVE 50개 발견: CVE-1999-0236, CVE-1999-0071, CVE-2000-1206, CVE-2002-1850, CVE-2003-0249...
  -> nuclei 스캔 중 (CVE 필터 적용)...

[*] 127.0.0.1:135 (msrpc) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (Microsoft Windows RPC)
  -> 해당 버전 CVE 37개 발견: CVE-2000-0771, CVE-2001-0509, CVE-2002-1140, CVE-2002-1141, CVE-2003-0003...
  -> Metasploit check 중...

[*] 127.0.0.1:445 (microsoft-ds) 스캔 시작...
  -> 버전 기반 CVE 조회 중... ()
  -> 해당 버전 CVE 0개 발견: 
  -> Metasploit check 중...

[*] 127.0.0.1:843 () 스캔 시작...
  -> 버전 기반 CVE 조회 중... ()
  -> 해당 버전 CVE 0개 발견: 
  -> Metasploit check 중...

[*] 127.0.0.1:3306 (mysql) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (MySQL 5.1.41-community)
  -> 해당 버전 CVE 50개 발견: CVE-2009-4484, CVE-2010-1626, CVE-2010-1848, CVE-2010-1849, CVE-2010-1850...
  -> Metasploit check 중...

[*] 8.8.8.8:53 (tcpwrapped) 스캔 시작...
  -> 버전 기반 CVE 조회 중... ()
  -> 해당 버전 CVE 0개 발견: 
  -> Metasploit check 중...

[*] 8.8.8.8:443 (https) 스캔 시작...
  -> 버전 기반 CVE 조회 중... (HTTP server (unknown))
  -> 해당 버전 CVE 0개 발견: 
  -> nuclei 스캔 중 (CVE 필터 적용)...

============================================================
스캔 결과
============================================================

[45.33.32.156:22] (ssh)
  검사한 CVE: 33개
  결과: 익스플로잇 없음 또는 취약하지 않음

[45.33.32.156:80] (http)
  검사한 CVE: 50개
  결과: 익스플로잇 없음 또는 취약하지 않음

[45.33.32.156:9929] (nping-echo)
  검사한 CVE: 0개
  결과: 익스플로잇 없음 또는 취약하지 않음

[45.33.32.156:31337] (tcpwrapped)
  검사한 CVE: 0개
  결과: 익스플로잇 없음 또는 취약하지 않음

[127.0.0.1:80] (http)
  검사한 CVE: 50개
  결과: 익스플로잇 없음 또는 취약하지 않음

[127.0.0.1:135] (msrpc)
  검사한 CVE: 37개
  [metasploit] MS03-026 Microsoft RPC DCOM Interface Overflow | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2003-0352
    CVSS: 7.5 (-) | EPSS: 0.90567
  [metasploit] MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2006-3439
    CVSS: 10.0 (-) | EPSS: 0.88959
  [metasploit] MS06-070 Microsoft Workstation Service NetpManageIPCConnect Overflow | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2006-4691
    CVSS: 10.0 (-) | EPSS: 0.8886
  [metasploit] MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (TCP) | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2007-1748
    CVSS: 10.0 (-) | EPSS: 0.83975
  [metasploit] MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB) | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2007-1748
    CVSS: 10.0 (-) | EPSS: 0.83975
  [metasploit] MS07-065 Microsoft Message Queueing Service DNS Name Path Overflow | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2007-3039
    CVSS: 9.0 (-) | EPSS: 0.8339
  [metasploit] MS08-067 Microsoft Server Service Relative Path Stack Corruption | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2008-4250
    CVSS: 10.0 (-) | EPSS: 0.93482
  [metasploit] MS10-061 Microsoft Print Spooler Service Impersonation Vulnerability | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2010-2729
    CVSS: 9.3 (-) | EPSS: 0.84698

[127.0.0.1:445] (microsoft-ds)
  검사한 CVE: 0개
  결과: 익스플로잇 없음 또는 취약하지 않음

[127.0.0.1:843] ()
  검사한 CVE: 0개
  결과: 익스플로잇 없음 또는 취약하지 않음

[127.0.0.1:3306] (mysql)
  검사한 CVE: 50개
  [metasploit] MySQL yaSSL CertDecoder::GetName Buffer Overflow | 잠재적 취약 가능성 있음 (수동 확인 필요)
    CVE: CVE-2009-4484
    CVSS: 7.5 (-) | EPSS: 0.75816

[8.8.8.8:53] (tcpwrapped)
  검사한 CVE: 0개
  결과: 익스플로잇 없음 또는 취약하지 않음

[8.8.8.8:443] (https)
  검사한 CVE: 0개
  결과: 익스플로잇 없음 또는 취약하지 않음
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

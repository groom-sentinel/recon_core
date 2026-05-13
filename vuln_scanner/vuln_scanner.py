import nuclei_scanner
import msf_scanner
import cve_enricher


def scan(port_scan_result, msf_password="password"):
    msf_scanner.connect(password=msf_password)

    results = []
    for entry in port_scan_result:
        ip = entry["ip"]
        port = entry["port"]
        service = entry.get("service", "")
        product = entry.get("product", "")
        version = entry.get("version", "")
        http_info = entry.get("http_info", {})

        print(f"\n[*] {ip}:{port} ({service}) 스캔 시작...")

        # 1. NVD에서 해당 버전의 CVE 목록 조회
        print(f"  -> 버전 기반 CVE 조회 중... ({product or version})")
        cve_ids = cve_enricher.get_cves_by_version(product, version)
        print(f"  -> 해당 버전 CVE {len(cve_ids)}개 발견: {', '.join(cve_ids[:5])}{'...' if len(cve_ids) > 5 else ''}")

        vulnerabilities = []

        # 2. 웹서비스면 nuclei로 CVE 기반 스캔
        if http_info.get("status_code"):
            print(f"  -> nuclei 스캔 중 (CVE 필터 적용)...")
            vulnerabilities += nuclei_scanner.scan(ip, port, cve_ids)
        else:
            # 3. 웹 아닌 경우 Metasploit으로 CVE별 익스플로잇 check
            print(f"  -> Metasploit check 중...")
            vulnerabilities += msf_scanner.scan(ip, port, cve_ids)

        # 4. CVSS, EPSS 조회
        all_cve_ids = list(set(cve_id for v in vulnerabilities for cve_id in v.get("cve_id", [])))
        cve_info = {c["cve_id"]: c for c in cve_enricher.enrich(all_cve_ids)}

        for v in vulnerabilities:
            for cve_id in v.get("cve_id", []):
                if cve_id in cve_info:
                    v["cvss_score"] = cve_info[cve_id]["cvss_score"]
                    v["cvss_severity"] = cve_info[cve_id]["cvss_severity"]
                    v["epss"] = cve_info[cve_id]["epss"]

        results.append({
            "ip": ip,
            "port": port,
            "service": service,
            "scanned_cves": cve_ids,
            "vulnerabilities": vulnerabilities,
            "no_vuln_found": len(vulnerabilities) == 0
        })

    return results


def print_result(results):
    print("\n" + "=" * 60)
    print("스캔 결과")
    print("=" * 60)
    for r in results:
        print(f"\n[{r['ip']}:{r['port']}] ({r['service']})")
        print(f"  검사한 CVE: {len(r['scanned_cves'])}개")

        if r["no_vuln_found"]:
            print(f"  결과: 익스플로잇 없음 또는 취약하지 않음")
        else:
            for v in r["vulnerabilities"]:
                cve_list = ", ".join(v.get("cve_id", [])) or "CVE 없음"
                cvss = v.get("cvss_score", "-")
                severity = v.get("cvss_severity", "-")
                epss = v.get("epss", "-")
                if v.get("source") == "metasploit":
                    if v.get("vulnerable") is True:
                        status = "취약"
                    elif v.get("vulnerable") is False:
                        status = "취약하지 않음"
                    else:
                        status = "잠재적 취약 가능성 있음 (수동 확인 필요)"
                else:
                    status = "취약 (nuclei 탐지)"
                print(f"  [{v['source']}] {v['name']} | {status}")
                print(f"    CVE: {cve_list}")
                print(f"    CVSS: {cvss} ({severity}) | EPSS: {epss}")


if __name__ == "__main__":
    import json
    with open('../scanner/scan_result.json', 'r') as f:
        data = json.load(f)
    results = scan(data)
    print_result(results)

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

        vulnerabilities = []
        
        #http status code가 존재하면 웹서비스로 판단하고 nuclei 취약점스캔 실행
        if http_info.get("status_code"):
            vulnerabilities += nuclei_scanner.scan(ip, port)

        if product or version:
            vulnerabilities += msf_scanner.scan(ip, port, product, version)

        # CVE ID 모아서 CVSS, EPSS 조회 후 취약점에 추가
        cve_ids = []
        for v in vulnerabilities:
            cve_ids += v.get("cve_id", [])

        cve_info = {c["cve_id"]: c for c in cve_enricher.enrich(cve_ids)}

        for v in vulnerabilities:
            for cve_id in v.get("cve_id", []):
                if cve_id in cve_info:
                    v["cvss_score"] = cve_info[cve_id]["cvss_score"]
                    v["cvss_severity"] = cve_info[cve_id]["cvss_severity"]
                    v["epss"] = cve_info[cve_id]["epss"]

        if not vulnerabilities:
            print(f"[{ip}:{port}] ({service}) 취약점 없음 또는 식별 불가")

        results.append({
            "ip": ip,
            "port": port,
            "service": service,
            "vulnerabilities": vulnerabilities,
            "no_vuln_found": len(vulnerabilities) == 0
        })

    return results

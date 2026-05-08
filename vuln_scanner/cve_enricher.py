import requests
import time


def get_cvss(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        res = requests.get(url, timeout=10).json()
        vuln = res["vulnerabilities"][0]["cve"]
        metrics = vuln.get("metrics", {})

        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            data = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            data = metrics["cvssMetricV2"][0]["cvssData"]
        else:
            return None

        return {
            "score": data["baseScore"],
            "severity": data["baseSeverity"]
        }
    except Exception:
        return None


def get_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        res = requests.get(url, timeout=10).json()
        if res["data"]:
            return float(res["data"][0]["epss"])
        return None
    except Exception:
        return None


def enrich(cve_ids):
    enriched = []
    for cve_id in cve_ids:
        time.sleep(0.6)  # NVD rate limit
        cvss = get_cvss(cve_id)
        epss = get_epss(cve_id)

        if cvss is None and epss is None:
            print(f"[{cve_id}] CVE 정보 없음")
            continue

        enriched.append({
            "cve_id": cve_id,
            "cvss_score": cvss["score"] if cvss else None,
            "cvss_severity": cvss["severity"] if cvss else None,
            "epss": epss
        })

    return enriched

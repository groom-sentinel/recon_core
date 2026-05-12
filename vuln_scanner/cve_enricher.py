import re
import requests
from concurrent.futures import ThreadPoolExecutor

NVD_API_KEY = "89781ccf-2845-41b5-ac3c-4fc6cdbc86cd"
NVD_HEADERS = {"apiKey": NVD_API_KEY}

CPE_MAP = {
    "apache": "apache:http_server",
    "httpd": "apache:http_server",
    "nginx": "nginx:nginx",
    "mysql": "oracle:mysql",
    "openssh": "openbsd:openssh",
    "mongoose": "cesanta:mongoose",
    "microsoft": "microsoft:windows",
    "iis": "microsoft:iis",
    "tomcat": "apache:tomcat",
    "openssl": "openssl:openssl",
}


def extract_version(version_str):
    match = re.search(r'(\d+\.\d+[\.\d]*)', version_str)
    return match.group(1) if match else None


def build_cpe(product, version_str):
    keyword = product.lower().split()[0] if product else version_str.lower().split()[0] if version_str else ""
    cpe_product = CPE_MAP.get(keyword)
    if not cpe_product:
        return None
    version = extract_version(version_str)
    if not version:
        return None
    return f"cpe:2.3:a:{cpe_product}:{version}:*:*:*:*:*:*:*"


def get_cves_by_version(product, version):
    cpe = build_cpe(product, version)
    if cpe:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}&resultsPerPage=50"
    else:
        keyword = f"{product} {version}".strip()
        if not keyword:
            return []
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=50"

    try:
        res = requests.get(url, headers=NVD_HEADERS, timeout=10).json()
        return [v["cve"]["id"] for v in res.get("vulnerabilities", [])]
    except Exception:
        return []


def get_cvss(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        res = requests.get(url, headers=NVD_HEADERS, timeout=10).json()
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
            "severity": data.get("baseSeverity", "-")
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


def enrich_one(cve_id):
    cvss = get_cvss(cve_id)
    epss = get_epss(cve_id)
    return {
        "cve_id": cve_id,
        "cvss_score": cvss["score"] if cvss else None,
        "cvss_severity": cvss["severity"] if cvss else None,
        "epss": epss
    }


def enrich(cve_ids):
    if not cve_ids:
        return []
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(enrich_one, cve_ids))
    return [r for r in results if r is not None]

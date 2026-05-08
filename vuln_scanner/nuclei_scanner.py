import subprocess
import json


def scan(ip, port):
    url = f"http://{ip}:{port}"
    cmd = ["nuclei", "-u", url, "-json", "-silent"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    vulnerabilities = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        data = json.loads(line)
        vulnerabilities.append({
            "name": data["info"]["name"],
            "severity": data["info"]["severity"],
            "cve_id": data["info"].get("classification", {}).get("cve-id", []),
            "matched_url": data["matched-at"],
            "source": "nuclei"
        })

    return vulnerabilities

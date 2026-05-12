import subprocess
import json


def scan(ip, port, cve_ids=None):
    url = f"http://{ip}:{port}"
    cmd = ["nuclei", "-u", url, "-json", "-silent", "-timeout", "3", "-c", "10"]

    if cve_ids:
        tags = ",".join(c.lower() for c in cve_ids)
        cmd += ["-tags", tags]

    result = subprocess.run(cmd, capture_output=True, text=True)

    vulnerabilities = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        vulnerabilities.append({
            "name": data["info"]["name"],
            "severity": data["info"]["severity"],
            "cve_id": data["info"].get("classification", {}).get("cve-id", []),
            "matched_url": data["matched-at"],
            "source": "nuclei"
        })

    return vulnerabilities

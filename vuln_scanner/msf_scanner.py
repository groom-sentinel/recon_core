from concurrent.futures import ThreadPoolExecutor
from pymetasploit3.msfrpc import MsfRpcClient

client = None


def connect(password="password", host="127.0.0.1", port=55553):
    global client
    try:
        client = MsfRpcClient(password, server=host, port=port)
    except Exception:
        print("[!] Metasploit RPC 연결 실패. msf 스캔을 건너뜁니다.")
        client = None


def find_modules_by_cve(cve_id):
    if client is None:
        return []
    results = client.modules.search(cve_id)
    return [r for r in results if r["type"] == "exploit"]


def check_exploit(ip, port, module_name, cve_id):
    try:
        exploit = client.modules.use("exploit", module_name)
        exploit["RHOSTS"] = ip
        exploit["RPORT"] = port

        try:
            result = exploit.check()
            vulnerable = result == "vulnerable"
        except Exception:
            vulnerable = None

        return {
            "name": exploit.info.get("name", module_name),
            "module": module_name,
            "cve_id": [cve_id],
            "vulnerable": vulnerable,
            "source": "metasploit"
        }
    except Exception:
        return None


def scan(ip, port, cve_ids):
    if client is None or not cve_ids:
        return []

    tasks = []
    for cve_id in cve_ids:
        modules = find_modules_by_cve(cve_id)
        for m in modules:
            tasks.append((ip, port, m["fullname"], cve_id))

    def run(task):
        return check_exploit(*task)

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(run, tasks))

    return [r for r in results if r is not None]

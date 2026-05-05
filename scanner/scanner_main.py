import nmap
import requests
import json
from datetime import datetime

class ScanningEngine:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def run_scan(self, target):
        print(f"스캔 대상: {target} - 분석 중...")
        
        self.nm.scan(target, arguments='-sV -O -T4')
        
        results = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    state = self.nm[host][proto][port]['state']
                    if state == 'open':
                        item = self.parse_result(host, proto, port)
                        results.append(item)
        
        return results

    def parse_result(self, host, proto, port):
        port_info = self.nm[host][proto][port]
        
        data = {
            "ip": host,
            "port": port,
            "service": port_info['name'],
            "version": f"{port_info['product']} {port_info['version']}".strip(),
            "os": self.nm[host].get('osmatch', [{}])[0].get('name', 'Unknown'),
            "http_info": {},
            "scanned_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        if port in [80, 443, 8080]:
            data["http_info"] = self.extract_http_headers(host, port)
            
        return data

    def extract_http_headers(self, host, port):
        url = f"{'https' if port == 443 else 'http'}://{host}:{port}"
        try:
            resp = requests.get(url, timeout=3, verify=False)
            return {
                "server": resp.headers.get("Server"),
                "x_powered_by": resp.headers.get("X-Powered-By"),
                "status_code": resp.status_code
            }
        except:
            return {"error": "Connection Timeout"}

if __name__ == "__main__":
    engine = ScanningEngine()
    scan_data = engine.run_scan('127.0.0.1')
    
    with open('scan_result.json', 'w', encoding='utf-8') as f:
        json.dump(scan_data, f, indent=4, ensure_ascii=False)
    
    print("스캔 완료: 결과가 scan_result.json에 저장되었습니다.")
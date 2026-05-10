import nmap
import requests
import json
import os
from datetime import datetime

class ScanningEngine:
    def __init__(self):
        # Nmap 엔진 초기화
        self.nm = nmap.PortScanner()

    def load_targets(self, file_path='targets.txt'):
        if not os.path.exists(file_path):
            print(f"[!] {file_path} 파일이 없습니다. 127.0.0.1로 기본 스캔을 진행합니다.")
            return ['127.0.0.1']
        
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
            return targets

    def run_scan(self, targets):
        all_results = []
        total = len(targets)
        
        print(f"[*] 총 {total}개의 타겟에 대해 스캔을 시작합니다.")

        for idx, target in enumerate(targets, 1):
            print(f"[{idx}/{total}] 현재 스캔 중: {target}...")
            
            try:
                # -sV: 서비스 버전 탐지
                # --version-intensity 7: 탐지 정밀도 (0~9, 7이 적당함)
                # --open: 열려 있는 포트만 결과에 포함
                # --host-timeout 3m: 한 IP당 최대 3분까지만 대기 (무한 대기 방지)
                scan_args = '-sV --version-intensity 7 -O --open --host-timeout 3m -T4'
                
                self.nm.scan(target, arguments=scan_args)
                
                if target not in self.nm.all_hosts():
                    print(f" [!] {target} 응답이 없습니다. 다음 타겟으로 넘어갑니다.")
                    continue

                # 발견된 정보 파싱
                for proto in self.nm[target].all_protocols():
                    ports = self.nm[target][proto].keys()
                    for port in ports:
                        result = self.parse_info(target, proto, port)
                        all_results.append(result)

            except Exception as e:
                # 에러ㅜ예외 처리
                print(f" [!] {target} 에러 발생: {e}")
                continue
                
        return all_results

    def parse_info(self, host, proto, port):
        #JSON 구조
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

        # 웹 서비스인 경우 추가 정보 
        if port in [80, 443, 8080]:
            data["http_info"] = self.get_web_details(host, port)
            
        return data

    def get_web_details(self, host, port):
        url = f"{'https' if port == 443 else 'http'}://{host}:{port}"
        try:
            resp = requests.get(url, timeout=3, verify=False)
            import re
            title = re.findall(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
            return {
                "server": resp.headers.get("Server"),
                "status_code": resp.status_code,
                "title": title[0] if title else "N/A"
            }
        except:
            return {"error": "Connection Failed"}

if __name__ == "__main__":
    engine = ScanningEngine()
    
    target_list = engine.load_targets()
    
    final_results = engine.run_scan(target_list)
    
    with open('scan_result.json', 'w', encoding='utf-8') as f:
        json.dump(final_results, f, indent=4, ensure_ascii=False)
    
    print(f"\n[+] 저장 완료 : scan_result.json")
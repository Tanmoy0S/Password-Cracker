import socket
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = {}

    def scan_ports(self):
        print(f"[*] Scanning {self.target} for open ports...")
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port in range(1, 1025):
                executor.submit(self.check_port, port)
        print(f"[*] Open ports: {self.open_ports}")

    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
                self.open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"[-] Error checking port {port}: {e}")

    def identify_services(self):
        print(f"[*] Identifying services on open ports...")
        for port in self.open_ports:
            service = self.get_service_name(port)
            self.services[port] = service
        print(f"[*] Services: {self.services}")

    def get_service_name(self, port):
        try:
            service = socket.getservbyport(port)
        except:
            service = "unknown"
        return service

    def check_vulnerabilities(self):
        print(f"[*] Checking for vulnerabilities...")
        # This is a simple placeholder for vulnerability data
        vulnerability_db = {
            'http': ['CVE-2021-12345', 'CVE-2021-12346'],
            'ssh': ['CVE-2021-12347'],
        }
        for port, service in self.services.items():
            self.vulnerabilities[port] = vulnerability_db.get(service, [])
        print(f"[*] Vulnerabilities: {self.vulnerabilities}")

    def display_results(self):
        print("\nScan Results:")
        print(f"Target: {self.target}")
        print(f"Open Ports: {self.open_ports}")
        for port, service in self.services.items():
            print(f"Port {port}: {service}")
            if self.vulnerabilities[port]:
                print(f"  Vulnerabilities: {', '.join(self.vulnerabilities[port])}")
            else:
                print("  No known vulnerabilities found.")

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

if __name__ == "__main__":
    target = input("Enter the target IP address: ").strip()
    if not is_valid_ip(target):
        print("Invalid IP address.")
    else:
        scanner = VulnerabilityScanner(target)
        scanner.scan_ports()
        scanner.identify_services()
        scanner.check_vulnerabilities()
        scanner.display_results()

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import urllib.parse

class PortScanner:
    def __init__(self):
        self.timeout = 2
        self.max_workers = 50

    def scan(self, url):
        """Main port scanning method"""
        findings = []

        try:
            # Extract hostname from URL
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.netloc

            # Handle port specification in hostname
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            # Define ports to scan
            # Common ports that are interesting for web applications
            ports_to_scan = [
                # Web servers
                80, 443, 8080, 8443, 8000, 8001, 8008, 3000, 5000, 9000,
                # SSH/Remote access
                22, 2222,
                # FTP
                20, 21,
                # Email
                25, 110, 143, 993, 995,
                # DNS
                53,
                # Database
                1433, 1521, 3306, 5432, 6379, 27017,
                # Other common services
                23, 135, 139, 445, 993, 995, 1723, 3389, 5900, 5901,
                # Development/Debug ports
                4444, 8888, 9090, 9999
            ]

            findings.append({
                'severity': 'Info',
                'title': 'Port Scan Started',
                'description': f'Scanning {len(ports_to_scan)} common ports on {hostname}'
            })

            # Perform multi-threaded port scan
            open_ports = self.scan_ports(hostname, ports_to_scan)

            # Analyze results
            findings.extend(self.analyze_open_ports(hostname, open_ports))

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Port scan error',
                'description': f'Error during port scanning: {str(e)}'
            })

        return findings

    def scan_ports(self, hostname, ports):
        """Scan multiple ports using threading"""
        open_ports = []

        def scan_single_port(port):
            """Scan a single port"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()

                if result == 0:
                    return port
                return None

            except Exception:
                return None

        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(scan_single_port, ports))

        # Filter out None results
        open_ports = [port for port in results if port is not None]

        return sorted(open_ports)

    def analyze_open_ports(self, hostname, open_ports):
        """Analyze open ports and provide security assessment"""
        findings = []

        if not open_ports:
            findings.append({
                'severity': 'Info',
                'title': 'No Open Ports Found',
                'description': 'No open ports detected in the scanned range'
            })
            return findings

        # Categorize ports by risk level
        high_risk_ports = []
        medium_risk_ports = []
        low_risk_ports = []
        info_ports = []

        # Port risk classification
        port_info = {
            # High risk - should generally not be exposed
            22: ('SSH', 'High', 'SSH access should be restricted'),
            23: ('Telnet', 'High', 'Telnet is insecure - use SSH instead'),
            135: ('RPC Endpoint Mapper', 'High', 'Windows RPC service exposed'),
            139: ('NetBIOS', 'High', 'NetBIOS service exposed'),
            445: ('SMB', 'High', 'SMB/CIFS service exposed'),
            1433: ('MSSQL', 'High', 'Microsoft SQL Server exposed'),
            3306: ('MySQL', 'High', 'MySQL database exposed'),
            3389: ('RDP', 'High', 'Remote Desktop Protocol exposed'),
            5432: ('PostgreSQL', 'High', 'PostgreSQL database exposed'),
            5900: ('VNC', 'High', 'VNC remote access exposed'),
            27017: ('MongoDB', 'High', 'MongoDB database exposed'),

            # Medium risk - might be acceptable but needs attention
            21: ('FTP', 'Medium', 'FTP service may be misconfigured'),
            25: ('SMTP', 'Medium', 'Mail server exposed'),
            53: ('DNS', 'Medium', 'DNS server exposed'),
            110: ('POP3', 'Medium', 'Email service exposed'),
            143: ('IMAP', 'Medium', 'Email service exposed'),
            993: ('IMAPS', 'Medium', 'Secure IMAP service'),
            995: ('POP3S', 'Medium', 'Secure POP3 service'),
            1521: ('Oracle DB', 'Medium', 'Oracle database exposed'),
            6379: ('Redis', 'Medium', 'Redis database exposed'),
            8080: ('HTTP Alt', 'Medium', 'Alternative HTTP port'),
            8443: ('HTTPS Alt', 'Medium', 'Alternative HTTPS port'),

            # Low risk - common and usually acceptable
            80: ('HTTP', 'Low', 'Standard web server port'),
            443: ('HTTPS', 'Low', 'Secure web server port'),

            # Info - development/other ports
            3000: ('Development', 'Info', 'Common development server port'),
            4444: ('Development', 'Info', 'Common development/debug port'),
            5000: ('Development', 'Info', 'Common application port'),
            8000: ('Development', 'Info', 'Common development port'),
            8001: ('Development', 'Info', 'Common development port'),
            8008: ('Development', 'Info', 'Common development port'),
            8888: ('Development', 'Info', 'Common development port'),
            9000: ('Development', 'Info', 'Common application port'),
            9090: ('Development', 'Info', 'Common development port'),
            9999: ('Development', 'Info', 'Common development port'),
        }

        # Categorize found ports
        for port in open_ports:
            if port in port_info:
                service, risk, description = port_info[port]
                port_detail = f"Port {port} ({service}): {description}"

                if risk == 'High':
                    high_risk_ports.append(port_detail)
                elif risk == 'Medium':
                    medium_risk_ports.append(port_detail)
                elif risk == 'Low':
                    low_risk_ports.append(port_detail)
                else:
                    info_ports.append(port_detail)
            else:
                # Unknown port
                medium_risk_ports.append(f"Port {port} (Unknown): Unidentified service")

        # Generate findings based on discovered ports
        if high_risk_ports:
            findings.append({
                'severity': 'High',
                'title': 'High-Risk Ports Open',
                'description': f'Found {len(high_risk_ports)} high-risk open ports: {high_risk_ports[0]}'
                + (f' and {len(high_risk_ports)-1} more' if len(high_risk_ports) > 1 else '')
            })

        if medium_risk_ports:
            findings.append({
                'severity': 'Medium',
                'title': 'Medium-Risk Ports Open',
                'description': f'Found {len(medium_risk_ports)} potentially risky ports: {medium_risk_ports[0]}'
                + (f' and {len(medium_risk_ports)-1} more' if len(medium_risk_ports) > 1 else '')
            })

        if low_risk_ports:
            findings.append({
                'severity': 'Low',
                'title': 'Standard Web Ports',
                'description': f'Standard web server ports found: {", ".join([f"Port {port.split()[1].strip("()")}" for port in low_risk_ports])}'
            })

        if info_ports:
            findings.append({
                'severity': 'Info',
                'title': 'Development Ports Detected',
                'description': f'Found {len(info_ports)} development/application ports'
            })

        # Overall summary
        findings.append({
            'severity': 'Info',
            'title': 'Port Scan Summary',
            'description': f'Scan completed. Found {len(open_ports)} open ports on {hostname}: {", ".join(map(str, open_ports))}'
        })

        # Additional security recommendations
        if len(open_ports) > 10:
            findings.append({
                'severity': 'Medium',
                'title': 'Large Attack Surface',
                'description': f'Many open ports ({len(open_ports)}) increase the attack surface. Consider closing unnecessary services'
            })

        return findings

    def banner_grab(self, hostname, port):
        """Attempt to grab service banner for service identification"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))

            # Send common probes
            probes = [b'\r\n', b'GET / HTTP/1.0\r\n\r\n']

            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if banner.strip():
                        sock.close()
                        return banner.strip()
                except:
                    continue

            sock.close()
            return None

        except Exception:
            return None

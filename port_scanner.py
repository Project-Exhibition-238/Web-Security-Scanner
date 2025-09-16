import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ipaddress

def scan_ports(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return {'error': f'Could not resolve hostname: {hostname}'}
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        open_ports = []
        
        # Use threading to scan ports faster
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in common_ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass
        
        # Analyze open ports for security implications
        analysis = analyze_open_ports(open_ports)
        
        return {
            'target': hostname,
            'ip': ip,
            'open_ports': open_ports,
            'analysis': analysis
        }
        
    except Exception as e:
        return {'error': str(e)}

def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except:
        return False

def analyze_open_ports(open_ports):
    issues = []
    recommendations = []
    
    # Check for potentially risky open ports
    risky_ports = {
        21: 'FTP - If not properly secured, can be vulnerable to attacks',
        22: 'SSH - If weak passwords are used, can be brute forced',
        23: 'Telnet - Insecure protocol, should be disabled',
        135: 'RPC - Can be exploited if not properly secured',
        139: 'NetBIOS - Can expose system information',
        445: 'SMB - Can be vulnerable to attacks like EternalBlue',
        3389: 'RDP - Can be brute forced if weak passwords are used'
    }
    
    for port in open_ports:
        if port in risky_ports:
            issues.append(f'Port {port} open: {risky_ports[port]}')
            recommendations.append(f'Ensure port {port} is properly secured or closed if not needed')
    
    # Check for unnecessary open ports
    unnecessary_ports = [23, 135, 139, 445]  # Typically not needed for web servers
    for port in open_ports:
        if port in unnecessary_ports:
            issues.append(f'Port {port} open: Typically not needed for web servers')
            recommendations.append(f'Consider closing port {port} if not specifically required')
    
    return {
        'issues': issues,
        'recommendations': recommendations
    }
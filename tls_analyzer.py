import requests
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class TLSAnalyzer:
    def __init__(self):
        self.timeout = 10

    def scan(self, url):
        findings = []
        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.netloc
            port = 443
            if ':' in hostname:
                hostname, port_str = hostname.split(':')
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            if parsed_url.scheme.lower() == 'http':
                test_url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
                findings.append({
                    'severity': 'Medium',
                    'title': 'HTTP Protocol Detected',
                    'description': f'Website using HTTP, testing HTTPS availability on {test_url}'
                })
            else:
                test_url = url
            findings.extend(self.analyze_certificate_detailed(hostname, port))
            findings.extend(self.analyze_tls_versions(hostname, port))
            findings.extend(self.analyze_cipher_suites(hostname, port))
            findings.extend(self.test_with_requests_enhanced(test_url))
        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'TLS analysis error',
                'description': f'Error during TLS analysis: {str(e)}'
            })
        return findings

    def analyze_certificate_detailed(self, hostname, port):
        findings = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                    now = datetime.now(timezone.utc)
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                    if now < not_before:
                        findings.append({
                            'severity': 'Critical',
                            'title': 'Certificate Not Yet Valid',
                            'description': f'Certificate not valid until {not_before}'
                        })
                    elif now > not_after:
                        findings.append({
                            'severity': 'Critical',
                            'title': 'Certificate Expired',
                            'description': f'Certificate expired on {not_after}'
                        })
                    else:
                        days = (not_after - now).days
                        if days < 7:
                            findings.append({
                                'severity': 'Critical',
                                'title': 'Certificate Expires Very Soon',
                                'description': f'Certificate expires in {days} days'
                            })
                        elif days < 30:
                            findings.append({
                                'severity': 'High',
                                'title': 'Certificate Expires Soon',
                                'description': f'Certificate expires in {days} days'
                            })
                        else:
                            findings.append({
                                'severity': 'Info',
                                'title': 'Certificate Valid',
                                'description': f'Certificate valid until {not_after} ({days} days remaining)'
                            })
                    # Key strength check
                    public_key = cert.public_key()
                    key_type = type(public_key).__name__
                    if hasattr(public_key, 'key_size'):
                        key_size = public_key.key_size
                        if key_size >= 4096:
                            findings.append({'severity': 'Info', 'title': 'Key Strength Excellent', 'description': f'{key_type} {key_size}-bit'})
                        elif key_size >= 2048:
                            findings.append({'severity': 'Info', 'title': 'Key Strength Good', 'description': f'{key_type} {key_size}-bit'})
                        else:
                            findings.append({'severity': 'Medium', 'title': 'Weak Key', 'description': f'{key_type} {key_size}-bit'})
        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate analysis error',
                'description': f'Could not analyze certificate: {str(e)}'
            })
        return findings

    def analyze_tls_versions(self, hostname, port):
        findings = []
        try:
            tls_tests = [
                ('TLS 1.3', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1_3, 'maximum_version': ssl.TLSVersion.TLSv1_3}),
                ('TLS 1.2', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1_2, 'maximum_version': ssl.TLSVersion.TLSv1_2}),
                ('TLS 1.1', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1_1, 'maximum_version': ssl.TLSVersion.TLSv1_1}),
                ('TLS 1.0', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1,   'maximum_version': ssl.TLSVersion.TLSv1}),
            ]
            supported_versions = []
            for version_name, protocol, vconf in tls_tests:
                try:
                    context = ssl.SSLContext(protocol)
                    context.minimum_version = vconf['minimum_version']
                    context.maximum_version = vconf['maximum_version']
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname):
                            supported_versions.append(version_name)
                except Exception:
                    continue
            if 'TLS 1.3' in supported_versions:
                findings.append({'severity': 'Info','title': 'TLS 1.3 Supported','description': 'Server supports TLS 1.3'})
            if 'TLS 1.2' in supported_versions:
                findings.append({'severity': 'Info','title': 'TLS 1.2 Supported','description': 'Server supports TLS 1.2'})
            deprecated = [v for v in supported_versions if v in ['TLS 1.0','TLS 1.1']]
            if deprecated:
                findings.append({'severity': 'Medium','title': 'Deprecated TLS Version(s)','description': 'Supported: ' + ', '.join(deprecated)})
            if not supported_versions:
                findings.append({'severity': 'Critical','title': 'No Secure TLS Version','description': 'No supported TLS version detected'})
        except Exception as e:
            findings.append({'severity':'Info','title':'TLS version analysis error','description':str(e)})
        return findings

    def analyze_cipher_suites(self, hostname, port):
        findings = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name, tls_version, key_bits = cipher_info
                        if any(x in cipher_name.upper() for x in ['RC4','3DES','DES','MD5']):
                            findings.append({'severity':'Critical','title':'Insecure Cipher Suite','description':cipher_name})
                        elif key_bits < 128:
                            findings.append({'severity':'Medium','title':'Weak Cipher Suite','description':f'{cipher_name}, bits: {key_bits}'})
                        else:
                            findings.append({'severity':'Info','title':'Current Cipher Suite','description':f'{cipher_name}, {key_bits} bits'})
        except Exception as e:
            findings.append({'severity':'Info','title':'Cipher suite analysis error','description':str(e)})
        return findings

    def test_with_requests_enhanced(self, url):
        findings = []
        try:
            session = requests.Session()
            session.headers.update({'User-Agent':'Enhanced-TLS-Analyzer/2.0'})
            response = session.get(url, timeout=self.timeout, verify=True)
            if response.status_code == 200:
                findings.append({'severity':'Info','title':'HTTPS Connection Successful','description':'SSL/TLS handshake and HTTPS connection completed successfully'})
                hsts = response.headers.get('Strict-Transport-Security')
                if hsts:
                    findings.append({'severity':'Info','title':'HSTS Present','description':f'Strict-Transport-Security: {hsts}'})
                else:
                    findings.append({'severity':'Medium','title':'Missing HSTS Header','description':'HTTP Strict Transport Security header not found'})
        except requests.exceptions.SSLError as e:
            findings.append({'severity':'Critical','title':'SSL Certificate Verification Failed','description':str(e)})
        except Exception as e:
            findings.append({'severity':'Info','title':'TLS connection error','description':str(e)})
        return findings

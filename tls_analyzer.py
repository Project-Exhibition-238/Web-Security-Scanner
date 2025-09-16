import ssl
import socket
import datetime
from urllib.parse import urlparse
import requests

def check_tls_configuration(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                
                # Check certificate expiration
                cert_expiry = get_certificate_expiration(cert)
                days_until_expiry = (cert_expiry - datetime.datetime.now()).days
                
                # Check supported protocols
                protocol_support = check_supported_protocols(hostname, port)
                
                return {
                    'certificate': {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expiration': cert_expiry.strftime('%Y-%m-%d'),
                        'days_until_expiry': days_until_expiry,
                        'valid': days_until_expiry > 0
                    },
                    'cipher': {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    },
                    'protocol': tls_version,
                    'protocol_support': protocol_support,
                    'analysis': analyze_tls_security(cert_expiry, tls_version, cipher[0])
                }
                
    except Exception as e:
        return {'error': str(e)}

def get_certificate_expiration(cert):
    expires = cert['notAfter']
    return datetime.datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')

def check_supported_protocols(hostname, port):
    protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
    results = {}
    
    for protocol in protocols:
        try:
            context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{protocol.replace('v', '_')}"))
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results[protocol] = True
        except:
            results[protocol] = False
    
    return results

def analyze_tls_security(expiry, protocol, cipher):
    issues = []
    recommendations = []
    score = 100
    
    # Check certificate expiration
    if (expiry - datetime.datetime.now()).days < 30:
        issues.append('Certificate expires soon')
        recommendations.append('Renew SSL certificate')
        score -= 20
    
    # Check protocol version
    if protocol in ['TLSv1', 'TLSv1.1']:
        issues.append(f'Using outdated protocol: {protocol}')
        recommendations.append('Disable support for TLSv1 and TLSv1.1')
        score -= 30
    elif protocol == 'SSLv3' or protocol == 'SSLv2':
        issues.append(f'Using insecure protocol: {protocol}')
        recommendations.append('Immediately disable support for SSL protocols')
        score -= 50
    
    # Check cipher strength
    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
    if any(cipher in cipher for cipher in weak_ciphers):
        issues.append(f'Using weak cipher: {cipher}')
        recommendations.append('Use strong ciphers like AES-GCM, CHACHA20')
        score -= 20
    
    return {
        'issues': issues,
        'recommendations': recommendations,
        'score': max(score, 0)  # Ensure score doesn't go below 0
    }
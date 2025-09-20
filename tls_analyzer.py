import requests
import ssl
import socket
import urllib.parse
from datetime import datetime
import OpenSSL.crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class TLSAnalyzer:
    def __init__(self):
        self.timeout = 10

    def scan(self, url):
        """Main TLS/SSL analysis method"""
        findings = []

        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.netloc
            port = 443

            # Handle port specification
            if ':' in hostname:
                hostname, port_str = hostname.split(':')
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443

            # Only analyze HTTPS URLs
            if parsed_url.scheme.lower() != 'https':
                findings.append({
                    'severity': 'High',
                    'title': 'No HTTPS',
                    'description': 'Website is not using HTTPS encryption'
                })
                return findings

            findings.extend(self.analyze_certificate(hostname, port))
            findings.extend(self.analyze_tls_configuration(hostname, port))
            findings.extend(self.test_with_requests(url))

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'TLS analysis error',
                'description': f'Error during TLS analysis: {str(e)}'
            })

        return findings

    def analyze_certificate(self, hostname, port):
        """Analyze SSL certificate details"""
        findings = []

        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert_chain()[0].to_der()
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Analyze certificate details
                    findings.extend(self._analyze_cert_validity(cert))
                    findings.extend(self._analyze_cert_issuer(cert))
                    findings.extend(self._analyze_cert_subject(cert, hostname))
                    findings.extend(self._analyze_cert_extensions(cert))

        except ssl.SSLError as e:
            findings.append({
                'severity': 'High',
                'title': 'SSL/TLS Error',
                'description': f'SSL connection failed: {str(e)}'
            })
        except socket.timeout:
            findings.append({
                'severity': 'Medium',
                'title': 'Connection Timeout',
                'description': f'Connection to {hostname}:{port} timed out'
            })
        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate analysis error',
                'description': f'Could not analyze certificate: {str(e)}'
            })

        return findings

    def analyze_tls_configuration(self, hostname, port):
        """Analyze TLS protocol and cipher configuration"""
        findings = []

        try:
            # Test different TLS versions
            tls_versions = [
                ('TLS 1.3', ssl.PROTOCOL_TLS),
                ('TLS 1.2', ssl.PROTOCOL_TLSv1_2),
                ('TLS 1.1', ssl.PROTOCOL_TLSv1_1),
                ('TLS 1.0', ssl.PROTOCOL_TLSv1),
            ]

            supported_versions = []
            negotiated_cipher = None

            for version_name, protocol in tls_versions:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock) as ssock:
                            supported_versions.append(version_name)
                            if not negotiated_cipher:
                                negotiated_cipher = ssock.cipher()
                            break  # Stop at first successful connection
                except:
                    continue

            # Evaluate TLS versions
            if 'TLS 1.3' in supported_versions:
                findings.append({
                    'severity': 'Info',
                    'title': 'Modern TLS Support',
                    'description': 'Server supports TLS 1.3 (latest standard)'
                })
            elif 'TLS 1.2' in supported_versions:
                findings.append({
                    'severity': 'Info',
                    'title': 'Good TLS Support',
                    'description': 'Server supports TLS 1.2'
                })

            # Check for deprecated versions
            if 'TLS 1.0' in supported_versions or 'TLS 1.1' in supported_versions:
                findings.append({
                    'severity': 'Medium',
                    'title': 'Deprecated TLS Versions',
                    'description': 'Server supports deprecated TLS 1.0/1.1 versions'
                })

            # Analyze cipher suite
            if negotiated_cipher:
                findings.extend(self._analyze_cipher_suite(negotiated_cipher))

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'TLS configuration error',
                'description': f'Could not analyze TLS configuration: {str(e)}'
            })

        return findings

    def test_with_requests(self, url):
        """Test HTTPS connection using requests library"""
        findings = []

        try:
            session = requests.Session()
            session.headers.update({'User-Agent': 'TLS-Analyzer/1.0'})

            # Test basic HTTPS connection
            response = session.get(url, timeout=self.timeout, verify=True)

            if response.status_code == 200:
                findings.append({
                    'severity': 'Info',
                    'title': 'HTTPS Connection Successful',
                    'description': 'SSL/TLS handshake completed successfully'
                })

            # Check for HTTP Strict Transport Security
            hsts_header = response.headers.get('Strict-Transport-Security')
            if hsts_header:
                findings.extend(self._analyze_hsts_header(hsts_header))
            else:
                findings.append({
                    'severity': 'Medium',
                    'title': 'Missing HSTS Header',
                    'description': 'HTTP Strict Transport Security header not found'
                })

        except requests.exceptions.SSLError as e:
            findings.append({
                'severity': 'High',
                'title': 'SSL Verification Failed',
                'description': f'SSL certificate verification failed: {str(e)}'
            })
        except requests.exceptions.RequestException as e:
            findings.append({
                'severity': 'Medium',
                'title': 'HTTPS Connection Failed',
                'description': f'Could not establish HTTPS connection: {str(e)}'
            })

        return findings

    def _analyze_cert_validity(self, cert):
        """Analyze certificate validity period"""
        findings = []

        try:
            now = datetime.utcnow()
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

            # Check if certificate is valid
            if now < not_before:
                findings.append({
                    'severity': 'High',
                    'title': 'Certificate Not Yet Valid',
                    'description': f'Certificate is not valid until {not_before}'
                })
            elif now > not_after:
                findings.append({
                    'severity': 'Critical',
                    'title': 'Certificate Expired',
                    'description': f'Certificate expired on {not_after}'
                })
            else:
                # Check if certificate expires soon
                days_until_expiry = (not_after - now).days
                if days_until_expiry < 30:
                    severity = 'High' if days_until_expiry < 7 else 'Medium'
                    findings.append({
                        'severity': severity,
                        'title': 'Certificate Expiring Soon',
                        'description': f'Certificate expires in {days_until_expiry} days on {not_after.strftime("%Y-%m-%d")}'
                    })
                else:
                    findings.append({
                        'severity': 'Info',
                        'title': 'Certificate Valid',
                        'description': f'Certificate valid until {not_after.strftime("%Y-%m-%d")} ({days_until_expiry} days remaining)'
                    })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate validity check error',
                'description': f'Could not check certificate validity: {str(e)}'
            })

        return findings

    def _analyze_cert_issuer(self, cert):
        """Analyze certificate issuer"""
        findings = []

        try:
            issuer = cert.issuer
            issuer_name = None

            for attribute in issuer:
                if attribute.oid.dotted_string == '2.5.4.3':  # Common Name OID
                    issuer_name = attribute.value
                    break

            if issuer_name:
                # Check if it's a well-known CA
                trusted_cas = [
                    "Let's Encrypt", 'DigiCert', 'Comodo', 'GeoTrust',
                    'Symantec', 'Thawte', 'VeriSign', 'GlobalSign',
                    'Sectigo', 'Amazon', 'Google Trust Services'
                ]

                is_trusted = any(ca.lower() in issuer_name.lower() for ca in trusted_cas)

                if is_trusted:
                    findings.append({
                        'severity': 'Info',
                        'title': 'Trusted Certificate Authority',
                        'description': f'Certificate issued by trusted CA: {issuer_name}'
                    })
                else:
                    findings.append({
                        'severity': 'Medium',
                        'title': 'Unknown Certificate Authority',
                        'description': f'Certificate issued by: {issuer_name}'
                    })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate issuer check error',
                'description': f'Could not analyze certificate issuer: {str(e)}'
            })

        return findings

    def _analyze_cert_subject(self, cert, expected_hostname):
        """Analyze certificate subject and hostname validation"""
        findings = []

        try:
            # Get subject common name
            subject = cert.subject
            subject_cn = None

            for attribute in subject:
                if attribute.oid.dotted_string == '2.5.4.3':  # Common Name OID
                    subject_cn = attribute.value
                    break

            # Get Subject Alternative Names
            san_names = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = [name.value for name in san_ext.value]
            except:
                pass

            # Check hostname validation
            all_names = [subject_cn] + san_names if subject_cn else san_names
            hostname_matches = any(
                name == expected_hostname or 
                (name.startswith('*.') and expected_hostname.endswith(name[2:]))
                for name in all_names if name
            )

            if hostname_matches:
                findings.append({
                    'severity': 'Info',
                    'title': 'Hostname Validation Passed',
                    'description': f'Certificate is valid for {expected_hostname}'
                })
            else:
                findings.append({
                    'severity': 'High',
                    'title': 'Hostname Validation Failed',
                    'description': f'Certificate is not valid for {expected_hostname}. Valid for: {", ".join(all_names)}'
                })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate subject check error',
                'description': f'Could not analyze certificate subject: {str(e)}'
            })

        return findings

    def _analyze_cert_extensions(self, cert):
        """Analyze certificate extensions"""
        findings = []

        try:
            # Check key usage
            try:
                key_usage_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
                if key_usage_ext.value.digital_signature and key_usage_ext.value.key_encipherment:
                    findings.append({
                        'severity': 'Info',
                        'title': 'Proper Key Usage',
                        'description': 'Certificate has appropriate key usage extensions'
                    })
            except:
                pass

            # Check extended key usage
            try:
                ext_key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
                if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage.value:
                    findings.append({
                        'severity': 'Info',
                        'title': 'Server Authentication',
                        'description': 'Certificate is properly configured for server authentication'
                    })
            except:
                pass

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate extensions check error',
                'description': f'Could not analyze certificate extensions: {str(e)}'
            })

        return findings

    def _analyze_cipher_suite(self, cipher_info):
        """Analyze negotiated cipher suite"""
        findings = []

        try:
            if cipher_info:
                cipher_name, tls_version, key_bits = cipher_info

                # Check for weak ciphers
                weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                is_weak = any(weak.lower() in cipher_name.lower() for weak in weak_ciphers)

                if is_weak:
                    findings.append({
                        'severity': 'High',
                        'title': 'Weak Cipher Suite',
                        'description': f'Server negotiated weak cipher: {cipher_name}'
                    })
                elif key_bits >= 256:
                    findings.append({
                        'severity': 'Info',
                        'title': 'Strong Cipher Suite',
                        'description': f'Strong cipher in use: {cipher_name} ({key_bits} bits)'
                    })
                elif key_bits >= 128:
                    findings.append({
                        'severity': 'Low',
                        'title': 'Adequate Cipher Suite',
                        'description': f'Adequate cipher in use: {cipher_name} ({key_bits} bits)'
                    })
                else:
                    findings.append({
                        'severity': 'Medium',
                        'title': 'Weak Key Length',
                        'description': f'Cipher uses weak key length: {cipher_name} ({key_bits} bits)'
                    })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Cipher analysis error',
                'description': f'Could not analyze cipher suite: {str(e)}'
            })

        return findings

    def _analyze_hsts_header(self, hsts_header):
        """Analyze HSTS header configuration"""
        findings = []

        try:
            # Parse HSTS header
            hsts_lower = hsts_header.lower()

            # Extract max-age
            max_age = 0
            if 'max-age=' in hsts_lower:
                try:
                    max_age_str = hsts_lower.split('max-age=')[1].split(';')[0].strip()
                    max_age = int(max_age_str)
                except:
                    pass

            # Check max-age value (recommended: at least 1 year = 31536000 seconds)
            if max_age >= 31536000:  # 1 year
                findings.append({
                    'severity': 'Info',
                    'title': 'Strong HSTS Policy',
                    'description': f'HSTS max-age is set to {max_age} seconds (≥1 year)'
                })
            elif max_age >= 86400:  # 1 day
                findings.append({
                    'severity': 'Low',
                    'title': 'Weak HSTS Policy',
                    'description': f'HSTS max-age is {max_age} seconds (recommended: ≥1 year)'
                })
            else:
                findings.append({
                    'severity': 'Medium',
                    'title': 'Very Weak HSTS Policy',
                    'description': f'HSTS max-age is only {max_age} seconds'
                })

            # Check for includeSubDomains
            if 'includesubdomains' in hsts_lower:
                findings.append({
                    'severity': 'Info',
                    'title': 'HSTS Subdomain Protection',
                    'description': 'HSTS policy includes subdomains'
                })

            # Check for preload
            if 'preload' in hsts_lower:
                findings.append({
                    'severity': 'Info',
                    'title': 'HSTS Preload Ready',
                    'description': 'HSTS policy is preload-ready'
                })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'HSTS analysis error',
                'description': f'Could not analyze HSTS header: {str(e)}'
            })

        return findings

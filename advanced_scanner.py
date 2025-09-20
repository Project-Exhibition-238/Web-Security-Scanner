import requests
import dns.resolver
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
from bs4 import BeautifulSoup

class AdvancedScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Advanced Security Assessment)'
        })
        self.timeout = 5  # Reduced timeout

    def _try_both_protocols(self, url):
        """Try both HTTP and HTTPS if one fails"""
        urls_to_try = []

        if url.startswith('https://'):
            urls_to_try = [url, url.replace('https://', 'http://')]
        elif url.startswith('http://'):
            urls_to_try = [url.replace('http://', 'https://'), url]
        else:
            # No protocol specified, try HTTPS first then HTTP
            urls_to_try = [f'https://{url}', f'http://{url}']

        for test_url in urls_to_try:
            try:
                print(f"[DEBUG] Trying to connect to: {test_url}")
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200:
                    print(f"[DEBUG] Successfully connected to: {test_url}")
                    return response, test_url
            except Exception as e:
                print(f"[DEBUG] Failed to connect to {test_url}: {e}")
                continue

        # If both fail, raise the last exception
        raise requests.exceptions.ConnectionError(f"Could not connect to {url} via HTTP or HTTPS")

    def scan(self, url):
        """Main scan method for advanced security checks"""
        findings = []

        try:
            print(f"[DEBUG] Starting advanced scan for: {url}")

            # Parse base domain for subdomain enumeration
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc

            # Run advanced checks with fallback
            print("[DEBUG] Running CSRF protection check...")
            findings.extend(self.check_csrf_protection(url))

            print("[DEBUG] Running clickjacking protection check...")
            findings.extend(self.check_clickjacking_protection(url))

            print("[DEBUG] Running version disclosure check...")
            findings.extend(self.check_version_disclosure(url))

            print("[DEBUG] Running subdomain enumeration...")
            findings.extend(self.enumerate_subdomains(domain))

        except Exception as e:
            print(f"[ERROR] Advanced scan error: {e}")
            findings.append({
                'severity': 'Info',
                'title': 'Advanced scan error',
                'description': f'Error during advanced scanning: {str(e)}'
            })

        return findings

    def check_csrf_protection(self, url):
        """Check for modern CSRF protection mechanisms"""
        findings = []

        try:
            response, working_url = self._try_both_protocols(url)

            # Check for SameSite cookie attributes (modern CSRF protection)
            csrf_protected = False

            # Look for SameSite attributes in Set-Cookie headers
            set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
            if not set_cookie_headers:
                # Fallback for different requests versions
                set_cookie_headers = [response.headers.get('Set-Cookie', '')]

            for cookie_header in set_cookie_headers:
                if cookie_header and ('SameSite=Lax' in cookie_header or 'SameSite=Strict' in cookie_header):
                    csrf_protected = True
                    break

            # Parse HTML for forms and check for CSRF tokens
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            csrf_tokens_found = 0
            for form in forms:
                # Look for common CSRF token field names
                csrf_fields = form.find_all('input', {'name': lambda x: x and any(
                    token in x.lower() for token in ['csrf', 'token', '_token', 'authenticity_token']
                )})
                if csrf_fields:
                    csrf_tokens_found += 1

            if not csrf_protected and len(forms) > 0:
                if csrf_tokens_found == 0:
                    findings.append({
                        'severity': 'High',
                        'title': 'Missing CSRF Protection',
                        'description': f'Found {len(forms)} forms without CSRF tokens and no SameSite cookie protection'
                    })
                else:
                    findings.append({
                        'severity': 'Medium',
                        'title': 'Weak CSRF Protection',
                        'description': f'CSRF tokens found but no modern SameSite cookie protection detected'
                    })
            elif csrf_protected:
                findings.append({
                    'severity': 'Info',
                    'title': 'CSRF Protection Active',
                    'description': 'Modern SameSite cookie protection detected'
                })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'CSRF check error',
                'description': f'Could not complete CSRF protection check: {str(e)}'
            })

        return findings

    def check_clickjacking_protection(self, url):
        """Check for clickjacking protection headers"""
        findings = []

        try:
            response, working_url = self._try_both_protocols(url)

            x_frame_options = response.headers.get('X-Frame-Options', '').lower()
            csp_header = response.headers.get('Content-Security-Policy', '').lower()

            clickjacking_protected = False

            # Check X-Frame-Options header
            if x_frame_options in ['deny', 'sameorigin'] or 'allow-from' in x_frame_options:
                clickjacking_protected = True
                findings.append({
                    'severity': 'Info',
                    'title': 'X-Frame-Options Protection',
                    'description': f'X-Frame-Options set to: {x_frame_options}'
                })

            # Check CSP frame-ancestors directive
            if 'frame-ancestors' in csp_header:
                clickjacking_protected = True
                findings.append({
                    'severity': 'Info',
                    'title': 'CSP Frame Protection',
                    'description': 'Content-Security-Policy includes frame-ancestors directive'
                })

            if not clickjacking_protected:
                findings.append({
                    'severity': 'Medium',
                    'title': 'Missing Clickjacking Protection',
                    'description': 'No X-Frame-Options header or CSP frame-ancestors directive found'
                })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Clickjacking check error',
                'description': f'Could not complete clickjacking check: {str(e)}'
            })

        return findings

    def check_version_disclosure(self, url):
        """Check for software version disclosure in headers"""
        findings = []

        try:
            response, working_url = self._try_both_protocols(url)

            version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']

            for header in version_headers:
                value = response.headers.get(header, '')
                if value:
                    # Look for version numbers in header values
                    import re
                    version_pattern = r'\b\d+\.\d+(\.\d+)?\b'
                    if re.search(version_pattern, value):
                        findings.append({
                            'severity': 'Medium',
                            'title': 'Version Disclosure',
                            'description': f'{header} header reveals version information: {value}'
                        })
                    else:
                        findings.append({
                            'severity': 'Low',
                            'title': 'Technology Disclosure',
                            'description': f'{header} header reveals technology stack: {value}'
                        })

            # Check for common CMS/framework signatures
            self._check_cms_signatures(response, findings)

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Version disclosure check error',
                'description': f'Could not complete version disclosure check: {str(e)}'
            })

        return findings

    def enumerate_subdomains(self, domain):
        """Enumerate subdomains using DNS lookups"""
        findings = []

        try:
            # Common subdomain list (reduced for speed)
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test',
                'staging', 'blog', 'app', 'secure', 'portal'
            ]

            found_subdomains = []

            def check_subdomain(subdomain):
                try:
                    full_domain = f"{subdomain}.{domain}"
                    dns.resolver.resolve(full_domain, 'A')
                    return full_domain
                except:
                    return None

            # Use threading to speed up DNS lookups
            with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced workers
                results = list(executor.map(check_subdomain, common_subdomains))

            found_subdomains = [sub for sub in results if sub]

            if found_subdomains:
                severity = 'Medium' if len(found_subdomains) > 3 else 'Low'
                findings.append({
                    'severity': severity,
                    'title': 'Subdomain Enumeration',
                    'description': f'Found {len(found_subdomains)} subdomains: {", ".join(found_subdomains[:5])}{"..." if len(found_subdomains) > 5 else ""}'
                })
            else:
                findings.append({
                    'severity': 'Info',
                    'title': 'Subdomain Enumeration',
                    'description': 'No common subdomains found via DNS enumeration'
                })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Subdomain enumeration error',
                'description': f'Could not complete subdomain enumeration: {str(e)}'
            })

        return findings

    def _check_cms_signatures(self, response, findings):
        """Check for CMS/framework signatures in response"""
        signatures = {
            'WordPress': ['wp-content/', 'wp-includes/', '/wp-json/'],
            'Drupal': ['/sites/default/', '/modules/', 'Drupal.'],
            'Joomla': ['/components/', '/modules/', 'Joomla!'],
            'Django': ['csrfmiddlewaretoken', '__admin_media_prefix__'],
            'Laravel': ['laravel_session', '_token'],
            'React': ['react', 'ReactDOM'],
            'Angular': ['ng-app', 'angular'],
            'Vue.js': ['vue', 'v-if', 'v-for']
        }

        response_text = response.text.lower()

        for cms, indicators in signatures.items():
            if any(indicator.lower() in response_text for indicator in indicators):
                findings.append({
                    'severity': 'Info',
                    'title': 'Technology Stack Identified',
                    'description': f'{cms} framework/CMS detected'
                })
                break

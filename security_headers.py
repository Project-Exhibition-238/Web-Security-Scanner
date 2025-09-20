import requests
import re
from urllib.parse import urlparse

class SecurityHeadersChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Security Headers Analysis)'
        })
        self.timeout = 10

    def scan(self, url):
        """Main security headers analysis method"""
        findings = []

        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers

            # Analyze all important security headers
            findings.extend(self.check_content_security_policy(headers))
            findings.extend(self.check_strict_transport_security(headers))
            findings.extend(self.check_x_frame_options(headers))
            findings.extend(self.check_x_content_type_options(headers))
            findings.extend(self.check_x_xss_protection(headers))
            findings.extend(self.check_referrer_policy(headers))
            findings.extend(self.check_permissions_policy(headers))
            findings.extend(self.check_other_headers(headers))

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Security headers check error',
                'description': f'Error during security headers analysis: {str(e)}'
            })

        return findings

    def check_content_security_policy(self, headers):
        """Analyze Content Security Policy header"""
        findings = []

        csp_header = headers.get('Content-Security-Policy') or headers.get('Content-Security-Policy-Report-Only')

        if not csp_header:
            findings.append({
                'severity': 'High',
                'title': 'Missing Content Security Policy',
                'description': 'No CSP header found. Site may be vulnerable to XSS and data injection attacks'
            })
            return findings

        # Analyze CSP directives
        csp_lower = csp_header.lower()

        # Check for dangerous directives
        dangerous_patterns = [
            ("'unsafe-inline'", "Medium", "CSP allows unsafe inline scripts/styles"),
            ("'unsafe-eval'", "Medium", "CSP allows unsafe eval() usage"),
            ("data:", "Low", "CSP allows data: URIs which can be risky"),
            ("*", "Medium", "CSP uses wildcard (*) which weakens security")
        ]

        for pattern, severity, description in dangerous_patterns:
            if pattern in csp_lower:
                findings.append({
                    'severity': severity,
                    'title': 'Weak CSP Directive',
                    'description': description
                })

        # Check for good practices
        if "'self'" in csp_lower:
            findings.append({
                'severity': 'Info',
                'title': 'CSP Self Restriction',
                'description': "CSP properly restricts sources to 'self'"
            })

        if 'script-src' in csp_lower:
            findings.append({
                'severity': 'Info',
                'title': 'CSP Script Protection',
                'description': 'CSP includes script-src directive for XSS protection'
            })

        # Check if it's report-only
        if 'Content-Security-Policy-Report-Only' in str(headers):
            findings.append({
                'severity': 'Low',
                'title': 'CSP in Report-Only Mode',
                'description': 'CSP is in report-only mode and not enforcing restrictions'
            })
        else:
            findings.append({
                'severity': 'Info',
                'title': 'CSP Header Present',
                'description': 'Content Security Policy header is present and enforcing'
            })

        return findings

    def check_strict_transport_security(self, headers):
        """Analyze HTTP Strict Transport Security header"""
        findings = []

        hsts_header = headers.get('Strict-Transport-Security')

        if not hsts_header:
            findings.append({
                'severity': 'Medium',
                'title': 'Missing HSTS Header',
                'description': 'No HTTP Strict Transport Security header found'
            })
            return findings

        # Parse HSTS header
        hsts_lower = hsts_header.lower()

        # Extract max-age
        max_age = 0
        max_age_match = re.search(r'max-age=(\d+)', hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))

        # Analyze max-age value
        one_year = 31536000  # seconds in a year

        if max_age >= one_year:
            findings.append({
                'severity': 'Info',
                'title': 'Strong HSTS Policy',
                'description': f'HSTS max-age is {max_age} seconds (≥1 year recommended)'
            })
        elif max_age >= 86400:  # 1 day
            findings.append({
                'severity': 'Low',
                'title': 'Weak HSTS Max-Age',
                'description': f'HSTS max-age is {max_age} seconds (should be ≥1 year)'
            })
        else:
            findings.append({
                'severity': 'Medium',
                'title': 'Very Weak HSTS Max-Age',
                'description': f'HSTS max-age is only {max_age} seconds'
            })

        # Check for includeSubDomains
        if 'includesubdomains' in hsts_lower:
            findings.append({
                'severity': 'Info',
                'title': 'HSTS Subdomain Protection',
                'description': 'HSTS policy includes subdomains'
            })
        else:
            findings.append({
                'severity': 'Low',
                'title': 'HSTS Missing Subdomain Protection',
                'description': 'HSTS policy does not include subdomains'
            })

        # Check for preload
        if 'preload' in hsts_lower:
            findings.append({
                'severity': 'Info',
                'title': 'HSTS Preload Ready',
                'description': 'HSTS policy includes preload directive'
            })

        return findings

    def check_x_frame_options(self, headers):
        """Analyze X-Frame-Options header"""
        findings = []

        xfo_header = headers.get('X-Frame-Options')

        if not xfo_header:
            findings.append({
                'severity': 'Medium',
                'title': 'Missing X-Frame-Options',
                'description': 'No X-Frame-Options header found. Site may be vulnerable to clickjacking'
            })
            return findings

        xfo_lower = xfo_header.lower()

        if xfo_lower == 'deny':
            findings.append({
                'severity': 'Info',
                'title': 'Strong Clickjacking Protection',
                'description': 'X-Frame-Options set to DENY (strongest protection)'
            })
        elif xfo_lower == 'sameorigin':
            findings.append({
                'severity': 'Info',
                'title': 'Good Clickjacking Protection',
                'description': 'X-Frame-Options set to SAMEORIGIN'
            })
        elif xfo_lower.startswith('allow-from'):
            findings.append({
                'severity': 'Low',
                'title': 'Limited Clickjacking Protection',
                'description': 'X-Frame-Options uses ALLOW-FROM (deprecated, use CSP instead)'
            })
        else:
            findings.append({
                'severity': 'Medium',
                'title': 'Invalid X-Frame-Options',
                'description': f'X-Frame-Options has invalid value: {xfo_header}'
            })

        return findings

    def check_x_content_type_options(self, headers):
        """Analyze X-Content-Type-Options header"""
        findings = []

        xcto_header = headers.get('X-Content-Type-Options')

        if not xcto_header:
            findings.append({
                'severity': 'Low',
                'title': 'Missing X-Content-Type-Options',
                'description': 'No X-Content-Type-Options header found. MIME type sniffing not prevented'
            })
            return findings

        if xcto_header.lower() == 'nosniff':
            findings.append({
                'severity': 'Info',
                'title': 'MIME Sniffing Protection',
                'description': 'X-Content-Type-Options properly set to nosniff'
            })
        else:
            findings.append({
                'severity': 'Low',
                'title': 'Invalid X-Content-Type-Options',
                'description': f'X-Content-Type-Options has invalid value: {xcto_header}'
            })

        return findings

    def check_x_xss_protection(self, headers):
        """Analyze X-XSS-Protection header"""
        findings = []

        xxp_header = headers.get('X-XSS-Protection')

        if not xxp_header:
            findings.append({
                'severity': 'Low',
                'title': 'Missing X-XSS-Protection',
                'description': 'No X-XSS-Protection header found (deprecated but still useful for older browsers)'
            })
            return findings

        xxp_lower = xxp_header.lower()

        if xxp_lower == '1; mode=block':
            findings.append({
                'severity': 'Info',
                'title': 'XSS Protection Enabled',
                'description': 'X-XSS-Protection properly configured with mode=block'
            })
        elif xxp_lower.startswith('1'):
            findings.append({
                'severity': 'Low',
                'title': 'Basic XSS Protection',
                'description': 'X-XSS-Protection enabled but consider adding mode=block'
            })
        elif xxp_lower == '0':
            findings.append({
                'severity': 'Medium',
                'title': 'XSS Protection Disabled',
                'description': 'X-XSS-Protection explicitly disabled'
            })
        else:
            findings.append({
                'severity': 'Low',
                'title': 'Invalid X-XSS-Protection',
                'description': f'X-XSS-Protection has invalid value: {xxp_header}'
            })

        return findings

    def check_referrer_policy(self, headers):
        """Analyze Referrer-Policy header"""
        findings = []

        rp_header = headers.get('Referrer-Policy')

        if not rp_header:
            findings.append({
                'severity': 'Low',
                'title': 'Missing Referrer-Policy',
                'description': 'No Referrer-Policy header found. Consider setting for privacy protection'
            })
            return findings

        rp_lower = rp_header.lower()

        strict_policies = ['no-referrer', 'same-origin', 'strict-origin']
        moderate_policies = ['strict-origin-when-cross-origin', 'origin']

        if rp_lower in strict_policies:
            findings.append({
                'severity': 'Info',
                'title': 'Strong Referrer Policy',
                'description': f'Referrer-Policy set to strict value: {rp_header}'
            })
        elif rp_lower in moderate_policies:
            findings.append({
                'severity': 'Info',
                'title': 'Moderate Referrer Policy',
                'description': f'Referrer-Policy set to moderate value: {rp_header}'
            })
        elif rp_lower in ['unsafe-url', 'no-referrer-when-downgrade']:
            findings.append({
                'severity': 'Low',
                'title': 'Weak Referrer Policy',
                'description': f'Referrer-Policy may leak information: {rp_header}'
            })
        else:
            findings.append({
                'severity': 'Low',
                'title': 'Unknown Referrer Policy',
                'description': f'Referrer-Policy has unknown value: {rp_header}'
            })

        return findings

    def check_permissions_policy(self, headers):
        """Analyze Permissions-Policy header"""
        findings = []

        pp_header = headers.get('Permissions-Policy')

        # Also check for deprecated Feature-Policy
        fp_header = headers.get('Feature-Policy')

        if pp_header:
            findings.append({
                'severity': 'Info',
                'title': 'Permissions Policy Present',
                'description': 'Permissions-Policy header found (modern standard)'
            })

            # Check for commonly restricted features
            pp_lower = pp_header.lower()
            restricted_features = []

            if 'camera=()' in pp_lower:
                restricted_features.append('camera')
            if 'microphone=()' in pp_lower:
                restricted_features.append('microphone')
            if 'geolocation=()' in pp_lower:
                restricted_features.append('geolocation')

            if restricted_features:
                findings.append({
                    'severity': 'Info',
                    'title': 'Feature Restrictions Active',
                    'description': f'Permissions Policy restricts: {", ".join(restricted_features)}'
                })

        elif fp_header:
            findings.append({
                'severity': 'Low',
                'title': 'Deprecated Feature Policy',
                'description': 'Feature-Policy header found (deprecated, use Permissions-Policy)'
            })

        else:
            findings.append({
                'severity': 'Info',
                'title': 'No Permissions Policy',
                'description': 'No Permissions-Policy header found (optional but recommended)'
            })

        return findings

    def check_other_headers(self, headers):
        """Check for other security-related headers"""
        findings = []

        # Cross-Origin-Embedder-Policy
        coep_header = headers.get('Cross-Origin-Embedder-Policy')
        if coep_header:
            findings.append({
                'severity': 'Info',
                'title': 'Cross-Origin Embedder Policy',
                'description': f'COEP header present: {coep_header}'
            })

        # Cross-Origin-Opener-Policy
        coop_header = headers.get('Cross-Origin-Opener-Policy')
        if coop_header:
            findings.append({
                'severity': 'Info',
                'title': 'Cross-Origin Opener Policy',
                'description': f'COOP header present: {coop_header}'
            })

        # Cross-Origin-Resource-Policy
        corp_header = headers.get('Cross-Origin-Resource-Policy')
        if corp_header:
            findings.append({
                'severity': 'Info',
                'title': 'Cross-Origin Resource Policy',
                'description': f'CORP header present: {corp_header}'
            })

        # Cache-Control for sensitive content
        cache_control = headers.get('Cache-Control')
        if cache_control:
            cc_lower = cache_control.lower()
            if 'no-store' in cc_lower or 'no-cache' in cc_lower:
                findings.append({
                    'severity': 'Info',
                    'title': 'Cache Control Protection',
                    'description': 'Cache-Control header prevents caching of sensitive data'
                })

        # Expect-CT (deprecated but still relevant)
        expect_ct = headers.get('Expect-CT')
        if expect_ct:
            findings.append({
                'severity': 'Info',
                'title': 'Certificate Transparency',
                'description': 'Expect-CT header present (deprecated but indicates CT awareness)'
            })

        return findings

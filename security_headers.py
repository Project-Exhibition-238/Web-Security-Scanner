import requests

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        headers = response.headers
        
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Feature-Policy'
        ]
        
        results = {}
        for header in security_headers:
            if header in headers:
                results[header] = {
                    'present': True,
                    'value': headers[header]
                }
            else:
                results[header] = {
                    'present': False,
                    'value': None
                }
        
        # Additional analysis
        results['analysis'] = analyze_header_security(headers)
        
        return results
        
    except requests.RequestException as e:
        return {'error': str(e)}

def analyze_header_security(headers):
    issues = []
    recommendations = []
    
    # HSTS analysis
    hsts = headers.get('Strict-Transport-Security', '')
    if not hsts:
        issues.append('Missing HSTS header')
        recommendations.append('Implement HSTS with appropriate max-age and includeSubDomains')
    elif 'max-age=0' in hsts:
        issues.append('HSTS set to max-age=0 (disabled)')
        recommendations.append('Set HSTS max-age to at least 31536000 (1 year)')
    
    # CSP analysis
    csp = headers.get('Content-Security-Policy', '')
    if not csp:
        issues.append('Missing Content Security Policy')
        recommendations.append('Implement a strong CSP to mitigate XSS attacks')
    elif 'unsafe-inline' in csp:
        issues.append('CSP allows unsafe-inline')
        recommendations.append('Avoid using unsafe-inline in CSP')
    
    # X-Frame-Options analysis
    xfo = headers.get('X-Frame-Options', '')
    if not xfo:
        issues.append('Missing X-Frame-Options header')
        recommendations.append('Implement X-Frame-Options to prevent clickjacking')
    
    return {
        'issues': issues,
        'recommendations': recommendations,
        'score': 100 - (len(issues) * 10)  # Simple scoring mechanism
    }
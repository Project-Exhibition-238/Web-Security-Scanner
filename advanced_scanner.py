import requests
from urllib.parse import urljoin, urlparse
import re

def advanced_security_scan(url):
    try:
        results = {
            'csrf_test': check_csrf_protection(url),
            'clickjacking_test': check_clickjacking_protection(url),
            'cors_test': check_cors_configuration(url),
            'http_methods_test': check_http_methods(url),
            'subdomain_enumeration': enumerate_subdomains(url)
        }
        
        return results
        
    except Exception as e:
        return {'error': str(e)}

def check_csrf_protection(url):
    try:
        response = requests.get(url, timeout=10)
        
        # Check for CSRF tokens in forms
        forms_without_csrf = []
        
        # Simple check for CSRF token in forms (this is a basic check)
        if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
            return {
                'status': 'Potential issue',
                'details': 'No obvious CSRF protection detected in forms'
            }
        
        return {
            'status': 'CSRF protection may be present',
            'details': 'CSRF tokens detected in page content'
        }
        
    except Exception as e:
        return {'error': str(e)}

def check_clickjacking_protection(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        # Check for clickjacking protection headers
        xfo = headers.get('X-Frame-Options', '').lower()
        csp = headers.get('Content-Security-Policy', '').lower()
        
        if not xfo and 'frame-ancestors' not in csp:
            return {
                'status': 'Vulnerable',
                'details': 'No clickjacking protection headers detected'
            }
        
        return {
            'status': 'Protected',
            'details': 'Clickjacking protection headers detected'
        }
        
    except Exception as e:
        return {'error': str(e)}

def check_cors_configuration(url):
    try:
        # Test CORS configuration by sending Origin header
        origin = 'https://malicious-site.com'
        response = requests.get(url, headers={'Origin': origin}, timeout=5)
        
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*' and acac == 'true':
            return {
                'status': 'Misconfigured',
                'details': 'CORS allows any origin with credentials'
            }
        elif acao == origin:
            return {
                'status': 'Misconfigured',
                'details': 'CORS reflects arbitrary origin'
            }
        
        return {
            'status': 'Secure',
            'details': 'No obvious CORS misconfiguration detected'
        }
        
    except Exception as e:
        return {'error': str(e)}

def check_http_methods(url):
    try:
        # Test for potentially dangerous HTTP methods
        methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        enabled_methods = []
        
        for method in methods:
            try:
                response = requests.request(method, url, timeout=5)
                if response.status_code != 405:  # 405 is Method Not Allowed
                    enabled_methods.append(method)
            except:
                pass
        
        if enabled_methods:
            return {
                'status': 'Potential issue',
                'details': f'Potentially dangerous HTTP methods enabled: {", ".join(enabled_methods)}'
            }
        
        return {
            'status': 'Secure',
            'details': 'No dangerous HTTP methods enabled'
        }
        
    except Exception as e:
        return {'error': str(e)}

def enumerate_subdomains(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Common subdomains to check
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns', 'mail2',
            'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
            'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
            'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'www3', 'search', 'staging',
            'server', 'ns3', 'mail1', 'live', 'ad', 'admanager', 'ads', 'admin', 'administrator',
            'app', 'apps', 'archive', 'auth', 'backup', 'backups', 'bastion', 'beta', 'blog',
            'cache', 'chat', 'client', 'clients', 'cloud', 'community', 'db', 'dev', 'developer',
            'drupal', 'forum', 'forums', 'git', 'help', 'host', 'hosting', 'image', 'images',
            'imap', 'irc', 'jabber', 'jira', 'ldap', 'lists', 'log', 'logs', 'm', 'mail',
            'manage', 'manager', 'marketing', 'mobile', 'mongodb', 'mysql', 'news', 'online',
            'owa', 'phone', 'photo', 'photos', 'phpmyadmin', 'pop', 'pop3', 'postgres',
            'private', 'proxy', 'public', 'remote', 'root', 'router', 'rss', 'sandbox',
            'server', 'service', 'shop', 'sql', 'ssh', 'ssl', 'status', 'store', 'support',
            'svn', 'sync', 'sysadmin', 'test', 'tomcat', 'vault', 'video', 'vpn', 'web',
            'webmail', 'webmaster', 'wordpress', 'www', 'xml', 'xmpp'
        ]
        
        found_subdomains = []
        
        # Check a subset of common subdomains (for performance)
        for subdomain in common_subdomains[:50]:  # Limit to 50 for performance
            test_url = f"http://{subdomain}.{domain}"
            try:
                response = requests.get(test_url, timeout=3, allow_redirects=False)
                if response.status_code < 400:
                    found_subdomains.append({
                        'subdomain': f"{subdomain}.{domain}",
                        'status': response.status_code
                    })
            except:
                pass
        
        return {
            'found': found_subdomains,
            'total_checked': 50
        }
        
    except Exception as e:
        return {'error': str(e)}
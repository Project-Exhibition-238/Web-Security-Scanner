import requests
from bs4 import BeautifulSoup, Comment
import re
import urllib.parse

class ContentAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Content Analysis)'
        })
        self.timeout = 10

    def scan(self, url):
        """Main content analysis method"""
        findings = []

        try:
            response = self.session.get(url, timeout=self.timeout)

            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Run content analysis checks
            findings.extend(self.analyze_html_comments(soup))
            findings.extend(self.analyze_forms(soup, url))
            findings.extend(self.analyze_scripts(soup))
            findings.extend(self.analyze_meta_information(soup))
            findings.extend(self.analyze_external_resources(soup, url))

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Content analysis error',
                'description': f'Error during content analysis: {str(e)}'
            })

        return findings

    def analyze_html_comments(self, soup):
        """Analyze HTML comments for sensitive information"""
        findings = []

        # Sensitive keywords to look for in comments
        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'api_key', 'apikey', 'api-key',
            'secret', 'token', 'auth', 'login', 'admin', 'username',
            'database', 'db_host', 'connection', 'config', 'configuration',
            'todo', 'fixme', 'hack', 'temporary', 'temp', 'debug',
            'development', 'staging', 'prod', 'production', 'env',
            'key', 'private', 'internal', 'hidden', 'confidential'
        ]

        try:
            # Find all HTML comments using BeautifulSoup's Comment type
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))

            sensitive_comments = []
            todo_comments = []
            total_comments = len(comments)

            for comment in comments:
                comment_text = comment.strip().lower()

                # Check for sensitive keywords
                found_keywords = [keyword for keyword in sensitive_keywords 
                                if keyword in comment_text]

                if found_keywords:
                    if any(kw in ['todo', 'fixme', 'hack', 'temporary', 'debug'] 
                          for kw in found_keywords):
                        todo_comments.append(comment.strip()[:100])
                    else:
                        sensitive_comments.append({
                            'comment': comment.strip()[:200],
                            'keywords': found_keywords
                        })

            # Report findings
            if sensitive_comments:
                findings.append({
                    'severity': 'Medium',
                    'title': 'Sensitive Information in Comments',
                    'description': f'Found {len(sensitive_comments)} HTML comments containing sensitive keywords. Example: "{sensitive_comments[0]["comment"][:100]}..."'
                })

            if todo_comments:
                findings.append({
                    'severity': 'Low',
                    'title': 'Development Comments Found',
                    'description': f'Found {len(todo_comments)} development-related comments (TODO, FIXME, etc.)'
                })

            if total_comments > 0 and not sensitive_comments and not todo_comments:
                findings.append({
                    'severity': 'Info',
                    'title': 'HTML Comments Present',
                    'description': f'Found {total_comments} HTML comments with no obvious sensitive content'
                })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Comment analysis error',
                'description': f'Could not analyze HTML comments: {str(e)}'
            })

        return findings

    def analyze_forms(self, soup, base_url):
        """Analyze forms for security issues"""
        findings = []

        try:
            forms = soup.find_all('form')

            if not forms:
                return findings

            insecure_forms = 0
            password_forms = 0

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()

                # Check if form submits over HTTP
                if action:
                    form_url = urllib.parse.urljoin(base_url, action)
                    if form_url.startswith('http://'):
                        insecure_forms += 1

                # Check for password fields
                password_inputs = form.find_all('input', {'type': 'password'})
                if password_inputs:
                    password_forms += 1

                # Check for file upload forms
                file_inputs = form.find_all('input', {'type': 'file'})
                if file_inputs:
                    enctype = form.get('enctype', '')
                    if enctype != 'multipart/form-data':
                        findings.append({
                            'severity': 'Low',
                            'title': 'File Upload Form Misconfiguration',
                            'description': 'File upload form found without proper enctype attribute'
                        })

            # Report form security issues
            if insecure_forms > 0:
                findings.append({
                    'severity': 'High',
                    'title': 'Forms Submit Over HTTP',
                    'description': f'{insecure_forms} forms submit data over unencrypted HTTP'
                })

            if password_forms > 0:
                findings.append({
                    'severity': 'Info',
                    'title': 'Password Forms Detected',
                    'description': f'Found {password_forms} forms with password fields'
                })

            findings.append({
                'severity': 'Info',
                'title': 'Forms Analysis Complete',
                'description': f'Analyzed {len(forms)} forms total'
            })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Form analysis error',
                'description': f'Could not analyze forms: {str(e)}'
            })

        return findings

    def analyze_scripts(self, soup):
        """Analyze JavaScript for potential issues"""
        findings = []

        try:
            # Find all script tags
            scripts = soup.find_all('script')

            inline_scripts = 0
            external_scripts = 0
            eval_usage = 0
            console_usage = 0

            for script in scripts:
                if script.get('src'):
                    external_scripts += 1
                elif script.string:
                    inline_scripts += 1
                    script_content = script.string.lower()

                    # Check for potentially dangerous functions
                    if 'eval(' in script_content:
                        eval_usage += 1

                    if 'console.' in script_content:
                        console_usage += 1

            # Report JavaScript findings
            if eval_usage > 0:
                findings.append({
                    'severity': 'Medium',
                    'title': 'JavaScript eval() Usage',
                    'description': f'Found {eval_usage} instances of eval() function usage, which can be dangerous'
                })

            if console_usage > 0:
                findings.append({
                    'severity': 'Low',
                    'title': 'Console Logging Detected',
                    'description': f'Found {console_usage} console logging statements that should be removed in production'
                })

            if inline_scripts > 5:
                findings.append({
                    'severity': 'Low',
                    'title': 'Many Inline Scripts',
                    'description': f'Found {inline_scripts} inline script blocks. Consider using external files for better CSP compliance'
                })

            findings.append({
                'severity': 'Info',
                'title': 'JavaScript Analysis Complete',
                'description': f'Analyzed {len(scripts)} script elements ({inline_scripts} inline, {external_scripts} external)'
            })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Script analysis error',
                'description': f'Could not analyze scripts: {str(e)}'
            })

        return findings

    def analyze_meta_information(self, soup):
        """Analyze meta tags for security and privacy implications"""
        findings = []

        try:
            # Find all meta tags
            meta_tags = soup.find_all('meta')

            generator_found = False
            viewport_found = False
            robots_found = False

            for meta in meta_tags:
                name = meta.get('name', '').lower()
                content = meta.get('content', '')

                # Check for generator meta tag
                if name == 'generator':
                    generator_found = True
                    findings.append({
                        'severity': 'Low',
                        'title': 'Generator Information Disclosed',
                        'description': f'Meta generator tag reveals technology: {content}'
                    })

                # Check for viewport meta tag
                elif name == 'viewport':
                    viewport_found = True

                # Check for robots meta tag
                elif name == 'robots':
                    robots_found = True
                    if 'noindex' in content.lower():
                        findings.append({
                            'severity': 'Info',
                            'title': 'Search Engine Indexing Disabled',
                            'description': 'Page has robots noindex directive'
                        })

            # Check for missing important meta tags
            if not viewport_found:
                findings.append({
                    'severity': 'Low',
                    'title': 'Missing Viewport Meta Tag',
                    'description': 'No viewport meta tag found - may affect mobile compatibility'
                })

            findings.append({
                'severity': 'Info',
                'title': 'Meta Analysis Complete',
                'description': f'Analyzed {len(meta_tags)} meta tags'
            })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'Meta analysis error',
                'description': f'Could not analyze meta tags: {str(e)}'
            })

        return findings

    def analyze_external_resources(self, soup, base_url):
        """Analyze external resources and links"""
        findings = []

        try:
            # Find external resources
            external_resources = []

            # Check stylesheets
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href', '')
                if href and (href.startswith('http://') or href.startswith('https://')):
                    external_resources.append(('CSS', href))

            # Check scripts
            for script in soup.find_all('script', src=True):
                src = script.get('src', '')
                if src and (src.startswith('http://') or src.startswith('https://')):
                    external_resources.append(('JavaScript', src))

            # Check images
            for img in soup.find_all('img', src=True):
                src = img.get('src', '')
                if src and (src.startswith('http://') or src.startswith('https://')):
                    external_resources.append(('Image', src))

            # Analyze external domains
            external_domains = set()
            http_resources = 0

            for resource_type, url in external_resources:
                parsed = urllib.parse.urlparse(url)
                external_domains.add(parsed.netloc)

                if url.startswith('http://'):
                    http_resources += 1

            # Report findings
            if http_resources > 0:
                findings.append({
                    'severity': 'Medium',
                    'title': 'Insecure External Resources',
                    'description': f'Found {http_resources} external resources loaded over HTTP'
                })

            if len(external_domains) > 10:
                findings.append({
                    'severity': 'Low',
                    'title': 'Many External Domains',
                    'description': f'Page loads resources from {len(external_domains)} external domains'
                })

            # Check for common CDNs
            common_cdns = ['googleapis.com', 'cdnjs.com', 'jsdelivr.net', 'unpkg.com']
            cdn_usage = [domain for domain in external_domains 
                        if any(cdn in domain for cdn in common_cdns)]

            if cdn_usage:
                findings.append({
                    'severity': 'Info',
                    'title': 'CDN Usage Detected',
                    'description': f'Using resources from CDNs: {", ".join(cdn_usage[:3])}'
                })

            findings.append({
                'severity': 'Info',
                'title': 'External Resources Analysis',
                'description': f'Found {len(external_resources)} external resources from {len(external_domains)} domains'
            })

        except Exception as e:
            findings.append({
                'severity': 'Info',
                'title': 'External resources analysis error',
                'description': f'Could not analyze external resources: {str(e)}'
            })

        return findings

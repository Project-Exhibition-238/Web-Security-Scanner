import requests
from bs4 import BeautifulSoup
import re

def analyze_content(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        results = {
            'forms': analyze_forms(soup),
            'scripts': analyze_scripts(soup),
            'comments': analyze_comments(soup),
            'meta_tags': analyze_meta_tags(soup),
            'inputs': analyze_inputs(soup)
        }
        
        return results
        
    except Exception as e:
        return {'error': str(e)}

def analyze_forms(soup):
    forms = soup.find_all('form')
    form_analysis = []
    
    for form in forms:
        form_info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        # Check form inputs
        inputs = form.find_all('input')
        for input_tag in inputs:
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name', '')
            
            form_info['inputs'].append({
                'type': input_type,
                'name': input_name
            })
        
        # Check for potential issues
        issues = []
        if form_info['method'] == 'get':
            issues.append('Form uses GET method - parameters will be exposed in URL')
        
        if not form_info['action']:
            issues.append('Form has no action attribute - may submit to same page')
        
        form_info['issues'] = issues
        form_analysis.append(form_info)
    
    return form_analysis

def analyze_scripts(soup):
    scripts = soup.find_all('script')
    script_analysis = []
    
    for script in scripts:
        script_src = script.get('src', '')
        script_type = script.get('type', '')
        
        script_info = {
            'src': script_src,
            'type': script_type,
            'external': bool(script_src),
            'inline': not bool(script_src) and script.string is not None
        }
        
        # Check for potential issues
        issues = []
        if script_src and not script_src.startswith(('http', 'https', '//')):
            issues.append('Relative script source - may be vulnerable to path manipulation')
        
        if not script_src and script.string and len(script.string) > 1000:
            issues.append('Large inline script - consider externalizing')
        
        script_info['issues'] = issues
        script_analysis.append(script_info)
    
    return script_analysis

def analyze_comments(soup):
    comments = soup.findAll(text=lambda text: isinstance(text, str) and '<!--' in text and '-->' in text)
    
    sensitive_patterns = [
        r'TODO', r'FIXME', r'TODO', r'DEBUG', r'TEMP',
        r'password', r'key', r'secret', r'token', r'api',
        r'admin', r'backdoor', r'hack', r'fixme'
    ]
    
    sensitive_comments = []
    
    for comment in comments:
        for pattern in sensitive_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                sensitive_comments.append(comment.strip())
                break
    
    return sensitive_comments

def analyze_meta_tags(soup):
    meta_tags = soup.find_all('meta')
    meta_analysis = []
    
    for meta in meta_tags:
        name = meta.get('name', meta.get('property', ''))
        content = meta.get('content', '')
        
        if name:
            meta_analysis.append({
                'name': name,
                'content': content
            })
    
    return meta_analysis

def analyze_inputs(soup):
    inputs = soup.find_all('input')
    input_analysis = []
    
    for input_tag in inputs:
        input_type = input_tag.get('type', 'text')
        input_name = input_tag.get('name', '')
        input_id = input_tag.get('id', '')
        input_class = input_tag.get('class', [])
        
        # Check for potential issues
        issues = []
        if not input_name and input_type != 'submit':
            issues.append('Input without name attribute')
        
        if input_type == 'password' and 'autocomplete' not in input_tag.attrs:
            issues.append('Password input without autocomplete=off')
        
        input_analysis.append({
            'type': input_type,
            'name': input_name,
            'id': input_id,
            'class': input_class,
            'issues': issues
        })
    
    return input_analysis
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from security_headers import check_security_headers
from tls_analyzer import check_tls_configuration
from vulnerability_checks import check_vulnerabilities
from content_analyzer import analyze_content
from port_scanner import scan_ports
from advanced_scanner import advanced_security_scan

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_website():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Run all security checks
        results = {
            'security_headers': check_security_headers(url),
            'tls_configuration': check_tls_configuration(url),
            'vulnerabilities': check_vulnerabilities(url),
            'content_analysis': analyze_content(url),
            'port_scan': scan_ports(url),
            'advanced_scan': advanced_security_scan(url)
        }
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
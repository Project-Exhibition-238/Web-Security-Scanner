from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from celery.result import AsyncResult
from tasks import run_full_scan, celery_app
import os

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Configure Celery
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

@app.route('/')
def index():
    """Serve the main interface"""
    return send_from_directory('static', 'index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        data = request.get_json()
        url = data.get('url')
        options = data.get('options', [])

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400

        # Start the scan task
        task = run_full_scan.apply_async(args=[url, options])

        return jsonify({
            'task_id': task.id,
            'status': 'started',
            'message': 'Scan initiated successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    """Get the status of a running scan"""
    try:
        task_result = AsyncResult(task_id, app=celery_app)

        if task_result.state == 'PENDING':
            response = {
                'state': 'PENDING',
                'progress': 0,
                'current': 'Initializing scan...',
                'result': None
            }
        elif task_result.state == 'PROGRESS':
            response = {
                'state': 'PROGRESS',
                'progress': task_result.info.get('progress', 0),
                'current': task_result.info.get('current', ''),
                'result': None
            }
        elif task_result.state == 'SUCCESS':
            response = {
                'state': 'SUCCESS',
                'progress': 100,
                'current': 'Scan completed',
                'result': task_result.result
            }
        else:
            # Handle FAILURE or other states
            response = {
                'state': task_result.state,
                'progress': 0,
                'current': 'Scan failed',
                'result': str(task_result.info) if task_result.info else 'Unknown error'
            }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'Web Security Scanner'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

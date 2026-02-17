import os
import json
import time
import threading
import queue
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import google.generativeai as genai
from dotenv import load_dotenv
from scanner_core import Scanner, get_public_ip

# Load environment variables
load_dotenv()

application = Flask(__name__)
application.config['API_KEY'] = os.getenv("API_KEY", "") # Load from .env

# Configure Gemini
genai.configure(api_key=application.config['API_KEY'])
model = genai.GenerativeModel('models/gemini-2.5-flash')

class ScanManager:
    def __init__(self):
        self.scanner = None
        self.results = []
        self.status = "Ready"
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.public_ip = "Loading..."

    def start_scan(self, target, config):
        with self.lock:
            if self.status == "Scanning":
                return False, "Scan already in progress"
            
            self.results = []
            self.status = "Scanning"
            self.stop_event.clear()
            self.public_ip = "Resolving..."
            
            # Start IP check
            threading.Thread(target=self._resolve_ip).start()

            self.scanner = Scanner(target, config, callback=self.add_result)
            t = threading.Thread(target=self._run_scan, daemon=True)
            t.start()
            return True, "Scan started"

    def stop_scan(self):
        with self.lock:
            if self.scanner:
                self.scanner.stop()
            self.status = "Stopped"
            return True, "Scan stopped"

    def _run_scan(self):
        if self.scanner:
            self.scanner.run()
        with self.lock:
            self.status = "Completed"

    def _resolve_ip(self):
        ip = get_public_ip()
        with self.lock:
            self.public_ip = ip

    def add_result(self, result):
        self.results.append(result)

    def get_results(self):
        return self.results

manager = ScanManager()

@application.route('/')
def index():
    return render_template('index.html', default_key=application.config['API_KEY'])

@application.route('/api/start', methods=['POST'])
def api_start():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    # Update API key if provided
    user_key = data.get('api_key')
    if user_key:
        genai.configure(api_key=user_key)
    
    config = {
        "threads": int(data.get('threads', 10)),
        "rate_delay": float(data.get('rate', 0.1)),
        "verify_ssl": data.get('verify_ssl', True),
        "headers_only": data.get('headers_only', False)
    }
    
    success, msg = manager.start_scan(target, config)
    if success:
        return jsonify({"message": msg}), 200
    else:
        return jsonify({"error": msg}), 409

@application.route('/api/stop', methods=['POST'])
def api_stop():
    manager.stop_scan()
    return jsonify({"message": "Stopped"}), 200

@application.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json
    finding = data.get('finding')
    detail = data.get('detail')
    
    prompt = f"""
    As a cybersecurity expert, analyze this finding:
    Type: {finding}
    Detail: {detail}
    
    1. What is the severity and why?
    2. How can this theoretically be exploited? (Educational purposes only)
    3. How to fix it?
    
    Keep it concise (under 200 words).
    """
    
    try:
        response = model.generate_content(prompt)
        return jsonify({"analysis": response.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@application.route('/api/stream')
def stream():
    def event_stream():
        last_idx = 0
        while True:
            current_len = len(manager.results)
            if current_len > last_idx:
                new_batch = manager.results[last_idx:current_len]
                last_idx = current_len
                yield f"data: {json.dumps({'type': 'results', 'data': new_batch})}\n\n"
            
            # Send status/IP updates periodically
            status_update = {
                "type": "status",
                "status": manager.status,
                "ip": manager.public_ip,
                "total": len(manager.results)
            }
            yield f"data: {json.dumps(status_update)}\n\n"
            
            if manager.status in ["Completed", "Stopped"] and last_idx >= len(manager.results):
                break
            time.sleep(0.5)

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

if __name__ == "__main__":
    application.run(debug=True, port=5000)

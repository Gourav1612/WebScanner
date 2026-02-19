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

# API Key Rotation Configuration
ALL_KEYS = [
    os.getenv("API_KEY"),
    os.getenv("API_KEY1"),
    os.getenv("API_KEY2"),
    os.getenv("API_KEY3"),
    os.getenv("API_KEY4"),
    os.getenv("API_KEY5"),
    os.getenv("API_KEY6")
]
# Filter out empty keys
API_KEYS = [k for k in ALL_KEYS if k and k.strip() and "your_key" not in k]
print(f"--- [SYSTEM] Loaded {len(API_KEYS)} API Keys from .env ---")
for i, k in enumerate(API_KEYS):
    print(f"Key {i}: {k[:5]}...{k[-4:]}")

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
    current_key = API_KEYS[current_key_index] if API_KEYS else ""
    return render_template('index.html', default_key=current_key)

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

# Using the specific model requested by the user for maximum speed and compatibility
SAFE_MODELS = ['models/gemini-2.5-flash']
current_model_index = 0
current_key_index = 0
requests_made = 0

def configure_genai(key_idx=None, model_idx=None):
    global current_key_index, model, requests_made, current_model_index
    
    if key_idx is not None: current_key_index = key_idx
    if model_idx is not None: current_model_index = model_idx
    
    if not API_KEYS:
        print("Warning: No valid API keys found!")
        return
    
    key = API_KEYS[current_key_index]
    model_name = SAFE_MODELS[current_model_index]
    
    genai.configure(api_key=key)
    model = genai.GenerativeModel(model_name)
    print(f"--- [CONFIG] Key {current_key_index + 1} | Model: {model_name} ---")

# Initial setup
if API_KEYS:
    configure_genai(0, 0)

@application.route('/api/analyze', methods=['POST'])
def api_analyze():
    global current_key_index, requests_made, model, current_model_index
    data = request.json
    finding = data.get('finding')
    detail = data.get('detail')
    
    if not API_KEYS:
        return jsonify({"error": "No API keys found. Please check your .env file."}), 500

    # Professional prompt with more sections
    fast_prompt = f"Analyze vulnerability: {finding} ({detail}). Respond in markdown with headers: 1. Severity & Risk Rating, 2. Exploit Summary, 3. Business Impact, 4. Remediation Steps. Concise but professional, max 250 words."
    
    failure_reasons = []
    
    # We will try up to 7 keys
    for _ in range(len(API_KEYS)):
        # 1. 10-Request Rotation Logic
        if requests_made >= 10:
            current_key_index = (current_key_index + 1) % len(API_KEYS)
            requests_made = 0
            configure_genai()

        # 2. Try models starting from last working model to save time
        # We start the loop from current_model_index
        for m_offset in range(len(SAFE_MODELS)):
            m_idx = (current_model_index + m_offset) % len(SAFE_MODELS)
            model_name = SAFE_MODELS[m_idx]
            
            try:
                # If model name changed within the loop, update the model object
                temp_model = model if m_idx == current_model_index else genai.GenerativeModel(model_name)
                
                response = temp_model.generate_content(fast_prompt)
                
                # SUCCESS! Update global "Stable Pointers"
                requests_made += 1
                if current_model_index != m_idx:
                    current_model_index = m_idx
                    model = temp_model # Sync global model
                
                return jsonify({"analysis": response.text})
            
            except Exception as e:
                err_msg = str(e).lower()
                
                # CRITICAL: If the error is about the API KEY itself (400, auth, invalid), 
                # we MUST rotate the key immediately even if it contains "not found".
                if any(x in err_msg for x in ["429", "exhausted", "limit", "400", "invalid", "403", "permission", "api key"]):
                    reason = f"Key {current_key_index} Failed ({err_msg[:40]})"
                    print(f"--- [KEY FAIL] {reason}. Rotating... ---")
                    failure_reasons.append(reason)
                    
                    current_key_index = (current_key_index + 1) % len(API_KEYS)
                    requests_made = 0
                    configure_genai()
                    break # Break model loop to try next key

                # If it's a model-specific error (and NOT a key error), try next model
                if any(x in err_msg for x in ["404", "not found", "enabled", "supported"]):
                    print(f"--- [MODEL FAIL] Model {model_name} not available on Key {current_key_index}. Trying next... ---")
                    continue
                
                # For any other failure, try next key just in case
                reason = f"Unexpected Error on Key {current_key_index}: {err_msg[:60]}"
                failure_reasons.append(reason)
                current_key_index = (current_key_index + 1) % len(API_KEYS)
                requests_made = 0
                configure_genai()
                break
        
    return jsonify({
        "error": "All keys/models failed. Check console for details.",
        "details": failure_reasons
    }), 429

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

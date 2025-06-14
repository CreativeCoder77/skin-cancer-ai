import os
import warnings
import logging
import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, request, render_template, jsonify, abort, send_from_directory
from werkzeug.utils import secure_filename
import base64
from functools import wraps
import pytz

# Suppress TensorFlow logs and warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
warnings.filterwarnings('ignore')
logging.getLogger('tensorflow').setLevel(logging.ERROR)

from keras.models import load_model
from PIL import Image, ImageOps
import numpy as np
import tensorflow as tf

# Disable scientific notation for clarity
np.set_printoptions(suppress=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

# Security and Monitoring Configuration
DDOS_THRESHOLD = 200           # requests per minute from single IP (50 req/sec) – likely botnet-level
SUSPICIOUS_THRESHOLD = 200      # suspicious requests per minute from single IP (3–4 per second)
RATE_LIMIT_WINDOW = 60          # seconds
MAX_REQUESTS_PER_WINDOW = 60    # max normal requests per IP per minute (1 request/sec)

# JSON file paths for persistent storage
BLOCKED_IPS_FILE = 'blocked_ips.json'
WHITELISTED_IPS_FILE = 'whitelisted_ips.json'
ACCESS_LOG_FILE = "access_log.json"

server_closed = False


# Global monitoring variables
class ServerMonitor:
    def __init__(self):
        self.request_count = 0
        self.error_count = 0
        self.prediction_count = 0
        self.start_time = time.time()
        
        # Request tracking for security
        self.ip_requests = defaultdict(deque)  # IP -> timestamps
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.whitelisted_ips = set()  # NEW: Whitelisted IPs
        
        # NEW: Store detailed block information
        self.blocked_ips_details = {}  # IP -> {reason, blocked_at, block_type, auto_block_trigger}
        
        # Load persistent data
        self.load_blocked_ips()
        self.load_whitelisted_ips()
        
        # NEW: Track active IPs with additional info
        self.active_ips = {}  # IP -> {last_seen, request_count, user_agent, first_seen}
        
        # Real-time metrics (last 60 data points for charts)
        self.requests_per_second = deque(maxlen=60)
        self.errors_per_second = deque(maxlen=60)
        self.response_times = deque(maxlen=100)
        
        # Threat detection
        self.security_events = deque(maxlen=100)
        
        # Initialize with zeros
        for i in range(60):
            self.requests_per_second.append(0)
            self.errors_per_second.append(0)
        
        # Start monitoring thread
        self.start_monitoring()
    
    def load_blocked_ips(self):
        """Load blocked IPs from JSON file"""
        try:
            if os.path.exists(BLOCKED_IPS_FILE):
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    data = json.load(f)
                    # Convert list back to set and load with metadata
                    for ip_data in data.get('blocked_ips', []):
                        if isinstance(ip_data, dict):
                            ip = ip_data['ip']
                            self.blocked_ips.add(ip)
                            # Store detailed information
                            self.blocked_ips_details[ip] = {
                                'reason': ip_data.get('reason', 'Unknown'),
                                'blocked_at': ip_data.get('blocked_at', datetime.now().isoformat()),
                                'block_type': ip_data.get('block_type', 'manual'),
                                'auto_block_trigger': ip_data.get('auto_block_trigger', None),
                                'request_count_at_block': ip_data.get('request_count_at_block', 0),
                                'detection_method': ip_data.get('detection_method', 'manual')
                            }
                        else:
                            # Handle old format (just IP strings)
                            self.blocked_ips.add(ip_data)
                            self.blocked_ips_details[ip_data] = {
                                'reason': 'Legacy block (no details available)',
                                'blocked_at': datetime.now().isoformat(),
                                'block_type': 'legacy',
                                'auto_block_trigger': None,
                                'request_count_at_block': 0,
                                'detection_method': 'legacy'
                            }
                print(f"Loaded {len(self.blocked_ips)} blocked IPs from file")
            else:
                print("No blocked IPs file found, starting with empty list")
        except Exception as e:
            print(f"Error loading blocked IPs: {e}")
            self.blocked_ips = set()
            self.blocked_ips_details = {}
    
    def save_blocked_ips(self):
        """Save blocked IPs to JSON file with detailed information"""
        try:
            # Create data structure with detailed metadata
            blocked_data = []
            for ip in self.blocked_ips:
                ip_details = self.blocked_ips_details.get(ip, {})
                blocked_data.append({
                    'ip': ip,
                    'blocked_at': ip_details.get('blocked_at', datetime.now().isoformat()),
                    'reason': ip_details.get('reason', 'Unknown'),
                    'block_type': ip_details.get('block_type', 'manual'),
                    'auto_block_trigger': ip_details.get('auto_block_trigger', None),
                    'request_count_at_block': ip_details.get('request_count_at_block', 0),
                    'detection_method': ip_details.get('detection_method', 'manual')
                })
            
            data = {
                'blocked_ips': blocked_data,
                'last_updated': datetime.now().isoformat(),
                'total_blocked_count': len(self.blocked_ips),
                'auto_blocks': len([ip for ip in self.blocked_ips if self.blocked_ips_details.get(ip, {}).get('block_type') == 'auto']),
                'manual_blocks': len([ip for ip in self.blocked_ips if self.blocked_ips_details.get(ip, {}).get('block_type') == 'manual'])
            }
            
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Saved {len(self.blocked_ips)} blocked IPs to file")
        except Exception as e:
            print(f"Error saving blocked IPs: {e}")
    
    def load_whitelisted_ips(self):
        """Load whitelisted IPs from JSON file"""
        try:
            if os.path.exists(WHITELISTED_IPS_FILE):
                with open(WHITELISTED_IPS_FILE, 'r') as f:
                    data = json.load(f)
                    # Convert list back to set
                    for ip_data in data.get('whitelisted_ips', []):
                        if isinstance(ip_data, dict):
                            self.whitelisted_ips.add(ip_data['ip'])
                        else:
                            # Handle old format (just IP strings)
                            self.whitelisted_ips.add(ip_data)
                print(f"Loaded {len(self.whitelisted_ips)} whitelisted IPs from file")
            else:
                print("No whitelisted IPs file found, starting with empty list")
        except Exception as e:
            print(f"Error loading whitelisted IPs: {e}")
            self.whitelisted_ips = set()
    
    def save_whitelisted_ips(self):
        """Save whitelisted IPs to JSON file"""
        try:
            # Create data structure with metadata
            whitelisted_data = []
            for ip in self.whitelisted_ips:
                whitelisted_data.append({
                    'ip': ip,
                    'whitelisted_at': datetime.now().isoformat(),
                    'reason': 'Trusted IP - bypass all security checks'
                })
            
            data = {
                'whitelisted_ips': whitelisted_data,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(WHITELISTED_IPS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Saved {len(self.whitelisted_ips)} whitelisted IPs to file")
        except Exception as e:
            print(f"Error saving whitelisted IPs: {e}")
    
    def add_blocked_ip(self, ip, reason="Manual block", block_type="manual", auto_block_trigger=None):
        """Add IP to blocked list with detailed reason and type"""
        if ip not in self.whitelisted_ips:  # Don't block whitelisted IPs
            self.blocked_ips.add(ip)
            
            # Store detailed information about the block
            current_request_count = len(self.ip_requests.get(ip, []))
            
            self.blocked_ips_details[ip] = {
                'reason': reason,
                'blocked_at': datetime.now().isoformat(),
                'block_type': block_type,  # 'auto' or 'manual'
                'auto_block_trigger': auto_block_trigger,  # e.g., 'ddos_detection', 'rate_limit_exceeded'
                'request_count_at_block': current_request_count,
                'detection_method': self._get_detection_method(block_type, auto_block_trigger)
            }
            
            self.save_blocked_ips()
            self.log_security_event("IP_BLOCKED", ip, f"{block_type.upper()}: {reason}")
            return True
        else:
            self.log_security_event("BLOCK_ATTEMPT_WHITELISTED", ip, f"Attempt to block whitelisted IP: {reason}")
            return False
    
    def _get_detection_method(self, block_type, auto_block_trigger):
        """Get human-readable detection method"""
        if block_type == "auto":
            if auto_block_trigger == "ddos_detection":
                return "Automated DDoS Detection"
            elif auto_block_trigger == "rate_limit_exceeded":
                return "Rate Limit Violation"
            elif auto_block_trigger == "suspicious_activity":
                return "Suspicious Activity Pattern"
            else:
                return "Automated Security System"
        else:
            return "Manual Block via Dashboard"
    
    def remove_blocked_ip(self, ip):
        """Remove IP from blocked list and save to file"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            # Remove detailed information
            if ip in self.blocked_ips_details:
                del self.blocked_ips_details[ip]
            self.save_blocked_ips()
            self.log_security_event("IP_UNBLOCKED", ip, "Manually unblocked")
            return True
        return False
    
    def add_whitelisted_ip(self, ip, reason="Manual whitelist"):
        """Add IP to whitelist and save to file"""
        self.whitelisted_ips.add(ip)
        # If IP was blocked, remove it from blocked list
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            if ip in self.blocked_ips_details:
                del self.blocked_ips_details[ip]
            self.save_blocked_ips()
        self.save_whitelisted_ips()
        self.log_security_event("IP_WHITELISTED", ip, reason)
        return True
    
    def remove_whitelisted_ip(self, ip):
        """Remove IP from whitelist and save to file"""
        if ip in self.whitelisted_ips:
            self.whitelisted_ips.remove(ip)
            self.save_whitelisted_ips()
            self.log_security_event("IP_REMOVED_FROM_WHITELIST", ip, "Manually removed from whitelist")
            return True
        return False
    
    def is_ip_whitelisted(self, ip):
        """Check if IP is whitelisted"""
        return ip in self.whitelisted_ips
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        def monitor():
            while True:
                time.sleep(1)  # Update every second
                self.update_metrics()
                self.check_security_threats()
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def update_metrics(self):
        """Update real-time metrics"""
        current_time = time.time()
        
        # Count requests in last second
        recent_requests = 0
        recent_errors = 0
        
        # Clean old data and count recent activity
        for ip, timestamps in self.ip_requests.items():
            # Remove old timestamps
            while timestamps and current_time - timestamps[0] > RATE_LIMIT_WINDOW:
                timestamps.popleft()
            
            # Count requests in last second
            recent_count = sum(1 for t in timestamps if current_time - t <= 1)
            recent_requests += recent_count
        
        self.requests_per_second.append(recent_requests)
        self.errors_per_second.append(recent_errors)  # Will be updated by error handler
    
    def log_request(self, ip, endpoint, user_agent):
        """Log incoming request"""
        current_time = time.time()
        self.request_count += 1
        
        # Track IP requests
        self.ip_requests[ip].append(current_time)
        
        # NEW: Track active IPs with detailed info
        if ip not in self.active_ips:
            self.active_ips[ip] = {
                'first_seen': datetime.now().isoformat(),
                'request_count': 0,
                'last_endpoint': endpoint,
                'user_agent': user_agent or 'Unknown'
            }
        
        # Update IP info
        self.active_ips[ip].update({
            'last_seen': datetime.now().isoformat(),
            'request_count': self.active_ips[ip]['request_count'] + 1,
            'last_endpoint': endpoint,
            'user_agent': user_agent or 'Unknown'
        })
        
        # Check for suspicious activity (only for non-whitelisted IPs)
        if not self.is_ip_whitelisted(ip):
            if len(self.ip_requests[ip]) > DDOS_THRESHOLD:
                if ip not in self.suspicious_ips:
                    self.suspicious_ips.add(ip)
                    self.log_security_event("DDoS_DETECTED", ip, f"Exceeded {DDOS_THRESHOLD} requests")
                    # Auto-block DDoS IPs with specific reason
                    self.add_blocked_ip(
                        ip, 
                        f"Automated DDoS Protection - {DDOS_THRESHOLD}+ requests in {RATE_LIMIT_WINDOW} seconds", 
                        block_type="auto", 
                        auto_block_trigger="ddos_detection"
                    )

    def log_error(self, ip, error_type, details):
        """Log error and update metrics"""
        self.error_count += 1
        self.log_security_event(error_type, ip, details)
    
    def log_security_event(self, event_type, ip, details):
        """Log security event"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'ip': ip,
            'details': details,
            'is_whitelisted': self.is_ip_whitelisted(ip)
        }
        self.security_events.append(event)
        print(f"SECURITY EVENT: {event_type} from {ip} - {details}")
    
    def check_security_threats(self):
        """Check for various security threats"""
        current_time = time.time()
        
        for ip, timestamps in self.ip_requests.items():
            # Skip whitelisted IPs
            if self.is_ip_whitelisted(ip):
                continue
                
            if len(timestamps) > SUSPICIOUS_THRESHOLD:
                if ip not in self.suspicious_ips:
                    self.suspicious_ips.add(ip)
                    self.log_security_event("SUSPICIOUS_ACTIVITY", ip, 
                                          f"High request rate: {len(timestamps)} requests")
                    # Auto-block for suspicious activity
                    self.add_blocked_ip(
                        ip, 
                        f"Automated Threat Detection - {len(timestamps)} requests in {RATE_LIMIT_WINDOW} seconds", 
                        block_type="auto", 
                        auto_block_trigger="suspicious_activity"
                    )
    
    def is_ip_blocked(self, ip):
        """Check if IP is blocked (whitelisted IPs are never blocked)"""
        if self.is_ip_whitelisted(ip):
            return False
        return ip in self.blocked_ips
    
    def get_blocked_ip_details(self, ip):
        """Get detailed information about a blocked IP"""
        return self.blocked_ips_details.get(ip, {})
    
    def get_stats(self):
        """Get current server statistics"""
        uptime = time.time() - self.start_time
        
        # NEW: Prepare active IPs data (limit to last 50 for performance)
        active_ips_list = []
        current_time = datetime.now()
        
        for ip, info in list(self.active_ips.items()):
            last_seen = datetime.fromisoformat(info['last_seen'])
            # Remove IPs not seen in last hour
            if (current_time - last_seen).total_seconds() > 3600:
                del self.active_ips[ip]
                continue
                
            active_ips_list.append({
                'ip': ip,
                'request_count': info['request_count'],
                'last_seen': info['last_seen'],
                'first_seen': info['first_seen'],
                'last_endpoint': info['last_endpoint'],
                'user_agent': info['user_agent'][:100],  # Truncate long user agents
                'is_suspicious': ip in self.suspicious_ips,
                'is_blocked': ip in self.blocked_ips,
                'is_whitelisted': ip in self.whitelisted_ips,
                'block_details': self.get_blocked_ip_details(ip) if ip in self.blocked_ips else None
            })
        
        # Sort by last seen (most recent first) and limit to 50
        active_ips_list.sort(key=lambda x: x['last_seen'], reverse=True)
        active_ips_list = active_ips_list[:50]
        
        # NEW: Prepare detailed blocked IPs list
        blocked_ips_detailed = []
        for ip in self.blocked_ips:
            ip_details = self.get_blocked_ip_details(ip)
            blocked_ips_detailed.append({
                'ip': ip,
                'reason': ip_details.get('reason', 'Unknown'),
                'blocked_at': ip_details.get('blocked_at', 'Unknown'),
                'block_type': ip_details.get('block_type', 'manual'),
                'auto_block_trigger': ip_details.get('auto_block_trigger', None),
                'request_count_at_block': ip_details.get('request_count_at_block', 0),
                'detection_method': ip_details.get('detection_method', 'Unknown')
            })
        
        return {
            'uptime': uptime,
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'total_predictions': self.prediction_count,
            'requests_per_second': list(self.requests_per_second),
            'errors_per_second': list(self.errors_per_second),
            'suspicious_ips_count': len(self.suspicious_ips),
            'blocked_ips_count': len(self.blocked_ips),
            'whitelisted_ips_count': len(self.whitelisted_ips),
            'recent_security_events': list(self.security_events)[-10:],  # Last 10 events
            'avg_response_time': sum(self.response_times) / len(self.response_times) if self.response_times else 0,
            'active_ips': active_ips_list,
            'unique_ips_count': len(self.active_ips),
            'blocked_ips_list': list(self.blocked_ips),  # Keep for backward compatibility
            'blocked_ips_detailed': blocked_ips_detailed,  # NEW: Detailed blocked IPs
            'whitelisted_ips_list': list(self.whitelisted_ips),
            'auto_blocks_count': len([ip for ip in self.blocked_ips if self.blocked_ips_details.get(ip, {}).get('block_type') == 'auto']),
            'manual_blocks_count': len([ip for ip in self.blocked_ips if self.blocked_ips_details.get(ip, {}).get('block_type') == 'manual'])
        }

# Initialize monitor
monitor = ServerMonitor()

@app.before_request
def check_server_status():
    global server_closed
    if server_closed:
        allowed_paths = ['/dashboard', '/toggle']
        if request.path.startswith('/static/') or request.path in allowed_paths:
            return  # allow
        return render_template("closed.html")

@app.route('/toggle', methods=['POST'])
def toggle():
    global server_closed
    server_closed = not server_closed
    return jsonify({
        "status": "⚠️ Server is CLOSED to all except /dashboard" if server_closed else "✅ Server is OPEN",
        "button": "Reopen Server" if server_closed else "Close Server"
    })


# Security decorator for rate limiting
def rate_limit(max_requests=MAX_REQUESTS_PER_WINDOW):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
            
            # Check if IP is whitelisted first (whitelisted IPs bypass all security)
            if monitor.is_ip_whitelisted(ip):
                monitor.log_request(ip, request.endpoint, request.headers.get('User-Agent', ''))
                start_time = time.time()
                result = f(*args, **kwargs)
                response_time = time.time() - start_time
                monitor.response_times.append(response_time)
                return result
            
            # Check if IP is blocked
            if monitor.is_ip_blocked(ip):
                monitor.log_error(ip, "BLOCKED_ACCESS", "Access denied for blocked IP")
                abort(403)
            
            # Log request
            monitor.log_request(ip, request.endpoint, request.headers.get('User-Agent', ''))
            
            # Check rate limit
            current_time = time.time()
            ip_requests = monitor.ip_requests[ip]
            
            # Count recent requests
            recent_requests = sum(1 for t in ip_requests if current_time - t <= RATE_LIMIT_WINDOW)
            
            if recent_requests > max_requests:
                monitor.log_error(ip, "RATE_LIMIT_EXCEEDED", f"Exceeded {max_requests} requests per minute")
                # Auto-block for rate limit exceeded
                monitor.add_blocked_ip(
                    ip, 
                    f"Rate Limit Exceeded - {recent_requests} requests in {RATE_LIMIT_WINDOW} seconds", 
                    block_type="auto", 
                    auto_block_trigger="rate_limit_exceeded"
                )
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            start_time = time.time()
            result = f(*args, **kwargs)
            response_time = time.time() - start_time
            monitor.response_times.append(response_time)
            
            return result
        return decorated_function
    return decorator

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Custom function to handle the deprecated 'groups' parameter
def custom_depthwise_conv2d(*args, **kwargs):
    kwargs.pop('groups', None)
    return tf.keras.layers.DepthwiseConv2D(*args, **kwargs)

# Global variables for model, labels and condition details
model = None
class_names = None
condition_details = None

def load_condition_details():
    """Load the condition details from JSON file"""
    global condition_details
    try:
        with open("details.json", "r") as f:
            data = json.load(f)
            condition_details = {condition['name']: condition for condition in data['skin_conditions']}
        print("Condition details loaded successfully!")
        return True
    except FileNotFoundError:
        print("Error: details.json file not found!")
        return False
    except Exception as e:
        print(f"Error loading condition details: {e}")
        return False

def load_ml_model():
    """Load the machine learning model and labels"""
    global model, class_names
    
    custom_objects = {'DepthwiseConv2D': custom_depthwise_conv2d}
    
    try:
        model = load_model(r"Rash_Models\Rash_model.h5", compile=False, custom_objects=custom_objects)
        print("Model loaded successfully!")
    except Exception as e:
        print(f"Error loading model: {e}")
        return False
    
    try:
        class_names = open("Rash_Models/labels.txt", "r").readlines()
        print("Labels loaded successfully!")
    except FileNotFoundError:
        print("Error: labels.txt file not found!")
        return False
    
    return True

def get_condition_info(class_name):
    """Get detailed information about the detected condition"""
    if condition_details is None:
        return None
    
    # Clean the class name and try to find a match
    clean_name = class_name.strip()
    
    # Try exact match first
    if clean_name in condition_details:
        return condition_details[clean_name]
    
    # Try partial matching for common variations
    for condition_key in condition_details.keys():
        if clean_name.lower() in condition_key.lower() or condition_key.lower() in clean_name.lower():
            return condition_details[condition_key]
    
    return None

def predict_image(image_path):
    """Predict the class of an uploaded image and return all confidences"""
    try:
        # Open and convert image
        image = Image.open(image_path).convert("RGB")
        
        # Resize and crop image
        size = (224, 224)
        image = ImageOps.fit(image, size, Image.Resampling.LANCZOS)
        
        # Convert to numpy array
        image_array = np.asarray(image)
        
        # Normalize the image
        normalized_image_array = (image_array.astype(np.float32) / 127.5) - 1
        
        # Create data array
        data = np.ndarray(shape=(1, 224, 224, 3), dtype=np.float32)
        data[0] = normalized_image_array
        
        # Make prediction
        prediction = model.predict(data)
        index = np.argmax(prediction)
        top_class_name = class_names[index]
        top_confidence_score = prediction[0][index]
        
        # Get all class confidences
        all_confidences = []
        for i, confidence in enumerate(prediction[0]):
            class_name_clean = class_names[i][2:].strip() if class_names[i].startswith(('0 ', '1 ')) else class_names[i].strip()
            all_confidences.append({
                'class': class_name_clean,
                'confidence': float(confidence),
                'percentage': float(confidence * 100)
            })
        
        # Sort by confidence (highest to lowest)
        all_confidences.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Clean top class name
        clean_top_class_name = top_class_name[2:].strip() if top_class_name.startswith(('0 ', '1 ')) else top_class_name.strip()
        
        # Check if confidence is less than 30%
        if top_confidence_score < 0.30:
            return {
                'top_prediction': {
                    'class': 'Unknown',
                    'confidence': float(top_confidence_score),
                    'details': {
                        'name': 'Unknown Condition',
                        'causes': ['Insufficient confidence in prediction to determine specific condition'],
                        'potential_harms': ['Please consult a healthcare professional for proper diagnosis'],
                        'possible_progression': ['Medical evaluation recommended for accurate assessment']
                    }
                },
                'all_confidences': all_confidences
            }
        
        # Get detailed condition information
        condition_info = get_condition_info(clean_top_class_name)
        
        result = {
            'top_prediction': {
                'class': clean_top_class_name,
                'confidence': float(top_confidence_score)
            },
            'all_confidences': all_confidences
        }
        
        if condition_info:
            result['top_prediction']['details'] = condition_info
        
        return result
    
    except Exception as e:
        return {'error': str(e)}


# Routes with security monitoring
@app.route('/')
@rate_limit()
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Security and monitoring dashboard"""
    global server_closed  # Add this if 'server_closed' is used globally

    # Load whitelist
    try:
        with open(WHITELISTED_IPS_FILE, "r") as file:
            data = json.load(file)
        whitelist_entries = data.get("whitelisted_ips", [])
        whitelisted_ips = [entry["ip"] for entry in whitelist_entries]
    except Exception as e:
        print(f"[ERROR] Failed to load whitelist: {e}")
        whitelisted_ips = []

    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    access_granted = user_ip in whitelisted_ips

    # Get time info
    utc_now = datetime.utcnow()
    ist = pytz.timezone('Asia/Kolkata')
    ist_now = utc_now.replace(tzinfo=pytz.utc).astimezone(ist)
    hour_block = ist_now.strftime("%d-%m-%Y %H")
    formatted_time = ist_now.strftime("%d-%m-%Y %I:%M:%S %p IST")

    log_entry = {
        "ip": user_ip,
        "latest_access_time": formatted_time,
        "access_count": 1
    }

    # Log access
    try:
        if os.path.exists(ACCESS_LOG_FILE):
            with open(ACCESS_LOG_FILE, "r") as log_file:
                access_log = json.load(log_file)
        else:
            access_log = {}

        if hour_block not in access_log:
            access_log[hour_block] = []

        ip_found = False
        for entry in access_log[hour_block]:
            if entry["ip"] == user_ip:
                entry["access_count"] += 1
                entry["latest_access_time"] = formatted_time
                ip_found = True
                break

        if not ip_found:
            access_log[hour_block].append(log_entry)

        with open(ACCESS_LOG_FILE, "w") as log_file:
            json.dump(access_log, log_file, indent=2)

    except Exception as e:
        print(f"[ERROR] Failed to log access: {e}")

    # Serve dashboard
    if access_granted:
        try:
            with open(BLOCKED_IPS_FILE) as file:
                data = json.load(file)
            blocked_ips = data.get("blocked_ips", [])
        except Exception as e:
            print(f"[ERROR] Could not load blocked IPs: {e}")
            blocked_ips = []


        status_text = "⚠️ Server is CLOSED to all except /dashboard" if server_closed else "✅ Server is OPEN"
        button_text = "Reopen Server" if server_closed else "Close Server"

        return render_template('dashboard.html', blocked_ips=blocked_ips, status_text=status_text, button_text=button_text)
    else:
        return render_template('404.html'), 403



@app.route('/api/dashboard/stats')
def dashboard_stats():
    """API endpoint for dashboard statistics"""
    return jsonify(monitor.get_stats())

@app.route('/api/dashboard/block-ip', methods=['POST'])
def block_ip():
    """Block a suspicious IP address"""
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block via dashboard')
    
    if ip:
        success = monitor.add_blocked_ip(ip, reason)
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} blocked successfully'})
        else:
            return jsonify({'success': False, 'message': f'Cannot block whitelisted IP {ip}'}), 400
    return jsonify({'success': False, 'message': 'Invalid IP address'}), 400

@app.route('/api/dashboard/unblock-ip', methods=['POST'])
def unblock_ip():
    """Unblock an IP address"""
    data = request.get_json()
    ip = data.get('ip')
    
    if ip:
        success = monitor.remove_blocked_ip(ip)
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} unblocked successfully'})
        else:
            return jsonify({'success': False, 'message': 'IP not found in blocked list'}), 400
    return jsonify({'success': False, 'message': 'Invalid IP address'}), 400

@app.route('/api/dashboard/whitelist-ip', methods=['POST'])
def whitelist_ip():
    """Add IP to whitelist"""
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Manual whitelist via dashboard')
    
    if ip:
        success = monitor.add_whitelisted_ip(ip, reason)
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} whitelisted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to whitelist IP'}), 500
    return jsonify({'success': False, 'message': 'Invalid IP address'}), 400

@app.route('/api/dashboard/remove-whitelist-ip', methods=['POST'])
def remove_whitelist_ip():
    """Remove IP from whitelist"""
    data = request.get_json()
    ip = data.get('ip')
    
    if ip:
        success = monitor.remove_whitelisted_ip(ip)
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} removed from whitelist successfully'})
        else:
            return jsonify({'success': False, 'message': 'IP not found in whitelist'}), 400
    return jsonify({'success': False, 'message': 'Invalid IP address'}), 400

@app.route('/predict', methods=['POST'])
@rate_limit(max_requests=100)  
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    if file and allowed_file(file.filename):
        try:
            # Save uploaded file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Make prediction
            result = predict_image(filepath)
            monitor.prediction_count += 1
            
            # Convert image to base64 for display
            with open(filepath, "rb") as img_file:
                img_base64 = base64.b64encode(img_file.read()).decode('utf-8')
            
            # Clean up uploaded file
            os.remove(filepath)
            
            if 'error' in result:
                return jsonify({'error': result['error']})
            
            # Load classification details
            try:
                with open('details.json', 'r') as file:
                    data = json.load(file)

                predicted_class = result['top_prediction']['class']
                
                # Find matching classification - more robust matching
                classification_info = None
                for condition in data['skin_conditions']:
                    if condition['name'].lower() == predicted_class.lower():
                        classification_info = {
                            "classification": condition.get("classification", "Unknown"),
                            "name": condition['name']
                        }
                        break
                
                # If no exact match found, use default
                if not classification_info:
                    classification_info = {
                        "classification": "Unknown", 
                        "name": predicted_class
                    }
                    
            except Exception as e:
                print(f"Error loading classification: {e}")
                classification_info = {
                    "classification": "Unknown", 
                    "name": result['top_prediction']['class']
                }
            
            response_data = {
                'success': True,
                'top_prediction': result['top_prediction'],
                'all_confidences': result['all_confidences'],
                'image': img_base64,
                'classification': classification_info
            }
            
            return jsonify(response_data)
        except Exception as e:
            monitor.log_error(request.remote_addr, "PREDICTION_ERROR", str(e))
            return jsonify({'error': f'Error processing image: {str(e)}'})
    
    return jsonify({'error': 'Invalid file type. Please upload an image file.'})

@app.route('/api/random-images/<path:image_path>')
@rate_limit()
def get_random_images(image_path):
    import os
    import random
    
    try:
        # Construct the full path to the image directory
        full_path = os.path.join(image_path)
        
        print(f"Looking for images in: {full_path}")  # Debug print
        
        if os.path.exists(full_path) and os.path.isdir(full_path):
            all_images = [f for f in os.listdir(full_path) 
                         if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'))]
            
            print(f"Found {len(all_images)} images: {all_images[:5]}")  # Debug print
            
            if not all_images:
                return jsonify({'images': [], 'message': 'No images found in directory'})
            
            # Get 3-5 random images
            num_images = min(random.randint(3, 5), len(all_images))
            selected_images = random.sample(all_images, num_images)
            
            # Create proper URLs - Flask will serve static files from the static folder
            image_urls = []
            for img in selected_images:
                # Convert the path to web-accessible URL
                if image_path.startswith('static/'):
                    # Remove 'static/' prefix since Flask serves it automatically
                    web_path = image_path[7:] + '/' + img
                else:
                    web_path = image_path + '/' + img
                
                image_urls.append(f"/static/{web_path}")
            
            print(f"Generated URLs: {image_urls}")  # Debug print
            
            return jsonify({'images': image_urls})
        else:
            print(f"Directory does not exist: {full_path}")  # Debug print
            return jsonify({'images': [], 'error': f'Directory not found: {full_path}'})
            
    except Exception as e:
        print(f"Error in get_random_images: {str(e)}")  # Debug print
        monitor.log_error(request.remote_addr, "IMAGE_FETCH_ERROR", str(e))
        return jsonify({'error': str(e), 'images': []})

# Alternative route if you need to serve dataset files directly
@app.route('/dataset/<path:filename>')
@rate_limit()
def serve_dataset_file(filename):
    """Serve files from the dataset directory"""
    try:
        return send_from_directory('static/dataset', filename)
    except Exception as e:
        print(f"Error serving dataset file: {str(e)}")
        monitor.log_error(request.remote_addr, "FILE_SERVE_ERROR", str(e))
        abort(404)

@app.route('/disease/<string:disease_name>')
@rate_limit()
def disease(disease_name):
    # Read the JSON data from details.json
    try:
        with open('details.json', 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print("details.json file not found")
        monitor.log_error(request.remote_addr, "FILE_NOT_FOUND", "details.json missing")
        abort(404)
    except json.JSONDecodeError:
        print("Error parsing details.json")
        monitor.log_error(request.remote_addr, "JSON_DECODE_ERROR", "details.json parse error")
        abort(500)
        
    # Find the specific disease
    selected_disease = None
    for condition in data['skin_conditions']:
        # Create URL-friendly version of the condition name for comparison
        condition_url_name = condition['name'].lower().replace(' ', '-').replace('_', '-')
        # Remove special characters
        condition_url_name = ''.join(c for c in condition_url_name if c.isalnum() or c == '-')
        
        if condition_url_name == disease_name.lower():
            selected_disease = condition
            break
    
    if selected_disease is None:
        print(f"Disease not found: {disease_name}")
        monitor.log_error(request.remote_addr, "DISEASE_NOT_FOUND", f"Disease {disease_name} not found")
        abort(404)
    
    # Debug print to check image path
    print(f"Selected disease: {selected_disease['name']}")
    print(f"Image path: {selected_disease.get('image_path', 'No image path')}")
    
    # Pass both the selected disease and all conditions for the dropdown
    return render_template('details.html', 
                         disease=selected_disease, 
                         all_conditions=data['skin_conditions'])

@app.route('/disease-details')
@rate_limit()
def home():
    # Read the JSON data to get all disease names for the home page
    try:
        with open('details.json', 'r') as file:
            data = json.load(file)
        return render_template('disease_database.html', skin_conditions=data['skin_conditions'])
    except Exception as e:
        monitor.log_error(request.remote_addr, "DATABASE_ERROR", str(e))
        abort(500)

# NEW: Bulk IP management endpoints
@app.route('/api/dashboard/bulk-block-ips', methods=['POST'])
def bulk_block_ips():
    """Block multiple IPs at once"""
    data = request.get_json()
    ips = data.get('ips', [])
    reason = data.get('reason', 'Bulk block via dashboard')
    
    if not ips or not isinstance(ips, list):
        return jsonify({'success': False, 'message': 'Invalid IP list'}), 400
    
    blocked_count = 0
    failed_ips = []
    
    for ip in ips:
        success = monitor.add_blocked_ip(ip.strip(), reason)
        if success:
            blocked_count += 1
        else:
            failed_ips.append(ip)
    
    return jsonify({
        'success': True,
        'message': f'Blocked {blocked_count} IPs successfully',
        'blocked_count': blocked_count,
        'failed_ips': failed_ips
    })

@app.route('/api/dashboard/bulk-whitelist-ips', methods=['POST'])
def bulk_whitelist_ips():
    """Whitelist multiple IPs at once"""
    data = request.get_json()
    ips = data.get('ips', [])
    reason = data.get('reason', 'Bulk whitelist via dashboard')
    
    if not ips or not isinstance(ips, list):
        return jsonify({'success': False, 'message': 'Invalid IP list'}), 400
    
    whitelisted_count = 0
    
    for ip in ips:
        success = monitor.add_whitelisted_ip(ip.strip(), reason)
        if success:
            whitelisted_count += 1
    
    return jsonify({
        'success': True,
        'message': f'Whitelisted {whitelisted_count} IPs successfully',
        'whitelisted_count': whitelisted_count
    })

@app.route('/api/dashboard/clear-blocked-ips', methods=['POST'])
def clear_blocked_ips():
    """Clear all blocked IPs"""
    monitor.blocked_ips.clear()
    monitor.save_blocked_ips()
    monitor.log_security_event("BULK_UNBLOCK", "SYSTEM", "All blocked IPs cleared via dashboard")
    return jsonify({'success': True, 'message': 'All blocked IPs cleared successfully'})

@app.route('/api/dashboard/export-ips', methods=['GET'])
def export_ips():
    """Export blocked and whitelisted IPs"""
    export_data = {
        'export_timestamp': datetime.now().isoformat(),
        'blocked_ips': list(monitor.blocked_ips),
        'whitelisted_ips': list(monitor.whitelisted_ips),
        'suspicious_ips': list(monitor.suspicious_ips)
    }
    return jsonify(export_data)

@app.route('/api/dashboard/import-ips', methods=['POST'])
def import_ips():
    """Import blocked and whitelisted IPs"""
    data = request.get_json()
    
    imported_blocked = 0
    imported_whitelisted = 0
    
    # Import blocked IPs
    if 'blocked_ips' in data:
        for ip in data['blocked_ips']:
            if monitor.add_blocked_ip(ip, "Imported via dashboard"):
                imported_blocked += 1
    
    # Import whitelisted IPs
    if 'whitelisted_ips' in data:
        for ip in data['whitelisted_ips']:
            if monitor.add_whitelisted_ip(ip, "Imported via dashboard"):
                imported_whitelisted += 1
    
    return jsonify({
        'success': True,
        'message': f'Imported {imported_blocked} blocked IPs and {imported_whitelisted} whitelisted IPs',
        'imported_blocked': imported_blocked,
        'imported_whitelisted': imported_whitelisted
    })

@app.errorhandler(404)
def not_found(e):
    monitor.log_error(request.remote_addr, "404_ERROR", f"Page not found: {request.url}")
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    main_line = "Your connection has been restricted due to suspicious activity."
    line_2 = "If this is a mistake, please contact the administrator with your IP address and time of access."
    error_code = "Error Code: 403 - Security Firewall"
    points = "Firewall Triggered · IP Monitored · Rate Limit Enforced"
    return render_template("error.html", main_line=main_line, line_2=line_2, error_code=error_code, points=points), 403


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(500)
def internal_server_error(e):
    monitor.log_error(request.remote_addr, "500_ERROR", f"Internal server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # ANSI color codes
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"

    try:
        # Load the model and condition details when starting the server
        model_loaded = load_ml_model()
        details_loaded = load_condition_details()

        if model_loaded:
            print(GREEN + "=" * 60 + RESET)
            print(GREEN + "Flask Server Stats!" + RESET)
            print(GREEN + "=" * 60 + RESET)
            print(YELLOW + f"Main Application: http://localhost:5000/" + RESET)
            print(YELLOW + f"Security Dashboard: http://localhost:5000/dashboard" + RESET)
            print(GREEN + f"Loaded {len(monitor.blocked_ips)} blocked IPs from file" + RESET)
            print(GREEN + f"Loaded {len(monitor.whitelisted_ips)} whitelisted IPs from file" + RESET)
            print(YELLOW + "IP data will be automatically saved to JSON files" + RESET)
            print(GREEN + "=" * 60 + RESET)
            
            if not details_loaded:
                print(YELLOW + "⚠️  Warning: Condition details not loaded. Will proceed without detailed information." + RESET)
            
            
            app.run(debug=True, host='0.0.0.0', port=5000)
        else:
            print(RED + "❌ Failed to load model. Server not started." + RESET)
    except KeyboardInterrupt:
        print(YELLOW + "\n🛑 Server stopped by user" + RESET)
    except Exception as e:
        print(RED + f"❌ Error starting server: {str(e)}" + RESET)
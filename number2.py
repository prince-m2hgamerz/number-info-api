from flask import Flask, request, jsonify, render_template
from datetime import datetime, timedelta, UTC
import requests
import logging
import os
import json
from dateutil import parser

# --- CONFIGURATION AND INITIALIZATION ---
# Use an environment variable for secret key in production
app = Flask(__name__)
# A secret key is essential for session management and flashing
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "A_FALLBACK_SECRET_CHANGE_ME_IMMEDIATELY")

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# File path for our JSON "database"
DATA_FILE = 'api_data.json'

# Master key for admin endpoints
# Using os.environ.get is correct, but we'll use a better name for the default
MASTER_ADMIN_KEY = os.environ.get("MASTER_ADMIN_KEY", "ADMIN_DEFAULT_KEY_CHANGE_ME_IN_PROD")

# Global Configuration Parameters (Persistent)
GLOBAL_CONFIG = {
    "default_cache_expiry_seconds": 86400, # 24 hours
    "rate_limit_count": 5,
    "rate_limit_window": 60,
    # blocked_user_agents will be loaded/initialized as a set in load_data
    "blocked_user_agents": set(["Python/requests", "curl/*", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", ""])
}

# Global variables (Persistent data, loaded from JSON)
VALID_API_KEYS = {}         # {key: {"user_id": str, "expires_at": datetime}} 
USAGE_STATS = {}            # {key: {"success_count": int, "cache_hit_count": int}}
RATE_LIMITER = {}           # {key: [datetime, datetime, ...]}
CLIENT_TTL_MAP = {}         # {key: seconds}
BLOCKED_IPS = set()         
ALLOWED_CORS_ORIGINS = set() 

# In-Memory Cache (NOT persistent)
CACHE = {} # {number: {"data": data_dict, "timestamp": datetime}}

# External API Endpoints for Fallback Logic
API_ENDPOINTS = [
    {"name": "Primary", "url": "https://jsr-number-info.onrender.com/lookup", "timeout": 10},
    {"name": "Fallback", "url": "https://conceptual-fallback-api.example.com/lookup", "timeout": 8}, 
]

# --- JSON Persistence Functions ---

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects and sets."""
    def default(self, obj):
        if isinstance(obj, datetime):
            # Encode datetime objects using isoformat (with timezone)
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

def load_data():
    """Loads all persistent data from the JSON file."""
    global VALID_API_KEYS, USAGE_STATS, RATE_LIMITER, CLIENT_TTL_MAP, BLOCKED_IPS, ALLOWED_CORS_ORIGINS, GLOBAL_CONFIG
    
    # Preserve default User Agents before loading, in case the loaded config doesn't have it
    default_uas = GLOBAL_CONFIG["blocked_user_agents"]
    
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
                
            # Update Global Config, and handle the set conversion for UAs
            loaded_config = data.get('global_config', {})
            for key, value in loaded_config.items():
                if key == "blocked_user_agents":
                    GLOBAL_CONFIG[key] = set(value)
                else:
                    GLOBAL_CONFIG[key] = value
            
            # Ensure UAs is a set, and merge in the defaults if not present
            if not isinstance(GLOBAL_CONFIG.get("blocked_user_agents"), set):
                 GLOBAL_CONFIG["blocked_user_agents"] = set(data.get('blocked_user_agents', []))
            
            # Merge defaults if the list was empty or replaced
            GLOBAL_CONFIG["blocked_user_agents"].update(default_uas) 
                
            keys_raw = data.get('api_keys', {})
            VALID_API_KEYS = {}
            for key, details in keys_raw.items():
                if isinstance(details, str):
                    # Legacy support for old string format
                    VALID_API_KEYS[key] = {"user_id": details, "expires_at": None}
                else:
                    expires_at_str = details.get("expires_at")
                    # Use dateutil.parser for robustness, then ensure UTC
                    expires_at = parser.parse(expires_at_str).astimezone(UTC) if expires_at_str else None
                    VALID_API_KEYS[key] = {"user_id": details.get("user_id"), "expires_at": expires_at}

            USAGE_STATS = data.get('usage_stats', {})
            CLIENT_TTL_MAP = data.get('client_ttl_map', {})
            BLOCKED_IPS = set(data.get('blocked_ips', []))
            ALLOWED_CORS_ORIGINS = set(data.get('allowed_cors_origins', ["*"]))
            
            RATE_LIMITER_RAW = data.get('rate_limiter', {})
            RATE_LIMITER = {
                # Convert timestamp strings back to datetime objects, ensuring UTC timezone
                key: [parser.parse(ts).astimezone(UTC) for ts in timestamps]
                for key, timestamps in RATE_LIMITER_RAW.items()
            }

            logging.info("Persistent data loaded successfully.")
        except Exception as e:
            logging.error(f"Error loading data from JSON: {e}. Using default/empty state.")
            # Re-initialize defaults on failure to prevent empty sets/dicts
            ALLOWED_CORS_ORIGINS = {"*"} 
            BLOCKED_IPS = set()
    else:
        logging.warning("JSON data file not found. Initializing with defaults.")
        # Initialize with sane defaults if the file doesn't exist
        VALID_API_KEYS = {
            "YOUR_SECRET_KEY_1": {"user_id": "UserA", "expires_at": None},
            "YOUR_SECRET_KEY_2": {"user_id": "UserB", "expires_at": None},
        }
        ALLOWED_CORS_ORIGINS = {"*"}
    
    # Ensure all persistent data structures are initialized for current keys
    for key in VALID_API_KEYS:
        USAGE_STATS.setdefault(key, {"success_count": 0, "cache_hit_count": 0})
        RATE_LIMITER.setdefault(key, [])
        CLIENT_TTL_MAP.setdefault(key, GLOBAL_CONFIG["default_cache_expiry_seconds"])

def save_data():
    """Saves all persistent data to the JSON file."""
    # Convert datetimes in RATE_LIMITER to strings and ensure they are timezone-aware (isoformat handles this)
    rate_limiter_serializable = {
        key: [ts.isoformat() for ts in timestamps]
        for key, timestamps in RATE_LIMITER.items()
    }
    
    # Prepare API Keys for saving: expires_at will be handled by DateTimeEncoder
    api_keys_serializable = {
        k: {"user_id": v["user_id"], "expires_at": v["expires_at"]}
        for k, v in VALID_API_KEYS.items()
    }

    # Prepare Global Config for saving: convert sets to lists for JSON serialization
    config_to_save = {k: (list(v) if isinstance(v, set) else v) for k, v in GLOBAL_CONFIG.items()}
    
    data_to_save = {
        'global_config': config_to_save,
        'api_keys': api_keys_serializable,
        'usage_stats': USAGE_STATS,
        'rate_limiter': rate_limiter_serializable,
        'client_ttl_map': CLIENT_TTL_MAP,
        'blocked_ips': list(BLOCKED_IPS),
        'allowed_cors_origins': list(ALLOWED_CORS_ORIGINS),
        'last_saved': datetime.now(UTC).isoformat()
    }
    try:
        with open(DATA_FILE, 'w') as f:
            # Use the custom encoder to handle sets and datetime objects
            json.dump(data_to_save, f, indent=4, cls=DateTimeEncoder)
    except Exception as e:
        logging.error(f"Error saving data to JSON: {e}")

# --- API Middleware (BEFORE Request) ---
@app.before_request
def check_ip_blocklist_and_user_agent():
    """Check IP blocklist and User-Agent blocklist."""
    client_ip = request.remote_addr
    # Use .get('User-Agent', '') for safe access
    user_agent = request.headers.get('User-Agent', '')

    # 1. IP Blocklist Check
    if client_ip in BLOCKED_IPS:
        logging.warning(f"Blocked IP: {client_ip}")
        # Return the response directly from the middleware
        return jsonify({"success": False, "error": "Access denied. Your IP address is blocked.", **get_api_info()}), 403

    # 2. User-Agent Blocklist Check
    # Check if the User-Agent is in the set of blocked UAs
    if user_agent in GLOBAL_CONFIG["blocked_user_agents"]:
        logging.warning(f"Blocked User-Agent: {user_agent} from {client_ip}")
        return jsonify({"success": False, "error": "Access denied. Your User-Agent is blocked.", **get_api_info()}), 403
        
# --- CORS and Utility Functions ---

@app.after_request
def add_cors_headers(response):
    """
    Adds CORS headers and handles Content-Type for JSON responses.
    """
    origin = request.headers.get('Origin')
    
    # 1. Determine Allowed Origin for CORS
    if "*" in ALLOWED_CORS_ORIGINS:
        allowed_origin = "*"
    elif origin and origin in ALLOWED_CORS_ORIGINS:
        allowed_origin = origin
    else:
        # If origin is not explicitly allowed, do not set the header
        allowed_origin = None

    if allowed_origin:
        # NOTE: Setting 'Access-Control-Allow-Credentials' to 'true' 
        # requires 'Access-Control-Allow-Origin' to be a specific domain, not '*'.
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
            
    # 2. Handle OPTIONS Pre-flight Request
    if request.method == 'OPTIONS':
        # Add necessary headers for pre-flight response
        response.headers["Access-Control-Allow-Methods"] = "GET, POST"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, X-Admin-Key"
        # Set status code for pre-flight success
        response.status_code = 204 # No Content
        return response

    # 3. Conditional Content-Type Fix
    # render_template() sets Content-Type to 'text/html'. 
    # We only ensure it's 'application/json' if it's not already something else (like text/html)
    current_content_type = response.headers.get('Content-Type', '').lower()
    if 'text/html' not in current_content_type and 'application/json' not in current_content_type:
        response.headers["Content-Type"] = "application/json"
    
    return response

def get_api_info():
    """Generates the base API information dictionary."""
    # Get current time in UTC and format as ISO standard
    return {
        "api_owner": "@m2hgamerz",
        "group": "@m2hwebsolution",
        "channel": "@m2hwebsolution",
        "api_version": "1.0",
        "timestamp": datetime.now(UTC).isoformat()
    }

def clean_expired_cache(api_key):
    """Removes expired entries from the in-memory CACHE, considering client TTL."""
    now = datetime.now(UTC)
    # Fetch the client-specific TTL or use the global default
    client_ttl = CLIENT_TTL_MAP.get(api_key, GLOBAL_CONFIG["default_cache_expiry_seconds"]) 

    keys_to_delete = []
    # Iterate over a copy of the keys to allow modification of the original dict
    for number, data in list(CACHE.items()): 
        # Ensure the stored timestamp is UTC-aware for comparison
        cache_time = data["timestamp"].astimezone(UTC)

        # Check if the current time is past the expiry time
        if now > cache_time + timedelta(seconds=client_ttl):
            keys_to_delete.append(number)
            
    for key in keys_to_delete:
        del CACHE[key]
        
def is_rate_limited(api_key):
    """Checks and updates the rate limit for the given API key."""
    now = datetime.now(UTC)
    window_start = now - timedelta(seconds=GLOBAL_CONFIG["rate_limit_window"])
    
    global RATE_LIMITER
    # Filter the list to only include timestamps within the current window
    RATE_LIMITER[api_key] = [
        t for t in RATE_LIMITER.get(api_key, []) if t > window_start
    ]
    
    current_count = len(RATE_LIMITER[api_key])
    
    # Check if the current count exceeds the limit
    if current_count >= GLOBAL_CONFIG["rate_limit_count"]:
        return True
    
    # Add the current request time to the list
    RATE_LIMITER[api_key].append(now)
    # Note: We don't save_data() here as this happens *per request* and would thrash the disk.
    # The usage stats update will trigger a save later, or an admin action.
    return False

def make_lookup_request(number, endpoint):
    """
    Makes a request to a single external API endpoint.
    Returns a dictionary with success status and results/error.
    """
    url = endpoint["url"]
    name = endpoint["name"]
    timeout = endpoint["timeout"]
    payload = {"number": number}

    try:
        # Use a User-Agent that's less likely to be blocked by default 
        # (though this API blocks some common ones like 'Python/requests')
        headers = {'User-Agent': 'M2H-Lookup-Service/1.0'}
        response = requests.post(url, json=payload, timeout=timeout, headers=headers)
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        
        # Check for specific data structure from the external API
        if "data" in data and "result" in data["data"] and data["data"]["result"]:
            return {"success": True, "results": data["data"]["result"], "source": name}
        else:
            # Handle cases where the API returns 200 but has no relevant data
            return {"success": False, "error": f"{name} API: No relevant data found in response structure"}
            
    except requests.exceptions.Timeout:
        return {"success": False, "error": f"{name} API: Timed out after {timeout}s"}
    except requests.exceptions.HTTPError as e:
        # Capture HTTP status code and response text for the error message
        error_msg = f"Status {e.response.status_code}: {e.response.text[:100].strip()}"
        return {"success": False, "error": f"{name} API: HTTP Request failed, {error_msg}"}
    except requests.exceptions.RequestException as e:
        # Catch all other requests-related errors (DNS, connection, etc.)
        return {"success": False, "error": f"{name} API: General Request failure, {str(e)[:100].strip()}"}
    except json.JSONDecodeError:
        # Catch case where response is not valid JSON
        return {"success": False, "error": f"{name} API: Invalid JSON response"}

def filter_response_fields(data, fields_str):
    """Filters a dictionary or list of dictionaries based on a comma-separated string of fields."""
    if not fields_str:
        return data

    requested_fields = {f.strip() for f in fields_str.split(',') if f.strip()} # Use a set for faster lookup
    
    if isinstance(data, dict):
        # Dictionary comprehension for filtering fields
        return {k: v for k, v in data.items() if k in requested_fields}
    elif isinstance(data, list):
        # List comprehension: for each item (dict), apply the filtering
        return [{k: v for k, v in item.items() if k in requested_fields} for item in data if isinstance(item, dict)]
    # Return original data if it's neither dict nor list (e.g., a string or int result)
    return data

def get_params_from_request(param_name):
    """Helper to extract a parameter from query args, JSON body, or form data."""
    # 1. Query Arguments (GET/POST)
    value = request.args.get(param_name)
    if value is not None:
        return value
    
    # 2. JSON Body (POST/PUT)
    if request.method in ('POST', 'PUT') and request.is_json:
        try:
            json_data = request.get_json()
            return json_data.get(param_name)
        except Exception:
            # Silently ignore if JSON parsing fails
            pass
            
    # 3. Form Data (POST)
    if request.method == 'POST' and request.form:
        return request.form.get(param_name)
    
    return None

# ----------------------------------------------------------------------
# ENDPOINT: HELP/DOCUMENTATION
# ----------------------------------------------------------------------
@app.route("/help", methods=["GET"])
def help_page():
    """Renders the HTML documentation page."""
    
    # Safely get the base URL (using the safer version from our last suggestion)
    base_url = request.url_root.rstrip('/')
    
    # Safely get the example API key
    example_api_key = next(iter(VALID_API_KEYS.keys()), "YOUR_API_KEY_HERE") if VALID_API_KEYS else "YOUR_API_KEY_HERE"
    
    context = {
        "master_admin_key": MASTER_ADMIN_KEY,
        "base_url": base_url, 
        "example_api_key": example_api_key,
        
        # 🔑 THE FIX: Pass the 'tiers' variable to the template
        "tiers": GLOBAL_CONFIG.get('rate_limit_tiers', {}), # Or whatever your tiers variable is named
        
        # Re-adding global config variables (if they are used in help.html)
        "rate_limit_count": GLOBAL_CONFIG.get('rate_limit_count', 'N/A'),
        "rate_limit_window": GLOBAL_CONFIG.get('rate_limit_window', 'N/A')
    }
    
    return render_template("help.html", **context)


# --- API ENDPOINT (Lookup) ---
@app.route("/", methods=["GET", "POST"])
def lookup_number():
    api_info = get_api_info()
    client_ip = request.remote_addr
    
    # Prioritize headers for API key, then args/body
    api_key = request.headers.get("X-API-Key") or get_params_from_request("key")
    number = get_params_from_request("number")
    fields_to_return = get_params_from_request("fields") 
    
    # 1. Input Validation (Number)
    if not number:
        return jsonify({"success": False, "error": "Missing number parameter in query, body, or form.", **api_info}), 400
        
    logging.info(f"Lookup from {client_ip} for {number}. Key: {api_key}")

    # 2. Authentication and Expiration Check 
    if not api_key or api_key not in VALID_API_KEYS:
        return jsonify({"success": False, "error": "Unauthorized: Missing or invalid API key.", **api_info}), 401
        
    key_details = VALID_API_KEYS[api_key]
    # Check expiration (datetime comparison with timezone-aware objects)
    if key_details["expires_at"] and key_details["expires_at"] < datetime.now(UTC):
        logging.warning(f"Access denied for expired key: {api_key}")
        return jsonify({"success": False, "error": "Unauthorized: API key has expired.", **api_info}), 401

    # 3. Rate Limiting Check
    if is_rate_limited(api_key):
        # Calculate time remaining until the rate limit resets (for a better user experience)
        window_end_time = RATE_LIMITER[api_key][0] + timedelta(seconds=GLOBAL_CONFIG["rate_limit_window"])
        retry_after_seconds = int((window_end_time - datetime.now(UTC)).total_seconds())
        
        response = jsonify({
            "success": False,
            "error": f"Rate limit exceeded. Maximum {GLOBAL_CONFIG['rate_limit_count']} requests per {GLOBAL_CONFIG['rate_limit_window']} seconds. Try again in {retry_after_seconds}s.",
            "retry_after": retry_after_seconds,
            **api_info
        })
        # Set the Retry-After header
        response.headers["Retry-After"] = str(retry_after_seconds)
        return response, 429 

    # 4. Caching Check (with Client TTL Logic) 
    client_ttl = CLIENT_TTL_MAP.get(api_key, GLOBAL_CONFIG["default_cache_expiry_seconds"])
    clean_expired_cache(api_key) # Clean the cache before checking
    
    if number in CACHE:
        cached_data = CACHE[number]["data"]
        USAGE_STATS[api_key]["cache_hit_count"] += 1 
        save_data() # Save stats update
        
        filtered_results = filter_response_fields(cached_data, fields_to_return)
        
        return jsonify({
            "success": True,
            "number": number,
            "source": "cache",
            "results": filtered_results,
            "client_ip": client_ip,
            "cache_ttl_seconds": client_ttl,
            **api_info
        }), 200

    # 5. Fallback/Sequential Lookup Logic
    final_result = None
    all_errors = []

    for endpoint in API_ENDPOINTS:
        lookup_response = make_lookup_request(number, endpoint)
        
        if lookup_response["success"]:
            final_result = lookup_response
            break 
        else:
            all_errors.append(lookup_response["error"])
    
    # 6. Process Final Result
    if final_result and final_result["success"]:
        results = final_result["results"]
        source = final_result["source"]
        
        # Add to CACHE with UTC timestamp
        CACHE[number] = {"data": results, "timestamp": datetime.now(UTC)}
        USAGE_STATS[api_key]["success_count"] += 1 
        save_data() # Save stats update
        
        filtered_results = filter_response_fields(results, fields_to_return)

        return jsonify({
            "success": True,
            "number": number,
            "source": source,
            "results": filtered_results,
            "client_ip": client_ip,
            "cache_ttl_seconds": client_ttl,
            **api_info
        }), 200
    else:
        # Return a 503 Service Unavailable if all upstream endpoints failed
        return jsonify({
            "success": False,
            "error": "Failed to retrieve data after trying all endpoints.",
            "details": all_errors,
            **api_info
        }), 503 


# --- HEALTH CHECK AND STATS ENDPOINTS ---
@app.route("/health", methods=["GET", "POST"])
def health_check():
    """Reports the API's operational status."""
    db_status = "OK" if os.path.exists(DATA_FILE) else "WARNING: DB file missing"
    
    return jsonify({
        "status": "OK",
        "service": "Number Lookup API",
        "db_status": db_status,
        "current_time_utc": datetime.now(UTC).isoformat(),
        **get_api_info()
    }), 200

@app.route("/stats", methods=["GET", "POST"])
def get_stats():
    """Provides usage statistics for a given API key."""
    api_info = get_api_info()
    api_key = request.headers.get("X-API-Key") or get_params_from_request("key")

    if not api_key or api_key not in VALID_API_KEYS:
        return jsonify({"success": False, "error": "Unauthorized: Missing or invalid API key.", **api_info}), 401
        
    user_id = VALID_API_KEYS[api_key]["user_id"]
    stats = USAGE_STATS.get(api_key, {"success_count": 0, "cache_hit_count": 0})
    
    return jsonify({
        "success": True,
        "user_id": user_id,
        "usage_statistics": stats,
        "cache_ttl_seconds": CLIENT_TTL_MAP.get(api_key, GLOBAL_CONFIG["default_cache_expiry_seconds"]),
        "rate_limit_settings": f"{GLOBAL_CONFIG['rate_limit_count']} per {GLOBAL_CONFIG['rate_limit_window']}s (Global)",
        "note": "Statistics are persistent.",
        **api_info
    }), 200

# --- ADMIN ENDPOINTS ---

def check_admin_auth():
    """Reusable function to check for the master admin key."""
    admin_key = request.headers.get("X-Admin-Key") or get_params_from_request("admin_key")
    if admin_key != MASTER_ADMIN_KEY:
        return jsonify({
            "success": False,
            "error": "Forbidden: Invalid or missing X-Admin-Key header.",
            **get_api_info()
        }), 403
    return None

@app.route("/admin/add_key", methods=["GET", "POST"])
def add_api_key():
    """Creates a new API key."""
    auth_response = check_admin_auth()
    if auth_response: return auth_response

    new_key = get_params_from_request('key')
    user_id = get_params_from_request('user_id')
    ttl_seconds = get_params_from_request('ttl')
    expires_at_str = get_params_from_request('expires_at') 

    if not new_key or not user_id:
        return jsonify({"success": False, "error": "Missing required parameters: 'key' and 'user_id'.", **get_api_info()}), 400
    if new_key in VALID_API_KEYS:
        return jsonify({"success": False, "error": f"API key '{new_key}' already exists.", **get_api_info()}), 409

    expires_at = None
    if expires_at_str:
        try:
            # Parse the date and ensure it is timezone-aware (UTC)
            expires_at = parser.parse(expires_at_str).astimezone(UTC)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid date format for 'expires_at'. Use ISO format (e.g., YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ).", **get_api_info()}), 400

    # Initialize the new key's details
    VALID_API_KEYS[new_key] = {"user_id": user_id, "expires_at": expires_at}
    USAGE_STATS.setdefault(new_key, {"success_count": 0, "cache_hit_count": 0})
    RATE_LIMITER.setdefault(new_key, [])
    
    try:
        ttl = int(ttl_seconds) if ttl_seconds else GLOBAL_CONFIG["default_cache_expiry_seconds"]
        if ttl <= 0: raise ValueError
        CLIENT_TTL_MAP[new_key] = ttl
    except (ValueError, TypeError):
        CLIENT_TTL_MAP[new_key] = GLOBAL_CONFIG["default_cache_expiry_seconds"] # Default on error

    save_data()
    
    expiry_msg = expires_at.isoformat() if expires_at else "Never"
    return jsonify({"success": True, "message": f"API key '{new_key}' created (Expires: {expiry_msg}, TTL: {CLIENT_TTL_MAP[new_key]}s).", **get_api_info()}), 201

@app.route("/admin/delete_key", methods=["GET", "POST"])
def delete_api_key():
    """Deletes an API key and all associated data."""
    auth_response = check_admin_auth()
    if auth_response: return auth_response

    key_to_delete = get_params_from_request('key')

    if not key_to_delete: return jsonify({"success": False, "error": "Missing parameter: 'key'.", **get_api_info()}), 400
    if key_to_delete not in VALID_API_KEYS: return jsonify({"success": False, "error": f"API key '{key_to_delete}' not found.", **get_api_info()}), 404

    # Safely remove from all global dictionaries
    VALID_API_KEYS.pop(key_to_delete, None)
    USAGE_STATS.pop(key_to_delete, None)
    RATE_LIMITER.pop(key_to_delete, None)
    CLIENT_TTL_MAP.pop(key_to_delete, None)
    
    save_data()
    return jsonify({"success": True, "message": f"API key '{key_to_delete}' and all associated data deleted.", **get_api_info()}), 200

@app.route("/admin/ip_blocklist", methods=["GET", "POST"])
def manage_ip_blocklist():
    """Manages the IP blocklist."""
    auth_response = check_admin_auth()
    if auth_response: return auth_response
    
    ip_address = get_params_from_request('ip')
    action = get_params_from_request('action')

    if request.method == 'GET':
        return jsonify({"success": True, "blocklist": sorted(list(BLOCKED_IPS)), **get_api_info()}), 200

    if not ip_address or action not in ('add', 'remove'):
        return jsonify({"success": False, "error": "Missing parameters. Required: 'ip' and 'action' ('add' or 'remove').", **get_api_info()}), 400
        
    if action == 'add':
        if ip_address not in BLOCKED_IPS:
            BLOCKED_IPS.add(ip_address)
            save_data()
            return jsonify({"success": True, "message": f"IP '{ip_address}' added to blocklist.", **get_api_info()}), 200
        else:
            return jsonify({"success": False, "error": f"IP '{ip_address}' is already blocked.", **get_api_info()}), 409
    
    elif action == 'remove':
        if ip_address in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip_address)
            save_data()
            return jsonify({"success": True, "message": f"IP '{ip_address}' removed from blocklist.", **get_api_info()}), 200
        else:
            return jsonify({"success": False, "error": f"IP '{ip_address}' was not found in blocklist.", **get_api_info()}), 404

@app.route("/admin/ua_blocklist", methods=["GET", "POST"])
def manage_ua_blocklist():
    """Manages the User-Agent blocklist."""
    auth_response = check_admin_auth()
    if auth_response: return auth_response
    
    user_agent = get_params_from_request('ua')
    action = get_params_from_request('action')

    if request.method == 'GET':
        # Return a sorted list view of the set
        return jsonify({"success": True, "blocklist": sorted(list(GLOBAL_CONFIG["blocked_user_agents"])), **get_api_info()}), 200

    if not user_agent or action not in ('add', 'remove'):
        return jsonify({"success": False, "error": "Missing parameters. Required: 'ua' (User-Agent string) and 'action' ('add' or 'remove').", **get_api_info()}), 400
        
    if action == 'add':
        if user_agent not in GLOBAL_CONFIG["blocked_user_agents"]:
            GLOBAL_CONFIG["blocked_user_agents"].add(user_agent)
            save_data()
            return jsonify({"success": True, "message": f"User-Agent '{user_agent}' added to blocklist.", **get_api_info()}), 200
        else:
            return jsonify({"success": False, "error": f"User-Agent '{user_agent}' is already blocked.", **get_api_info()}), 409
    
    elif action == 'remove':
        if user_agent in GLOBAL_CONFIG["blocked_user_agents"]:
            GLOBAL_CONFIG["blocked_user_agents"].remove(user_agent)
            save_data()
            return jsonify({"success": True, "message": f"User-Agent '{user_agent}' removed from blocklist.", **get_api_info()}), 200
        else:
            return jsonify({"success": False, "error": f"User-Agent '{user_agent}' was not found in blocklist.", **get_api_info()}), 404

@app.route("/admin/config", methods=["GET", "POST"])
def manage_global_config():
    """Manages global configuration parameters."""
    auth_response = check_admin_auth()
    if auth_response: return auth_response
    
    if request.method == 'GET':
        # Create a copy and convert the set to a list for JSON serialization
        config_view = GLOBAL_CONFIG.copy()
        config_view["blocked_user_agents"] = list(config_view["blocked_user_agents"])
        
        return jsonify({"success": True, "config": config_view, **get_api_info()}), 200

    data = request.get_json() if request.is_json else request.form 
    if not data:
        return jsonify({"success": False, "error": "Missing update data.", **get_api_info()}), 400

    updated_fields = {}
    
    # Define which keys are allowed to be updated and their expected type
    allowed_updates = {
        "rate_limit_count": int,
        "rate_limit_window": int,
        "default_cache_expiry_seconds": int
    }
    
    for key, expected_type in allowed_updates.items():
        if key in data:
            try:
                # Type conversion and validation
                value = expected_type(data[key])
                if value <= 0:
                    raise ValueError(f"Value for '{key}' must be positive.")
                
                GLOBAL_CONFIG[key] = value
                updated_fields[key] = value
            except ValueError as e:
                return jsonify({"success": False, "error": f"Invalid value or type for '{key}'. Details: {e}", **get_api_info()}), 400

    if updated_fields:
        save_data()
        return jsonify({"success": True, "message": "Global configuration updated.", "updated_fields": updated_fields, **get_api_info()}), 200
    else:
        return jsonify({"success": False, "error": "No valid configuration fields provided for update.", **get_api_info()}), 400

@app.route("/admin/cors_origins", methods=["GET", "POST"])
def manage_cors_origins():
    """Manages the set of allowed CORS origins."""
    auth_response = check_admin_auth()
    if auth_response: return auth_response
    
    origin = get_params_from_request('origin')
    action = get_params_from_request('action')

    if request.method == 'GET':
        return jsonify({"success": True, "origins": sorted(list(ALLOWED_CORS_ORIGINS)), "note": "Use '*' to allow all origins.", **get_api_info()}), 200

    if not origin or action not in ('add', 'remove'):
        return jsonify({"success": False, "error": "Missing parameters. Required: 'origin' (URL) and 'action' ('add' or 'remove').", **get_api_info()}), 400
        
    if action == 'add':
        if origin not in ALLOWED_CORS_ORIGINS:
            ALLOWED_CORS_ORIGINS.add(origin)
            save_data()
            return jsonify({"success": True, "message": f"Origin '{origin}' added to allowed list.", **get_api_info()}), 200
        else:
            return jsonify({"success": False, "error": f"Origin '{origin}' is already allowed.", **get_api_info()}), 409
    
    elif action == 'remove':
        if origin in ALLOWED_CORS_ORIGINS:
            ALLOWED_CORS_ORIGINS.remove(origin)
            save_data()
            return jsonify({"success": True, "message": f"Origin '{origin}' removed from allowed list.", **get_api_info()}), 200
        else:
            return jsonify({"success": False, "error": f"Origin '{origin}' not found in allowed list.", **get_api_info()}), 404


# ----------------------------------------------------------------------
# WSGI ENTRY POINT
# ----------------------------------------------------------------------
# This is called once when the application starts (e.g., by gunicorn, uWSGI, or PythonAnywhere).
load_data()

# Optional: Add a standard Flask development server launch block for local testing
if __name__ == "__main__":
    logging.info("Starting Flask development server...")
    # NOTE: Set debug=True only for development, never for production
    app.run(debug=True, host='0.0.0.0', port=5000)
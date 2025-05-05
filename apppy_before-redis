# import eventlet
# eventlet.monkey_patch()
from gevent import monkey
monkey.patch_all()



import os
import json
import time
import requests
import logging
import secrets
import re
from flask import Flask, request, render_template, jsonify, abort, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, disconnect
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)

app = Flask(__name__)
# Use environment variable for secret key with a fallback
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
# No session timeout for 24/7 operation
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Removed session expiration

# Improved SocketIO configuration with reconnection settings
socketio = SocketIO(
    app, 
    async_mode=None,  # Let Flask-SocketIO choose the best mode
    cors_allowed_origins='*',
    ping_timeout=60,
    ping_interval=25,
    reconnection=True,
    reconnection_attempts=5,
    reconnection_delay=1,
    reconnection_delay_max=10
)

# Configuration from Heroku config vars
CONNECTOR_URL = os.environ.get("CONNECTOR_URL")
CONNECTOR_API_KEY = os.environ.get("CONNECTOR_API_KEY")
# Timeout configuration - can be adjusted via environment variables
DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", 60))
# Max consecutive heartbeat failures before considering disconnected
MAX_HEARTBEAT_FAILURES = int(os.environ.get("MAX_HEARTBEAT_FAILURES", 3))
# Store the last connection parameters for potential auto-reconnect
last_connection_params = {}

# Global state tracking with separated concerns
connection_state = {
    "ibkr_connected": False,        # True when backend reports IBKR is connected
    "last_backend_heartbeat": None, # Last successful backend heartbeat
    "heartbeat_failures": 0,        # Count of consecutive failures
    "reconnect_in_progress": False, # Whether auto-reconnect is in progress
    "last_ibkr_status": None        # Last known IBKR connection status from backend
}

# Socket connection is tracked separately
socket_state = {
    "connected": False,             # Current socket.io connection status
    "last_connected": None,         # When socket was last connected
    "clients": set()                # Set of connected socket client IDs
}

# User database (replace with a real database in production)
# In production, use a proper database like PostgreSQL, MySQL, or MongoDB
users_db = {}

# Webhook URL paths with their tokens
# Format: {"webhook_token": {"name": "Name", "created_at": "timestamp", "created_by": "username"}}
webhook_tokens = {}

# Authentication decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        # No session expiration check for 24/7 operation
        return f(*args, **kwargs)
    return decorated_function

# Initialize admin user from environment variables
@app.before_first_request
def initialize_admin_user():
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    
    if admin_username and admin_password and admin_username not in users_db:
        app.logger.info(f"Initializing admin user: {admin_username}")
        users_db[admin_username] = {
            "password_hash": generate_password_hash(admin_password),
            "is_admin": True,
            "created_at": datetime.now().isoformat()
        }
    
    # Initialize a default webhook token from environment
    default_webhook_token = os.environ.get("DEFAULT_WEBHOOK_TOKEN")
    if default_webhook_token:
        app.logger.info("Initializing default webhook token")
        webhook_tokens[default_webhook_token] = {
            "name": "Default Token",
            "created_at": datetime.now().isoformat(),
            "created_by": "system"
        }
        
    # START HEARTBEAT LOOP ONCE AT FIRST REQUEST
    app.logger.info("Spawning heartbeat background task")
    socketio.start_background_task(target=start_heartbeat_check)



# User management routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to index
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users_db and check_password_hash(users_db[username]['password_hash'], password):
            session.permanent = True  # Make session permanent for 24/7 operation
            session['user_id'] = username
            session['is_admin'] = users_db[username].get('is_admin', False)
            
            app.logger.info(f"User logged in: {username}")
            next_page = request.args.get('next', url_for('index'))
            return redirect(next_page)
        else:
            error = "Invalid username or password"
            app.logger.warning(f"Failed login attempt for user: {username}")
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    username = session.get('user_id', 'Unknown')
    session.clear()
    app.logger.info(f"User logged out: {username}")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        username = session['user_id']
        
        # Verify current password
        if not check_password_hash(users_db[username]['password_hash'], current_password):
            error = "Current password is incorrect"
        elif new_password != confirm_password:
            error = "New passwords do not match"
        elif len(new_password) < 8:
            error = "Password must be at least 8 characters long"
        else:
            # Update password
            users_db[username]['password_hash'] = generate_password_hash(new_password)
            users_db[username]['password_updated_at'] = datetime.now().isoformat()
            success = "Password changed successfully"
            app.logger.info(f"Password changed for user: {username}")
    
    return render_template('change_password.html', error=error, success=success)

# Admin routes for user management
@app.route('/admin/users', methods=['GET'])
@login_required
def admin_users():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('admin_users.html', users=users_db)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        if username in users_db:
            error = f"Username '{username}' already exists"
        elif len(password) < 8:
            error = "Password must be at least 8 characters long"
        else:
            users_db[username] = {
                "password_hash": generate_password_hash(password),
                "is_admin": is_admin,
                "created_at": datetime.now().isoformat(),
                "created_by": session['user_id']
            }
            success = f"User '{username}' created successfully"
            app.logger.info(f"New user created: {username} by {session['user_id']}")
    
    return render_template('add_user.html', error=error, success=success)

@app.route('/admin/delete_user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    if not session.get('is_admin', False):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    if username == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
    elif username in users_db:
        del users_db[username]
        flash(f"User '{username}' deleted successfully.", 'success')
        app.logger.info(f"User deleted: {username} by {session['user_id']}")
    else:
        flash(f"User '{username}' not found.", 'danger')
    
    return redirect(url_for('admin_users'))

# Webhook token management
@app.route('/admin/webhook_tokens', methods=['GET'])
@login_required
def admin_webhook_tokens():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    # Generate full webhook URLs for each token
    webhook_urls = {}
    for token, details in webhook_tokens.items():
        webhook_urls[token] = request.host_url.rstrip('/') + f"/webhook/{token}"
    
    return render_template('admin_webhook_tokens.html', webhook_tokens=webhook_tokens, webhook_urls=webhook_urls)

@app.route('/admin/generate_webhook_token', methods=['GET', 'POST'])
@login_required
def generate_webhook_token():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    error = None
    success = None
    new_token = None
    webhook_url = None
    
    if request.method == 'POST':
        token_name = request.form.get('token_name')
        
        if not token_name:
            error = "Token name is required"
        else:
            # Generate a secure webhook token
            new_token = secrets.token_hex(16)
            webhook_tokens[new_token] = {
                "name": token_name,
                "created_at": datetime.now().isoformat(),
                "created_by": session['user_id']
            }
            webhook_url = request.host_url.rstrip('/') + f"/webhook/{new_token}"
            success = "Webhook token created successfully"
            app.logger.info(f"New webhook token created: {token_name} by {session['user_id']}")
    
    return render_template('generate_webhook_token.html', error=error, success=success, new_token=new_token, webhook_url=webhook_url)

@app.route('/admin/delete_webhook_token/<token>', methods=['POST'])
@login_required
def delete_webhook_token(token):
    if not session.get('is_admin', False):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    if token in webhook_tokens:
        token_name = webhook_tokens[token]['name']
        del webhook_tokens[token]
        flash(f"Webhook token '{token_name}' deleted successfully.", 'success')
        app.logger.info(f"Webhook token deleted: {token_name} by {session['user_id']}")
    else:
        flash("Webhook token not found.", 'danger')
    
    return redirect(url_for('admin_webhook_tokens'))

# Route for index page now requires login
@app.route('/')
@login_required
def index():
    # Get the default webhook URL (first token or empty string)
    default_token = next(iter(webhook_tokens.keys()), "")
    webhook_url = request.host_url.rstrip('/') + f"/webhook/{default_token}" if default_token else ""
    
    app.logger.info(f"Serving index page. Webhook URL: {webhook_url}")
    return render_template('index.html', webhook_url=webhook_url, username=session.get('user_id', 'User'))

# The functions below are from the original code with webhook modifications

def send_backend_request(endpoint, method="POST", json_data=None, form_data=None, timeout=None):
    """Centralized function to handle backend requests with proper error handling"""
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    
    url = f"{CONNECTOR_URL}/{endpoint}"
    headers = {}
    if CONNECTOR_API_KEY:
        headers['X-API-KEY'] = CONNECTOR_API_KEY

    app.logger.info(f"Sending {method} request to backend: {url}")
    
    try:
        # if method.upper() == "POST":
        #    if json_data:
        #        response = requests.post(url, json=json_data, headers=headers, timeout=timeout)
        #    elif form_data:
        #        response = requests.post(url, data=form_data, headers=headers, timeout=timeout)
        #    else:
        #        response = requests.post(url, headers=headers, timeout=timeout)
        #else:
        #    response = requests.get(url, headers=headers, timeout=timeout)

        if method.upper() == "POST":
            if json_data is not None:
                response = requests.post(url, json=json_data, headers=headers, timeout=timeout)
            elif form_data is not None:
                response = requests.post(url, data=form_data, headers=headers, timeout=timeout)
            else:
                response = requests.post(url, headers=headers, timeout=timeout)
        else:
            response = requests.get(url, headers=headers, timeout=timeout)

        response.raise_for_status()
        return response.json(), None
    
    except requests.exceptions.Timeout:
        error_msg = f"Request to backend timed out after {timeout}s."
        app.logger.error(error_msg)
        return None, {"error": error_msg, "status_code": 504}
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to backend server. Please check if it's running."
        app.logger.error(error_msg)
        return None, {"error": error_msg, "status_code": 502}
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {str(e)}"
        status_code = getattr(e.response, 'status_code', 500) if hasattr(e, 'response') else 500
        app.logger.error(error_msg)
        return None, {"error": error_msg, "status_code": status_code}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        app.logger.error(error_msg, exc_info=True)
        return None, {"error": error_msg, "status_code": 500}

@app.route('/connect', methods=['POST'])
@login_required
def connect_route():
    app.logger.info("Received request on /connect route")

    # 1) Read the HTML form
    data = request.form
    payload = {
        "ip":           data.get("ip"),
        "user_id":      data.get("user_id"),
        "account_type": data.get("account_type")
    }

    # 2) Reject if any field is missing
    missing_fields = [f for f, v in payload.items() if not v]
    if missing_fields:
        error_msg = f"Missing required fields: {', '.join(missing_fields)}"
        app.logger.warning(f"Connection request missing fields: {error_msg}")
        socketio.emit('connection_status', {
            "success": False,
            "message": error_msg,
            "socket_connected": socket_state["connected"]
        })
        return jsonify({"success": False, "message": error_msg}), 400

    # 3) Forward to your IBKR-connector as JSON
    result, error = send_backend_request("connect", json_data=payload)
    if error:
        app.logger.error(f"IBKR connector rejected /connect: {error['error']}")
        socketio.emit('connection_status', {
            "success": False,
            "message": error["error"],
            "socket_connected": socket_state["connected"]
        })
        return jsonify({"success": False, "message": error["error"]}), error["status_code"]

    # 4) Only *after* the connector has accepted it do we stash for auto-reconnect
    global last_connection_params
    last_connection_params = payload.copy()
    app.logger.info(f"Storing connection params for auto-reconnect: {last_connection_params!r}")

    # 5) Tell the front-end it worked
    socketio.emit('connection_status', {
        "success": True,
        "message": result.get("message", "Connected successfully."),
        "socket_connected": socket_state["connected"]
    })
    return jsonify(result), 200

    
    # If successful, update connection state and start heartbeat
    if result and result.get('success'):
        connection_state["ibkr_connected"] = True
        connection_state["last_ibkr_status"] = True
        connection_state["last_backend_heartbeat"] = datetime.now()
        connection_state["heartbeat_failures"] = 0
        connection_state["reconnect_in_progress"] = False
        
        # Add socket_connected to the status
        result["socket_connected"] = socket_state["connected"]
        socketio.emit('connection_status', result)
        
        # Start the enhanced heartbeat check if not already running
        socketio.start_background_task(target=start_heartbeat_check)
    else:
        # Add socket_connected to the status
        result["socket_connected"] = socket_state["connected"]
        socketio.emit('connection_status', result)
    
    return jsonify(result)

@app.route('/disconnect', methods=['POST'])
@login_required
def disconnect_route():
    app.logger.info("Received request on /disconnect route")
    
    # Make the backend request
    result, error = send_backend_request("disconnect")
    
    if error:
        socketio.emit('connection_status', {
            "success": False, 
            "message": error['error'],
            "socket_connected": socket_state["connected"]
        })
        return jsonify({"success": False, "message": error['error']}), error['status_code']
    
    # Update connection state
    connection_state["ibkr_connected"] = False
    connection_state["last_ibkr_status"] = False
    
    # Add socket_connected to the status
    result["socket_connected"] = socket_state["connected"]
    socketio.emit('connection_status', result)
    
    return jsonify(result)

# Modified webhook route to use token in URL instead of header
@app.route('/webhook/<token>', methods=['POST'])
def webhook_receiver(token):
    # Validate the token
    if token not in webhook_tokens:
        app.logger.warning(f"Unauthorized webhook attempt with invalid token: {token}")
        return jsonify({"error": "Unauthorized. Invalid webhook token."}), 401
        
    data = request.json
    if not data:
        app.logger.warning("Received invalid data on /webhook")
        socketio.emit('webhook_error', {"message": "Invalid webhook data received"})
        return "Invalid data", 400

    app.logger.info(f"[WEBHOOK] Received data: {json.dumps(data)}")
    socketio.emit('new_webhook', data)

    # Save order in memory in case we need to retry
    order_id = data.get('ORDER_ID', str(time.time()))
    socketio.emit('order_status', {
        "order_id": order_id,
        "status": "received",
        "message": "Order received, forwarding to backend"
    })

    # Forward to backend
    result, error = send_backend_request("order", json_data=data)
    
    if error:
        error_msg = f"Error forwarding order: {error['error']}"
        app.logger.error(error_msg)
        socketio.emit('order_status', {
            "order_id": order_id,
            "status": "failed",
            "message": error_msg
        })
        return error_msg, error['status_code']
    
    # Success
    socketio.emit('order_status', {
        "order_id": order_id,
        "status": "processed",
        "message": "Order successfully processed by backend",
        "details": result
    })
    
    return "Webhook received and processed successfully", 200

# Add catch-all route for old webhook URL
@app.route('/webhook', methods=['POST'])
def webhook_legacy():
    app.logger.warning("Received request to deprecated webhook URL without token")
    return jsonify({
        "error": "This webhook URL is deprecated. Please use the new URL format with your authentication token."
    }), 403

@app.route('/status', methods=['GET'])
@login_required
def status():
    """Check connection status with backend"""
    if not CONNECTOR_URL:
        return jsonify({
            "frontend": "running",
            "backend_configured": False,
            "message": "Backend URL not configured",
            "socket_connected": socket_state["connected"]
        })
    
    try:
        result, error = send_backend_request("heartbeat", method="GET", timeout=5)
        backend_status = "running" if not error else "unreachable"
        
        # If backend is reachable, also get the IBKR status
        ibkr_status = connection_state["ibkr_connected"]
        if not error and backend_status == "running":
            # Try to get the current IBKR status from backend
            ibkr_result, ibkr_error = send_backend_request("heartbeat", method="GET", timeout=5)
            if not ibkr_error and ibkr_result and "connected_to_ibkr" in ibkr_result:
                ibkr_status = ibkr_result["connected_to_ibkr"]
                # Update our state if it's different
                if connection_state["ibkr_connected"] != ibkr_status:
                    connection_state["ibkr_connected"] = ibkr_status
                    connection_state["last_ibkr_status"] = ibkr_status
        
        return jsonify({
            "frontend": "running",
            "backend": backend_status,
            "backend_configured": True,
            "connected_to_ibkr": ibkr_status,
            "last_heartbeat": connection_state["last_backend_heartbeat"].isoformat() if connection_state["last_backend_heartbeat"] else None,
            "heartbeat_failures": connection_state["heartbeat_failures"],
            "reconnect_in_progress": connection_state["reconnect_in_progress"],
            "socket_connected": socket_state["connected"],
            "socket_clients": len(socket_state["clients"])
        })
    except Exception as e:
        app.logger.error(f"Status check error: {str(e)}")
        return jsonify({
            "frontend": "running",
            "backend": "error",
            "backend_configured": True,
            "connected_to_ibkr": connection_state["ibkr_connected"],
            "heartbeat_failures": connection_state["heartbeat_failures"],
            "error": str(e),
            "socket_connected": socket_state["connected"]
        })

# Enhanced heartbeat route to include IBKR status
@app.route('/heartbeat', methods=['GET'])
def heartbeat():
    """Enhanced endpoint to check server heartbeat and IBKR status"""
    try:
        # Get IBKR connection status from backend if possible
        result, error = send_backend_request("heartbeat", method="GET", timeout=5)
        ibkr_connected = False
        
        if not error and result and "connected_to_ibkr" in result:
            ibkr_connected = result["connected_to_ibkr"]
            # Update our internal state if it's different
            if connection_state["ibkr_connected"] != ibkr_connected:
                connection_state["ibkr_connected"] = ibkr_connected
                connection_state["last_ibkr_status"] = ibkr_connected
        else:
            # Use our internal state if we can't get from backend
            ibkr_connected = connection_state["ibkr_connected"]
        
        return jsonify({
            "status": "alive", 
            "timestamp": datetime.now().isoformat(),
            "connected_to_ibkr": ibkr_connected
        })
    except Exception as e:
        app.logger.error(f"Heartbeat error: {str(e)}")
        return jsonify({
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "connected_to_ibkr": connection_state["ibkr_connected"],
            "error": str(e)
        })

def heartbeat_check():
    """Enhanced background task to periodically check backend connectivity with focus on IBKR status"""
    while True:  # Always keep running, don't depend on connection_state["ibkr_connected"]
        try:
            result, error = send_backend_request("heartbeat", method="GET", timeout=5)
            
            if not error and result:
                # Update last backend heartbeat timestamp
                connection_state["last_backend_heartbeat"] = datetime.now()
                
                # Check for IBKR status from backend response
                # The backend should return 'connected_to_ibkr' in its response
                ibkr_status = False
                if "connected_to_ibkr" in result:
                    ibkr_status = result["connected_to_ibkr"]
                    
                    # Only update the UI if the status has changed
                    if connection_state["last_ibkr_status"] != ibkr_status:
                        app.logger.info(f"IBKR connection status changed: {connection_state['last_ibkr_status']} -> {ibkr_status}")
                        connection_state["ibkr_connected"] = ibkr_status
                        connection_state["last_ibkr_status"] = ibkr_status
                        
                        # Broadcast status change to all connected clients
                        socketio.emit('connection_status', {
                            "success": ibkr_status,
                            "message": "Connected to IBKR" if ibkr_status else "Not Connected to IBKR",
                            "reconnect_in_progress": connection_state["reconnect_in_progress"],
                            "socket_connected": socket_state["connected"]
                        })
                
                # IMPORTANT CHANGE: Only reset heartbeat failures if both backend and IBKR are connected
                if ibkr_status:
                    connection_state["heartbeat_failures"] = 0
                else:
                    # Increment failures if IBKR is disconnected
                    app.logger.warning("Backend is reachable but IBKR is disconnected")
                    connection_state["heartbeat_failures"] += 1
                
                socketio.emit('heartbeat', {
                    "status": "alive",
                    "timestamp": connection_state["last_backend_heartbeat"].isoformat(),
                    "ibkr_connected": ibkr_status
                })
            else:
                connection_state["heartbeat_failures"] += 1
                app.logger.warning(f"Heartbeat failure #{connection_state['heartbeat_failures']}: {error['error'] if error else 'Unknown error'}")
                
                socketio.emit('heartbeat', {
                    "status": "warning",
                    "error": error['error'] if error else "Unknown error",
                    "consecutive_failures": connection_state["heartbeat_failures"],
                    "max_failures": MAX_HEARTBEAT_FAILURES,
                    "ibkr_connected": connection_state["ibkr_connected"]  # Keep previous status
                })
            
            # Try to reconnect if either the backend is unreachable OR IBKR is disconnected
            # after multiple consecutive failures
            if connection_state["heartbeat_failures"] >= MAX_HEARTBEAT_FAILURES and not connection_state["reconnect_in_progress"]:
                app.logger.error(f"Maximum heartbeat failures reached ({MAX_HEARTBEAT_FAILURES}). Attempting verification...")
                verify_and_reconnect()
            
        except Exception as e:
            connection_state["heartbeat_failures"] += 1
            app.logger.error(f"Heartbeat check exception: {str(e)}")
            
            socketio.emit('heartbeat', {
                "status": "error",
                "error": str(e),
                "consecutive_failures": connection_state["heartbeat_failures"],
                "max_failures": MAX_HEARTBEAT_FAILURES,
                "ibkr_connected": connection_state["ibkr_connected"]  # Keep previous status
            })
            
            if connection_state["heartbeat_failures"] >= MAX_HEARTBEAT_FAILURES and not connection_state["reconnect_in_progress"]:
                app.logger.error(f"Maximum heartbeat failures reached ({MAX_HEARTBEAT_FAILURES}). Attempting verification...")
                verify_and_reconnect()
        
        # Wait before next check - should be at least 30 seconds to avoid too frequent checks
        socketio.sleep(30)

def start_heartbeat_check():
    """Start the continuous heartbeat check without the reconnection logic"""
    socketio.start_background_task(target=heartbeat_check)

def verify_and_reconnect():
    """Verify IBKR connection and attempt reconnection if needed"""
    # Only proceed if we're not already trying to reconnect
    if connection_state["reconnect_in_progress"]:
        return
        
    connection_state["reconnect_in_progress"] = True
    socketio.emit('connection_status', {
        "success": connection_state["ibkr_connected"],
        "message": "Verifying connection status...",
        "verifying": True,
        "socket_connected": socket_state["connected"]
    })
    
    try:
        # Check if backend is still alive
        backend_result, backend_error = send_backend_request("heartbeat", method="GET", timeout=10)
        
        if not backend_error:
            # Backend is responding, try to check actual connection status
            # verify_result, verify_error = send_backend_request("heatbeat", timeout=10)

            verify_result, verify_error = send_backend_request(
                "heartbeat",
                method="GET",
                timeout=10
            )

            
            if not verify_error and verify_result:
                # Get the actual IBKR connection status
                ibkr_status = verify_result.get('connected', False)
                
                # Update our connection status
                connection_state["ibkr_connected"] = ibkr_status
                connection_state["last_ibkr_status"] = ibkr_status
                
                if ibkr_status:
                    # We're actually still connected! Reset the heartbeat failure counter
                    app.logger.info("Connection verification successful - IBKR is connected!")
                    connection_state["heartbeat_failures"] = 0
                    connection_state["last_backend_heartbeat"] = datetime.now()
                    connection_state["reconnect_in_progress"] = False
                    
                    socketio.emit('connection_status', {
                        "success": True,
                        "message": "IBKR connection verified successfully",
                        "verified": True,
                        "socket_connected": socket_state["connected"]
                    })
                    return
                else:
                    # IBKR is not connected according to backend
                    app.logger.warning("Backend reports IBKR is not connected. Trying to reconnect...")
                    try_reconnect()
            else:
                # Verification failed
                app.logger.warning(f"IBKR connection verification failed with error: {verify_error['error'] if verify_error else 'Unknown error'}")
                try_reconnect()
        else:
            app.logger.warning(f"Backend verification failed with error: {backend_error['error']}")
            # Backend is unreachable, but we'll try reconnecting anyway
            try_reconnect()
            
    except Exception as e:
        app.logger.error(f"Connection verification failed: {str(e)}")
        try_reconnect()
    finally:
        # Make sure we reset the reconnect flag if something went wrong
        if connection_state["reconnect_in_progress"]:
            connection_state["reconnect_in_progress"] = False

def try_reconnect():
    """Attempt to reconnect to backend using stored connection parameters"""
    global last_connection_params
    
    if not connection_state["reconnect_in_progress"]:
        connection_state["reconnect_in_progress"] = True
    
    socketio.emit('connection_status', {
        "success": connection_state["ibkr_connected"],
        "message": "Connection lost or unstable. Attempting to reconnect...",
        "reconnecting": True,
        "socket_connected": socket_state["connected"]
    })
    
    # Check if we have connection params
    # if not last_connection_params or not all(last_connection_params.values()):
    #    app.logger.warning("No stored connection parameters available for auto-reconnect")
    #    connection_state["reconnect_in_progress"] = False
    #    socketio.emit('connection_status', {
    #        "success": connection_state["ibkr_connected"],
    #        "message": "Cannot auto-reconnect: No stored connection parameters",
    #        "reconnecting": False,
    #        "socket_connected": socket_state["connected"]
    #    })
    #   return
    if not last_connection_params or not all(last_connection_params.values()):
        app.logger.warning("Cannot auto-reconnect: no stored connection parameters")
        connection_state["reconnect_in_progress"] = False
        socketio.emit('connection_status', {
            "success": False,
            "message": "Cannot auto-reconnect: no stored connection parameters",
            "reconnecting": False,
            "socket_connected": socket_state["connected"]
        })
        return

   
    # Attempt to reconnect using the stored parameters
    app.logger.info(f"Attempting automatic reconnect with stored parameters: {json.dumps(last_connection_params)}")
    # result, error = send_backend_request("connect", json_data=last_connection_params)
    result, error = send_backend_request(
        "connect",
        method="POST",
        json_data=last_connection_params
    )

   
    if error:
        app.logger.error(f"Auto-reconnect failed: {error['error']}")
        connection_state["reconnect_in_progress"] = False
        socketio.emit('connection_status', {
            "success": connection_state["ibkr_connected"],  # Keep previous status
            "message": f"Auto-reconnect failed: {error['error']}",
            "reconnecting": False,
            "socket_connected": socket_state["connected"]
        })
    elif result and result.get('success'):
        app.logger.info("Auto-reconnect successful!")
        connection_state["ibkr_connected"] = True
        connection_state["last_ibkr_status"] = True
        connection_state["last_backend_heartbeat"] = datetime.now()
        connection_state["heartbeat_failures"] = 0
        connection_state["reconnect_in_progress"] = False
        
        socketio.emit('connection_status', {
            "success": True,
            "message": "Auto-reconnect successful",
            "reconnected": True,
            "socket_connected": socket_state["connected"]
        })
    else:
        app.logger.warning(f"Auto-reconnect received unexpected response: {json.dumps(result)}")
        connection_state["reconnect_in_progress"] = False
        socketio.emit('connection_status', {
            "success": connection_state["ibkr_connected"],  # Keep previous status
            "message": "Auto-reconnect failed with unexpected response from backend",
            "reconnecting": False,
            "socket_connected": socket_state["connected"],
            "details": result
        })

# Socket.IO event handlers
@socketio.on('connect')
def socket_connect():
    app.logger.info(f"Socket.IO client connected: {request.sid}")
    
    # Check if user is logged in (for authenticated sockets)
    if 'user_id' not in session:
        app.logger.warning(f"Unauthenticated socket connection attempt: {request.sid}")
        disconnect()
        return
    
    # Update socket state
    socket_state["connected"] = True
    socket_state["last_connected"] = datetime.now()
    socket_state["clients"].add(request.sid)
    
    # Send initial connection state to newly connected clients: Skipping initial emit here to avoid sending stale “Not Connected”
    # emit('connection_status', {
    #    "success": connection_state["ibkr_connected"],
    #    "message": "Connected to IBKR" if connection_state["ibkr_connected"] else "Not Connected",
    #    "reconnect_in_progress": connection_state["reconnect_in_progress"],
    #    "heartbeat_failures": connection_state["heartbeat_failures"],
    #    "socket_connected": True
    # })

@socketio.on('disconnect')
def socket_disconnect():
    app.logger.info(f"Socket.IO client disconnected: {request.sid}")
    # Remove client from tracked clients
    if request.sid in socket_state["clients"]:
        socket_state["clients"].remove(request.sid)
    
    # Update socket state
    if len(socket_state["clients"]) == 0:
        socket_state["connected"] = False
    
    # Note: We do NOT change the IBKR connection status here

@socketio.on('force_reconnect')
def force_reconnect():
    """Handle manual reconnect request from client"""
    # Check if user is logged in
    if 'user_id' not in session:
        app.logger.warning(f"Unauthenticated socket reconnect attempt: {request.sid}")
        disconnect()
        return
        
    app.logger.info(f"Manual reconnect requested by client: {request.sid}")
    if not connection_state["reconnect_in_progress"]:
        socketio.emit('connection_status', {
            "success": connection_state["ibkr_connected"],
            "message": "Initiating reconnection...",
            "reconnecting": True,
            "socket_connected": socket_state["connected"]
        })
        socketio.start_background_task(target=verify_and_reconnect)
    else:
        emit('connection_status', {
            "success": connection_state["ibkr_connected"],
            "message": "Reconnection already in progress",
            "reconnecting": True,
            "socket_connected": socket_state["connected"]
        })

@socketio.on_error()
def error_handler(e):
    app.logger.error(f"Socket.IO error: {str(e)}")

@app.route('/backend_heartbeat', methods=['GET'])
def backend_heartbeat():
    """Check if backend is responsive"""
    try:
        # Try to connect to backend with a short timeout
        result, error = send_backend_request("heartbeat", method="GET", timeout=5)
        if error:
            return jsonify({
                "status": "unreachable",
                "error": error['error']
            }), 503
        return jsonify({
            "status": "reachable",
            "backend_response": result
        })
    except Exception as e:
        app.logger.error(f"Backend heartbeat check failed: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/reset_heartbeat_failures', methods=['POST'])
@login_required
def reset_heartbeat_failures():
    """Manually reset heartbeat failures counter"""
    connection_state["heartbeat_failures"] = 0
    app.logger.info("Heartbeat failures counter manually reset")
    return jsonify({
        "success": True,
        "message": "Heartbeat failures counter reset",
        "heartbeat_failures": connection_state["heartbeat_failures"]
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    use_debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.logger.info(f"Starting Frontend Flask app on 0.0.0.0:{port} (Debug Mode: {use_debug})")
    socketio.run(app, host="0.0.0.0", port=port, debug=use_debug)

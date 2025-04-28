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

# Global state tracking
connection_state = {
    "connected": False, 
    "last_heartbeat": None,
    "heartbeat_failures": 0,
    "reconnect_in_progress": False
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

# ... (all other routes unchanged) ...

@app.route('/heartbeat', methods=['GET'])
def heartbeat_route():
    """Simple endpoint to check server heartbeat"""
    return jsonify({"status": "alive", "timestamp": datetime.now().isoformat()})


def heartbeat_check():
    """Background task to periodically check backend connectivity with enhanced error handling"""
    while connection_state["connected"]:
        try:
            result, error = send_backend_request("heartbeat", method="GET", timeout=5)

            # === SUCCESS: backend reports connected=True ===
            if not error and result and result.get("connected", False):
                connection_state["heartbeat_failures"] = 0
                connection_state["last_heartbeat"] = datetime.now()

                socketio.emit(
                    "connection_status",
                    {
                        "success": True,
                        "message": "Connected to IBKR",
                        "timestamp": connection_state["last_heartbeat"].isoformat(),
                    },
                )

            # === FAILURE: error or connected=False ===
            else:
                connection_state["heartbeat_failures"] += 1
                app.logger.warning(
                    f"Heartbeat failure #{connection_state['heartbeat_failures']}: "
                    f"{error.get('error') if error else 'Connected=False'}"
                )

                socketio.emit(
                    "connection_status",
                    {
                        "success": False,
                        "message": "Disconnected from IBKR",
                        "consecutive_failures": connection_state["heartbeat_failures"],
                        "max_failures": MAX_HEARTBEAT_FAILURES,
                    },
                )

                if connection_state["heartbeat_failures"] >= MAX_HEARTBEAT_FAILURES:
                    app.logger.error(
                        f"Maximum heartbeat failures reached ({MAX_HEARTBEAT_FAILURES}). Giving up until reconnect."
                    )
                    break

        except Exception as e:
            connection_state["heartbeat_failures"] += 1
            app.logger.error(f"Heartbeat check exception: {e}")

            socketio.emit(
                "connection_status",  # emit status on exception too
                {
                    "success": False,
                    "message": f"Heartbeat error: {e}",
                    "consecutive_failures": connection_state["heartbeat_failures"],
                    "max_failures": MAX_HEARTBEAT_FAILURES,
                },
            )

            if connection_state["heartbeat_failures"] >= MAX_HEARTBEAT_FAILURES:
                app.logger.error(
                    f"Maximum heartbeat failures reached ({MAX_HEARTBEAT_FAILURES}) in exception handler."
                )
                break

        # Wait 30 seconds before next check
        socketio.sleep(30)

# Ensure start_heartbeat_check and all other logic remains unchanged

import os
import subprocess
import threading
import time
import socket
import requests
from flask import Flask, request, Response, render_template, redirect, url_for, session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
# WARNING: This secret key should be stored securely and not hardcoded in production!
app.secret_key = "super_secret_key_change_this"  # used for session cookies

running_apps = {}
START_PORT = 9000  # internal sub-app ports

# -----------------------------
# Load users from text file
# -----------------------------
def load_users():
    """Loads user credentials from users.txt."""
    users = {}
    file_path = os.path.join(BASE_DIR, "users.txt")
    if not os.path.exists(file_path):
        print("[⚠️] users.txt not found, creating sample one...")
        with open(file_path, "w") as f:
            # Sample user for first run
            f.write("admin:1234\n")
    with open(file_path, "r") as f:
        for line in f:
            if ":" in line:
                user, pwd = line.strip().split(":", 1)
                users[user] = pwd
    return users

USERS = load_users()

# -----------------------------
# Utility functions
# -----------------------------
def is_port_open(port):
    """Checks if a given port is listening on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0

# Removed the install_requirements function as requested.
# Sub-app dependencies must be installed manually before running the main script.

def start_app(folder, port):
    """Starts a sub-application using its app.py in a separate process."""
    app_path = os.path.join(BASE_DIR, folder, "app.py")
    if not os.path.exists(app_path):
        print(f"[❌] {folder}/app.py not found")
        return

    # Installation logic removed per user request.
    # The sub-app is started directly.

    print(f"[🚀] Starting {folder} on port {port}")
    # Run the sub-app, passing the port as an argument
    subprocess.Popen(["python3", app_path, str(port)], cwd=os.path.join(BASE_DIR, folder))

    # Wait until port is open
    for _ in range(60): # 30 seconds total wait time
        if is_port_open(port):
            print(f"[✅] {folder} running on port {port}")
            return
        time.sleep(0.5)
    print(f"[⚠️] {folder} failed to start in time or port {port} not opened.")

# -----------------------------
# Authentication routes
# -----------------------------
def requires_auth(f):
    """Decorator to check if user is logged in."""
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ # Preserve function name for Flask routing
    return decorated_function

@app.route("/", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if USERS.get(username) == password:
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            # Use a message box/alert in the HTML template instead of `flash` for simplicity
            error_message = "Invalid username or password"
            return render_template("login.html", error=error_message)
    # Renders a simple login form (assuming login.html exists)
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Handles user logout."""
    session.pop("user", None)
    return redirect(url_for("login"))

# -----------------------------
# Dashboard page (after login)
# -----------------------------
@app.route("/dashboard")
@requires_auth
def dashboard():
    """Displays the list of running applications."""
    # Renders a dashboard with a list of apps (assuming dashboard.html exists)
    return render_template("dashboard.html", running_apps=running_apps, username=session["user"])

# -----------------------------
# Proxy requests to internal APIs
# -----------------------------
@app.route("/<folder>/", defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<folder>/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@requires_auth
def route_folder(folder, path):
    """Proxies requests to the running sub-application."""

    port = running_apps.get(folder)
    if not port:
        return Response(f"No running app for '{folder}'", status=404)

    # Ensure path starts with a single slash
    path = "/" + path if not path.startswith("/") else path
    target = f"http://127.0.0.1:{port}{path}"

    try:
        # Use request.args to pass query parameters
        resp = requests.request(
            method=request.method,
            url=target,
            params=request.args,
            # Forward headers, excluding hop-by-hop headers
            headers={k: v for (k, v) in request.headers if k.lower() not in ["host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"]},
            data=request.get_data(), # Raw request body data
            cookies=request.cookies,
            allow_redirects=False,
            timeout=120
        )
        
        # Prepare response headers, excluding hop-by-hop headers
        excluded = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded]
        
        return Response(resp.content, resp.status_code, headers)

    except requests.exceptions.Timeout:
        return Response(f"Proxy request timed out for {folder}", status=504)
    except requests.exceptions.ConnectionError:
        return Response(f"Could not connect to sub-app '{folder}' on port {port}", status=503)
    except Exception as e:
        print(f"Proxy error: {e}")
        return Response(f"Internal proxy error forwarding to {folder}", status=500)

# -----------------------------
# Main launcher
# -----------------------------
def main():
    """Initializes and runs the main application and sub-apps."""
    port = START_PORT
    
    # Check for sub-apps in subdirectories
    for folder in os.listdir(BASE_DIR):
        folder_path = os.path.join(BASE_DIR, folder)
        # Check if it's a directory and contains an app.py
        if os.path.isdir(folder_path) and os.path.exists(os.path.join(folder_path, "app.py")):
            # Assign a port and launch the app in a separate thread
            running_apps[folder] = port
            # Note: Dependencies for sub-apps are not automatically installed now.
            threading.Thread(target=start_app, args=(folder, port), daemon=True).start()
            port += 1

    time.sleep(3) # Give threads a moment to start
    print("[✅] All sub-apps initialization complete:", running_apps)

    main_port = int(os.environ.get("PORT", 8000))
    print(f"[🌐] Main Flask host running on PORT={main_port}")
    # Note: Flask's default development server is not recommended for production.
    # It also relies on the Werkzeug library.
    app.run(host="0.0.0.0", port=main_port)

if __name__ == "__main__":
    main()
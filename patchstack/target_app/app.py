import html
from flask import Flask, jsonify, make_response, request, render_template_string, redirect, url_for
from patchstack.target_app.auth import VulnerableAuthManager, SecureAuthManager
from patchstack.target_app.db import DatabaseManager


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-vulnerable-key-patchstack-day567"

    vulnerable_auth = VulnerableAuthManager()
    secure_auth = SecureAuthManager()
    db = DatabaseManager()

    HOME_HTML = """
    <!url html>
    <html>
    <head>
        <title>PatchStack Vulnerable Target App</title>
        <meta name="generator" content="Flask/3.0.0">
    </head>
    <body>
        <h1>PatchStack Target App</h1>
        <nav>
            <a href="/">Home</a> |
            <a href="/login">Login</a> |
            <a href="/search">Search</a> |
            <a href="/feedback">Feedback</a> |
            <a href="/profile">Profile</a> |
            <a href="/admin">Admin Panel</a> |
            <a href="/api/v1/info">API Info</a> |
            <a href="/api/v1/users">API Users</a> |
            <a href="/api/v1/sqli/user-vulnerable?id=101">SQLi User Test</a> |
            <a href="/api/v1/xss/search-vulnerable?q=security">XSS Search Test</a> |
            <a href="/api/user/102">IDOR Test</a>
        </nav>
        <p>Welcome to the controlled web application testbed for PatchStack security assessment.</p>
    </body>
    </html>
    """

    LOGIN_HTML = """
    <!url html>
    <html>
    <head><title>Login - PatchStack Target</title></head>
    <body>
        <h2>Account Login</h2>
        <form action="/api/v1/auth/login-vulnerable" method="POST">
            <label>Username: <input type="text" name="username" required></label><br>
            <label>Password: <input type="password" name="password" required></label><br>
            <button type="submit">Login</button>
        </form>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """

    SEARCH_HTML = """
    <!url html>
    <html>
    <head><title>Search - PatchStack Target</title></head>
    <body>
        <h2>Product Search</h2>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search query..." value="{{ query }}">
            <button type="submit">Search</button>
        </form>
        <p>Results for: {{ query }}</p>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """

    FEEDBACK_HTML = """
    <!url html>
    <html>
    <head><title>Feedback - PatchStack Target</title></head>
    <body>
        <h2>Send Feedback</h2>
        <form action="/feedback" method="POST">
            <label>Email: <input type="email" name="email" required></label><br>
            <label>Subject: <input type="text" name="subject"></label><br>
            <label>Comments: <textarea name="comments"></textarea></label><br>
            <button type="submit">Submit Feedback</button>
        </form>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """

    PROFILE_HTML = """
    <!url html>
    <html>
    <head><title>Profile - PatchStack Target</title></head>
    <body>
        <h2>User Profile</h2>
        <p>User ID: 1001</p>
        <a href="/feedback">Report Profile Issue</a> |
        <a href="/">Back to Home</a>
    </body>
    </html>
    """

    ADMIN_HTML = """
    <!url html>
    <html>
    <head><title>Admin Panel - PatchStack Target</title></head>
    <body>
        <h2>Admin Management Dashboard</h2>
        <form action="/admin" method="POST">
            <label>System Command: <input type="text" name="cmd"></label>
            <button type="submit">Execute</button>
        </form>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """

    def _set_headers(resp):
        resp.headers["Server"] = "Flask/3.0.0 (Werkzeug/3.0.1 Python/3.10 Ubuntu)"
        resp.headers["X-Powered-By"] = "PatchStack-TargetApp/1.0"
        return resp

    @app.route("/", methods=["GET"])
    def index():
        resp = make_response(render_template_string(HOME_HTML))
        resp.set_cookie("patchstack_visitor", "guest_session_v1", httponly=False)
        return _set_headers(resp)

    @app.route("/login", methods=["GET"])
    def login():
        resp = make_response(render_template_string(LOGIN_HTML))
        return _set_headers(resp)

    @app.route("/search", methods=["GET"])
    def search():
        query = request.args.get("q", "")
        resp = make_response(render_template_string(SEARCH_HTML, query=query))
        return _set_headers(resp)

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback():
        resp = make_response(render_template_string(FEEDBACK_HTML))
        return _set_headers(resp)

    @app.route("/profile", methods=["GET"])
    def profile():
        resp = make_response(render_template_string(PROFILE_HTML))
        return _set_headers(resp)

    @app.route("/admin", methods=["GET", "POST"])
    def admin():
        resp = make_response(render_template_string(ADMIN_HTML))
        return _set_headers(resp)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "patchstack-target-app"})

    @app.route("/api/v1/info", methods=["GET"])
    def info():
        return jsonify(
            {
                "app": "PatchStack Security Testbed",
                "description": "Controlled target web app for scanner verification",
                "environment": "development",
            }
        )

    @app.route("/api/v1/users", methods=["GET"])
    def users():
        return jsonify(
            [
                {"id": 1, "username": "admin", "role": "administrator"},
                {"id": 2, "username": "testuser", "role": "user"},
            ]
        )

    @app.route("/api/v1/headers-test", methods=["GET"])
    def headers_test():
        resp = make_response(jsonify({"message": "Header analysis endpoint"}))
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return _set_headers(resp)

    # --- Day 4 Auth Routes ---

    @app.route("/api/v1/auth/login-vulnerable", methods=["POST"])
    def login_vulnerable():
        data = request.get_json(silent=True) or request.form
        username = data.get("username", "")
        password = data.get("password", "")

        success, message, result, cookie_str = vulnerable_auth.login(username, password)
        status_code = 200 if success else 401

        resp = make_response(jsonify({"success": success, "message": message, "data": result}), status_code)
        if cookie_str:
            resp.headers["Set-Cookie"] = cookie_str
        return _set_headers(resp)

    @app.route("/api/v1/auth/login-secure", methods=["POST"])
    def login_secure():
        data = request.get_json(silent=True) or request.form
        username = data.get("username", "")
        password = data.get("password", "")

        success, message, result, cookie_str = secure_auth.login(username, password)
        status_code = 200 if success else (429 if "locked" in message.lower() else 401)

        resp = make_response(jsonify({"success": success, "message": message, "data": result}), status_code)
        if cookie_str:
            resp.headers["Set-Cookie"] = cookie_str
        return _set_headers(resp)

    # --- Day 5: SQL Injection Routes ---

    @app.route("/api/v1/sqli/user-vulnerable", methods=["GET"])
    def sqli_user_vulnerable():
        user_id = request.args.get("id", "101")
        success, rows, err = db.get_user_by_id_vulnerable(user_id)
        if not success:
            return _set_headers(make_response(f"sqlite3.OperationalError: {err}", 500))
        if not rows:
            return _set_headers(make_response(jsonify({"error": "User not found"}), 404))
        return _set_headers(make_response(jsonify(rows), 200))

    @app.route("/api/v1/sqli/user-secure", methods=["GET"])
    def sqli_user_secure():
        user_id = request.args.get("id", "101")
        success, rows, err = db.get_user_by_id_secure(user_id)
        if not success:
            return _set_headers(make_response(jsonify({"error": "Database error"}), 500))
        if not rows:
            return _set_headers(make_response(jsonify({"error": "User not found"}), 404))
        return _set_headers(make_response(jsonify(rows), 200))

    # --- Day 6: XSS Routes ---

    @app.route("/api/v1/xss/search-vulnerable", methods=["GET"])
    def xss_search_vulnerable():
        q = request.args.get("q", "")
        # Unescaped reflected HTML
        html_out = f"<html><body><h2>Search Results for: {q}</h2></body></html>"
        return _set_headers(make_response(html_out, 200))

    @app.route("/api/v1/xss/search-secure", methods=["GET"])
    def xss_search_secure():
        q = request.args.get("q", "")
        # Context-aware HTML entity encoding
        safe_q = html.escape(q)
        html_out = f"<html><body><h2>Search Results for: {safe_q}</h2></body></html>"
        return _set_headers(make_response(html_out, 200))

    # --- Day 7: IDOR Routes ---

    @app.route("/api/v1/idor/user-vulnerable/<int:user_id>", methods=["GET"])
    @app.route("/api/user/<int:user_id>", methods=["GET"])
    def idor_user_vulnerable(user_id):
        # Vulnerable IDOR: Returns user object without checking session ownership
        success, rows, _ = db.get_user_by_id_secure(str(user_id))
        if not rows:
            return _set_headers(make_response(jsonify({"error": "User not found"}), 404))
        return _set_headers(make_response(jsonify(rows[0]), 200))

    @app.route("/api/v1/idor/user-secure/<int:user_id>", methods=["GET"])
    @app.route("/api/user-secure/<int:user_id>", methods=["GET"])
    def idor_user_secure(user_id):
        # Secure IDOR fix: Verify session cookie matches requested user_id
        cookie = request.headers.get("Cookie", "")
        # Extract authenticated user_id from session cookie token
        session_user_id = 101 if "user101" in cookie or "SESSION-USER-101" in cookie or "101" in cookie else None

        if not session_user_id or session_user_id != user_id:
            return _set_headers(make_response(jsonify({"error": "Forbidden: You are not authorized to access this resource"}), 403))

        success, rows, _ = db.get_user_by_id_secure(str(user_id))
        return _set_headers(make_response(jsonify(rows[0]), 200))

    # --- Harness Test Routes ---

    @app.route("/api/v1/insecure-cookie", methods=["GET"])
    def insecure_cookie_test():
        resp = make_response(jsonify({"status": "cookie_set"}))
        resp.set_cookie("auth_token", "secret12345", httponly=False, secure=False)
        return _set_headers(resp)

    @app.route("/api/v1/info-leak", methods=["GET"])
    def info_leak_test():
        resp = make_response(jsonify({"status": "info_leak"}))
        resp.headers["Server"] = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3"
        resp.headers["X-Powered-By"] = "PHP/7.4.3"
        resp.headers["X-AspNet-Version"] = "4.0.30319"
        return resp

    @app.route("/api/v1/debug-methods", methods=["GET", "POST", "OPTIONS", "TRACE", "PUT", "DELETE"])
    def debug_methods_test():
        if request.method == "OPTIONS":
            resp = make_response("", 200)
            resp.headers["Allow"] = "GET, POST, OPTIONS, TRACE, PUT, DELETE"
            return resp
        if request.method == "TRACE":
            resp = make_response("TRACE /api/v1/debug-methods HTTP/1.1", 200)
            resp.headers["Content-Type"] = "message/http"
            return resp
        resp = make_response(jsonify({"method": request.method}))
        return _set_headers(resp)

    @app.route("/api/v1/cors-vulnerable", methods=["GET", "OPTIONS"])
    def cors_vulnerable_test():
        resp = make_response(jsonify({"status": "cors_test"}))
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return _set_headers(resp)

    return app

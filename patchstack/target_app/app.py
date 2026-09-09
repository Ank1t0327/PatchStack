from flask import Flask, jsonify, make_response, request, render_template_string, redirect, url_for


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-vulnerable-key-patchstack-day3"

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
            <a href="/api/v1/insecure-cookie">Insecure Cookie Test</a> |
            <a href="/api/v1/info-leak">Info Leak Test</a> |
            <a href="/api/v1/cors-vulnerable">CORS Vulnerable Test</a>
        </nav>
        <p>Welcome to the controlled web application testbed for PatchStack reconnaissance & vulnerability assessment.</p>
    </body>
    </html>
    """

    LOGIN_HTML = """
    <!url html>
    <html>
    <head><title>Login - PatchStack Target</title></head>
    <body>
        <h2>Account Login</h2>
        <form action="/login" method="POST">
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

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            resp = make_response(redirect(url_for("profile")))
            resp.set_cookie("session", "patchstack_auth_session_token_8899", httponly=True)
            return _set_headers(resp)
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

    # --- Day 3 Test Harness Routes ---

    @app.route("/api/v1/insecure-cookie", methods=["GET"])
    def insecure_cookie_test():
        resp = make_response(jsonify({"status": "cookie_set"}))
        # Intentionally insecure cookie: no HttpOnly, no Secure, no SameSite
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

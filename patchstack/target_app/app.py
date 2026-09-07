from flask import Flask, jsonify, make_response, request


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-vulnerable-key-patchstack-day1"

    @app.route("/", methods=["GET"])
    def index():
        resp = make_response(
            jsonify(
                {
                    "name": "PatchStack Controlled Vulnerable Target",
                    "status": "running",
                    "version": "1.0.0",
                    "endpoints": ["/health", "/api/v1/info", "/api/v1/headers-test"],
                }
            )
        )
        # Intentionally omit security headers for detection harness
        resp.headers["Server"] = "Flask/3.0.0 (Werkzeug/3.0.1 Python/3.10)"
        resp.headers["X-Powered-By"] = "PatchStack-TargetApp/1.0"
        return resp

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

    @app.route("/api/v1/headers-test", methods=["GET"])
    def headers_test():
        resp = make_response(jsonify({"message": "Header analysis endpoint"}))
        # Intentionally dynamic CORS misconfiguration stub for testing
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    return app

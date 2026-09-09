from typing import Dict, Any, List
from patchstack.recon.models import TargetFingerprint
from patchstack.scanner.http_client import HTTPResponseTelemetry


class TechnologyFingerprinter:
    """
    Analyzes HTTP telemetry to identify server technology, web frameworks, and application stack.
    """

    @classmethod
    def analyze(cls, telemetry: HTTPResponseTelemetry, meta_tags: Dict[str, str] = None) -> TargetFingerprint:
        meta_tags = meta_tags or {}
        headers = {k.lower(): v for k, v in telemetry.headers.items()}
        cookies = telemetry.cookies
        body = telemetry.body

        server = headers.get("server", "Unknown")
        x_powered_by = headers.get("x-powered-by", "")

        technologies: List[str] = []
        framework = "Unknown"
        language = "Unknown"

        # Server detection
        if "werkzeug" in server.lower() or "flask" in server.lower() or "flask" in x_powered_by.lower():
            server = server if server != "Unknown" else "Werkzeug/Flask"
            framework = "Flask"
            language = "Python"
            technologies.append("Flask")
            technologies.append("Python")

        elif "gunicorn" in server.lower():
            technologies.append("Gunicorn")
            language = "Python"

        elif "uvicorn" in server.lower():
            framework = "FastAPI"
            language = "Python"
            technologies.append("FastAPI")
            technologies.append("Uvicorn")

        elif "express" in x_powered_by.lower():
            framework = "Express"
            language = "Node.js"
            technologies.append("Express.js")
            technologies.append("Node.js")

        elif "nginx" in server.lower():
            technologies.append("Nginx")

        elif "apache" in server.lower():
            technologies.append("Apache")

        # Cookie signatures
        for cookie_name in cookies.keys():
            cookie_lower = cookie_name.lower()
            if cookie_lower in ("session", "flask_session"):
                if framework == "Unknown":
                    framework = "Flask"
                    language = "Python"
                technologies.append("Flask Session Cookie")
            elif cookie_lower in ("sessionid", "csrftoken"):
                framework = "Django"
                language = "Python"
                technologies.append("Django Session")
            elif cookie_lower == "phpsessid":
                language = "PHP"
                technologies.append("PHP Session")
            elif cookie_lower == "jsessionid":
                language = "Java"
                technologies.append("Java Servlet")

        # HTML Body / Meta tag signatures
        if "generator" in meta_tags:
            gen = meta_tags["generator"]
            technologies.append(f"Generator: {gen}")

        if "jinja" in body.lower() or "werkzeug" in body.lower():
            technologies.append("Jinja2 Templates")

        # Remove duplicate technologies
        unique_techs = list(dict.fromkeys(technologies))

        return TargetFingerprint(
            server=server,
            framework=framework,
            programming_language=language,
            technologies=unique_techs,
            headers=dict(telemetry.headers),
            cookies=cookies,
        )

import argparse
import sys
from patchstack.target_app.app import create_app


def main():
    parser = argparse.ArgumentParser(description="Start PatchStack Target Vulnerable Web Application")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Run Flask app in debug mode")

    args = parser.parse_args()

    app = create_app()
    print(f"[*] Starting PatchStack Target App on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

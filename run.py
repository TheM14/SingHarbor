#!/usr/bin/env python
"""SingHarbor entry point.

Usage:
    python run.py                        # Start with defaults
    python run.py --host 0.0.0.0         # Listen on all interfaces
    python run.py --port 8443            # Custom port
    python run.py --config config.json   # Custom config file
    python run.py --debug                # Debug mode

Install dependencies from requirements.txt in a Python 3.12+ environment.
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.app import create_app
from src.config import AppConfig


def parse_args():
    parser = argparse.ArgumentParser(
        description="SingHarbor - sing-box Management WebUI"
    )
    parser.add_argument(
        "--host", default=None,
        help="Host address to bind (default: from config or 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Port to listen on (default: from config or 51080)"
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="Path to SingHarbor configuration file"
    )
    parser.add_argument(
        "--debug", action="store_true", default=False,
        help="Enable debug mode"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    config_path = Path(args.config) if args.config else None
    app = create_app(config_path)

    host = args.host or app.config["app_config"].listen_host
    port = args.port or app.config["app_config"].listen_port

    print(f"SingHarbor starting on http://{host}:{port}")
    print(f"Data directory: {app.config['app_config'].data_dir}")

    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\n" + "=" * 70)
        print("  SECURITY WARNING: Binding to non-localhost address!")
        print(f"  SingHarbor will listen on {host}:{port}")
        print()
        print("  SingHarbor provides NO built-in HTTPS, certificate management,")
        print("  or firewall configuration. Exposing it on a public network")
        print("  is strongly discouraged without a proper HTTPS reverse proxy.")
        print("=" * 70 + "\n")

    from waitress import serve
    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()

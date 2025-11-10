#!/usr/bin/env python3
"""Simple smoke test: import the Flask app and request '/' to ensure HTML is served.

Run this from the repository root with the project's Python environment activated.
"""
import os
import sys

# Ensure the parent directory (python-service) is importable when running this file.
THIS_DIR = os.path.dirname(__file__)
SERVICE_DIR = os.path.dirname(THIS_DIR)
sys.path.insert(0, SERVICE_DIR)

from app import app

def run_smoke_test():
    with app.app_context():
        client = app.test_client()
        resp = client.get('/')
        print(f"GET / -> status {resp.status_code}")
        body = resp.get_data(as_text=True)

        if resp.status_code != 200:
            print("FAIL: Expected status 200 for /")
            print(body[:400])
            raise SystemExit(2)

        # Look for HTML markers in the response
        lowered = body.lower()
        if '<!doctype' in lowered or '<html' in lowered:
            print("PASS: Root served HTML")
            return

        print("FAIL: Root did not return HTML. Response preview:")
        print(body[:800])
        raise SystemExit(3)

if __name__ == '__main__':
    run_smoke_test()

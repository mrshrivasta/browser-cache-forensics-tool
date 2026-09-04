#!/usr/bin/env python3
"""
Browser Cache Forensics Tool — Web application entrypoint.
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Usage:
    python3 run.py                # runs on http://127.0.0.1:5000
    FLASK_DEBUG=1 python3 run.py  # with debug reloader

DISCLAIMER: This tool real-parses REAL Chrome/Chromium Simple Cache entry
files found on the machine it runs on. Only run it against browser profiles
you own or are explicitly authorized to examine. See README.md for the full
disclaimer.
"""
import os
from app.factory import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", 5000))
    print("=" * 70)
    print(" Browser Cache Forensics Tool — developed by Karanam Shrivasta")
    print(" GitHub:   https://github.com/mrshrivasta")
    print(" LinkedIn: https://www.linkedin.com/in/karanam-shrivasta")
    print(" DISCLAIMER: Authorized use only. See README.md.")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=debug)

import os
import sys

# Make sure the project root (one level up from /api) is on the path so
# "from app import app" can find app.py.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402

# Vercel's Python runtime looks for a top-level WSGI callable named `app`
# in this file. Nothing else is required -- do NOT call app.run() or
# socketio.run() here; Vercel invokes `app` directly per-request.

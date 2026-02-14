"""
minicorn — A lightweight, production-grade WSGI and ASGI server.

Inspired by Uvicorn and Gunicorn, minicorn provides a simple CLI for serving
PEP 3333 compliant WSGI applications and ASGI applications (FastAPI, Starlette, etc.)
with auto-reload support for development.
"""

__version__ = "0.1.0"
__all__ = ["serve", "run", "serve_asgi", "run_asgi"]

# WSGI server exports
from minicorn.wsgi_server import serve, run

# ASGI server exports
from minicorn.asgi_server import serve_asgi, run_asgi

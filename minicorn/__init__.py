"""
minicorn — A lightweight, production-grade synchronous WSGI server.

Inspired by Uvicorn and Gunicorn, minicorn provides a simple CLI for serving
PEP 3333 compliant WSGI applications with auto-reload support for development.
"""

__version__ = "0.1.0"
__all__ = ["serve", "run"]

from minicorn.server import serve, run

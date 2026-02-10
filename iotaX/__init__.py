"""
iotaX — A lightweight, production-grade synchronous WSGI server.

Inspired by Uvicorn and Gunicorn, iotaX provides a simple CLI for serving
PEP 3333 compliant WSGI applications with auto-reload support for development.
"""

__version__ = "0.1.0"
__all__ = ["serve", "run"]

from iotaX.server import serve, run

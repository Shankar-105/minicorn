"""
minicorn/asgi_server.py — Production-grade asynchronous ASGI server core.
Designed to serve ASGI 3.0 compliant applications (FastAPI, Starlette, etc.)
using Python's asyncio for concurrent request handling.
"""

import asyncio
import socket
import sys
import datetime
import logging
import importlib
import signal
from typing import Callable, Any, Optional
from urllib.parse import unquote

# Default Configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888
MAX_HEADER_SIZE = 64 * 1024         # 64 KB — reject oversized headers
MAX_BODY_SIZE = 1 * 1024 * 1024     # 1 MB — reject oversized bodies
RECV_CHUNK = 8192                   # bytes per recv call

# Module-level logger (configured by CLI or calling code)
log = logging.getLogger("minicorn")

# HTTP status code helpers
_STATUS_PHRASES = {
    200: "OK",
    400: "Bad Request",
    408: "Request Timeout",
    413: "Payload Too Large",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
}


def _http_date() -> str:
    """RFC 7231 date for the Date header."""
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )


def _build_error_response(status_code: int, message: str = "") -> bytes:
    """Build a minimal, valid HTTP/1.1 error response."""
    phrase = _STATUS_PHRASES.get(status_code, "Error")
    body = f"{status_code} {phrase}\r\n{message}".encode("utf-8")
    return (
        f"HTTP/1.1 {status_code} {phrase}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Date: {_http_date()}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8") + body


def load_app(app_path: str) -> Callable:
    """
    Load an ASGI application from a module:attribute string.
    Examples:
        "main:app" → from main import app
        "myproject.api:application" → from myproject.api import application
    """
    if ":" not in app_path:
        raise ValueError(
            f"Invalid app path: {app_path!r}. "
            "Expected format: 'module:attribute' (e.g., 'main:app')"
        )
    
    module_path, attr_name = app_path.rsplit(":", 1)
    
    # Add current directory to sys.path if not already there
    import os
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    
    try:
        # Import or reload the module
        if module_path in sys.modules:
            module = importlib.reload(sys.modules[module_path])
        else:
            module = importlib.import_module(module_path)
    except ImportError as e:
        raise ImportError(f"Could not import module '{module_path}': {e}") from e
    
    try:
        app = getattr(module, attr_name)
    except AttributeError:
        raise AttributeError(
            f"Module '{module_path}' has no attribute '{attr_name}'"
        )
    
    if not callable(app):
        raise TypeError(f"'{module_path}:{attr_name}' is not callable")
    
    return app


async def _read_request(reader: asyncio.StreamReader) -> dict | None:
    """
    Read and parse one HTTP request from the stream.
    Returns a dict with keys:
        method, path, raw_path, query_string, version, headers, body
    or None when the peer closes the connection cleanly.
    """
    # Read headers
    header_data = b""
    while b"\r\n\r\n" not in header_data:
        if len(header_data) > MAX_HEADER_SIZE:
            raise ValueError("Headers exceed maximum allowed size")
        try:
            chunk = await asyncio.wait_for(reader.read(RECV_CHUNK), timeout=30.0)
        except asyncio.TimeoutError:
            raise ValueError("Request timeout")
        if not chunk:
            if not header_data:
                return None  # Clean close
            raise ValueError("Connection closed during header read")
        header_data += chunk
    
    # Split headers and any body that came with it
    header_end = header_data.index(b"\r\n\r\n")
    header_bytes = header_data[:header_end]
    body_start = header_data[header_end + 4:]
    
    # Parse request line
    lines = header_bytes.split(b"\r\n")
    if not lines:
        raise ValueError("Empty request")
    
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ValueError(f"Malformed request line: {request_line}")
    
    method, raw_path, version = parts
    
    # Parse path and query string
    if "?" in raw_path:
        path_part, query_string = raw_path.split("?", 1)
    else:
        path_part = raw_path
        query_string = ""
    
    path = unquote(path_part)
    
    # Parse headers
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            name, _, value = line.partition(b":")
            header_name = name.decode("latin-1").strip().lower()
            header_value = value.decode("latin-1").strip()
            headers[header_name] = header_value
    
    # Read body if Content-Length specified
    content_length = int(headers.get("content-length", 0))
    if content_length > MAX_BODY_SIZE:
        raise ValueError("Body exceeds maximum allowed size")
    
    body = body_start
    while len(body) < content_length:
        remaining = content_length - len(body)
        chunk = await asyncio.wait_for(
            reader.read(min(remaining, RECV_CHUNK)), 
            timeout=30.0
        )
        if not chunk:
            break
        body += chunk
    
    return {
        "method": method,
        "path": path,
        "raw_path": raw_path,
        "query_string": query_string.encode("latin-1"),
        "version": version,
        "headers": headers,
        "body": body,
    }


def _build_scope(
    request: dict,
    client_addr: tuple,
    server_host: str,
    server_port: int,
) -> dict:
    """Build ASGI scope dict from parsed request."""
    # Convert headers to ASGI format: list of [name, value] byte tuples
    headers = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in request["headers"].items()
    ]
    
    # Extract HTTP version number (e.g., "HTTP/1.1" -> "1.1")
    http_version = request["version"].replace("HTTP/", "")
    
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": http_version,
        "method": request["method"],
        "scheme": "http",
        "path": request["path"],
        "raw_path": request["raw_path"].encode("latin-1"),
        "query_string": request["query_string"],
        "root_path": "",
        "headers": headers,
        "server": (server_host, server_port),
        "client": client_addr,
    }


class ASGIServer:
    """
    An asynchronous ASGI server instance.
    Attributes:
        host: Bind address
        port: Bind port
        app: The ASGI application callable
        should_exit: Flag to signal server shutdown
    """
    
    def __init__(
        self,
        app: Callable,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
    ):
        self.app = app
        self.host = host
        self.port = port
        self.should_exit = False
        self._server: Optional[asyncio.Server] = None
    
    def signal_exit(self):
        """Signal the server to stop accepting new connections."""
        self.should_exit = True
        if self._server:
            self._server.close()
    
    def shutdown(self):
        """Close the server."""
        self.should_exit = True
        if self._server:
            self._server.close()
            self._server = None
    
    def serve(self):
        """Run the async server using asyncio.run()."""
        try:
            asyncio.run(self._serve_async())
        except KeyboardInterrupt:
            log.info("Interrupted")
    
    async def _serve_async(self):
        """Main async server loop."""
        import os
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
            reuse_address=True,
        )
        
        log.info("Started ASGI server process [%d]", os.getpid())
        log.info("Listening on http://%s:%s", self.host, self.port)
        
        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.signal_exit)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass
        async with self._server:
            try:
                await self._server.serve_forever()
            except asyncio.CancelledError:
                pass
        
        log.info("ASGI server stopped")
    
    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle one client connection."""
        client_addr = writer.get_extra_info("peername")
        if client_addr is None:
            client_addr = ("unknown", 0)
        
        try:
            # Read the HTTP request
            try:
                request = await _read_request(reader)
            except ValueError as e:
                log.warning("%s:%s → 400 %s", client_addr[0], client_addr[1], e)
                writer.write(_build_error_response(400, str(e)))
                await writer.drain()
                return
            
            if request is None:
                # Clean close
                return
            
            log.info(
                '%s:%s - "%s %s %s"',
                client_addr[0], client_addr[1],
                request["method"], request["raw_path"], request["version"],
            )
            
            # Build ASGI scope
            scope = _build_scope(request, client_addr, self.host, self.port)
            
            # State for receive/send
            body_sent = False
            request_body = request["body"]
            response_started = False
            response_status = 200
            
            async def receive() -> dict:
                """ASGI receive callable."""
                nonlocal body_sent
                if body_sent:
                    # Simulate disconnect after body is consumed
                    return {"type": "http.disconnect"}
                body_sent = True
                return {
                    "type": "http.request",
                    "body": request_body,
                    "more_body": False,
                }
            
            async def send(message: dict):
                """ASGI send callable."""
                nonlocal response_started, response_status
                
                if message["type"] == "http.response.start":
                    response_started = True
                    response_status = message["status"]
                    status_phrase = _STATUS_PHRASES.get(response_status, "")
                    
                    # Build response line
                    response_line = f"HTTP/1.1 {response_status} {status_phrase}\r\n"
                    writer.write(response_line.encode("latin-1"))
                    
                    # Write headers
                    headers = message.get("headers", [])
                    has_date = False
                    has_server = False
                    
                    for name, value in headers:
                        if isinstance(name, bytes):
                            name = name.decode("latin-1")
                        if isinstance(value, bytes):
                            value = value.decode("latin-1")
                        
                        if name.lower() == "date":
                            has_date = True
                        if name.lower() == "server":
                            has_server = True
                        
                        writer.write(f"{name}: {value}\r\n".encode("latin-1"))
                    
                    # Add default headers
                    if not has_date:
                        writer.write(f"Date: {_http_date()}\r\n".encode("latin-1"))
                    if not has_server:
                        writer.write(b"Server: minicorn\r\n")
                    
                    writer.write(b"\r\n")
                    await writer.drain()
                
                elif message["type"] == "http.response.body":
                    body = message.get("body", b"")
                    if body:
                        writer.write(body)
                        await writer.drain()
            
            # Call the ASGI application
            try:
                await self.app(scope, receive, send)
            except Exception as e:
                log.error("ASGI app raised an exception: %s", e, exc_info=True)
                if not response_started:
                    writer.write(_build_error_response(500, "Internal Server Error"))
                    await writer.drain()
                return
            
            log.info(
                '%s:%s - "%s %s" %s',
                client_addr[0], client_addr[1],
                request["method"], request["raw_path"],
                response_status,
            )
        
        except Exception as e:
            log.error("Error handling connection: %s", e, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def serve_asgi(app_path: str, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    """
    Load and serve an ASGI application.
    Args:
        app_path: Module path in format "module:attribute" (e.g., "main:app")
        host: Host address to bind to
        port: Port number to bind to
    """
    app = load_app(app_path)
    server = ASGIServer(app, host, port)
    server.serve()


def run_asgi(app: Callable, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    """
    Serve an ASGI application directly (already imported).
    Args:
        app: An ASGI callable
        host: Host address to bind to
        port: Port number to bind to
    """
    server = ASGIServer(app, host, port)
    server.serve()

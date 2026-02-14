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
DEFAULT_PORT = 8000
MAX_HEADER_SIZE = 64 * 1024         # 64 KB — reject oversized headers
MAX_BODY_SIZE = 1 * 1024 * 1024     # 1 MB — reject oversized bodies
RECV_TIMEOUT = 10.0                 # seconds before recv times out (408)
KEEP_ALIVE_TIMEOUT = 15.0           # idle timeout between kept-alive requests
MAX_KEEP_ALIVE_REQUESTS = 100       # max requests per single TCP connection
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

async def _read_request(reader: asyncio.StreamReader, timeout: float = RECV_TIMEOUT) -> dict | None:
    """
    Read and parse one HTTP request from the stream.
    Returns a dict with keys:
        method, path, raw_path, query_string, version, headers, body
    or None when the peer closes the connection cleanly.
    Raises ValueError on malformed / oversized / timed-out requests.
    """
    # Read headers
    header_data = b""
    while b"\r\n\r\n" not in header_data:
        if len(header_data) > MAX_HEADER_SIZE:
            raise ValueError("Headers exceed maximum allowed size")
        try:
            chunk = await asyncio.wait_for(reader.read(RECV_CHUNK),timeout=timeout)
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
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(remaining, RECV_CHUNK)), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            raise ValueError("Timeout reading request body")
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


def _wants_keep_alive(request: dict) -> bool:
    """Return True if the client wants (and is allowed) to keep-alive."""
    conn = request["headers"].get("connection", "").lower()
    version = request["version"]
    if version == "HTTP/1.1":
        # HTTP/1.1 defaults to keep-alive unless "close" is specified
        return "close" not in conn
    # HTTP/1.0 requires explicit "keep-alive"
    return "keep-alive" in conn


class ASGIResponseHandler:
    """
    Handles ASGI receive/send lifecycle for a single HTTP request.
    
    Encapsulates the state and callbacks for communication between
    the ASGI application and the HTTP connection.
    """
    
    def __init__(
        self,
        writer: asyncio.StreamWriter,
        request_body: bytes,
        keep_alive: bool = True,
    ):
        self.writer = writer
        self.request_body = request_body
        self.keep_alive = keep_alive
        
        # State tracking
        self.body_sent = False
        self.response_started = False
        self.response_status = 200
        self.response_complete = False
    
    async def receive(self) -> dict:
        """
        ASGI receive callable.
        
        Returns the request body on first call, then signals disconnect.
        """
        if self.body_sent:
            # After body is consumed, signal disconnect
            return {"type": "http.disconnect"}
        
        self.body_sent = True
        return {
            "type": "http.request",
            "body": self.request_body,
            "more_body": False,
        }
    
    async def send(self, message: dict):
        """
        ASGI send callable.
        
        Handles http.response.start and http.response.body messages.
        """
        if message["type"] == "http.response.start":
            await self._send_response_start(message)
        
        elif message["type"] == "http.response.body":
            await self._send_response_body(message)
    
    async def _send_response_start(self, message: dict):
        """Handle http.response.start message."""
        self.response_started = True
        self.response_status = message["status"]
        status_phrase = _STATUS_PHRASES.get(self.response_status, "")
        
        # Build and write response line
        response_line = f"HTTP/1.1 {self.response_status} {status_phrase}\r\n"
        self.writer.write(response_line.encode("latin-1"))
        
        # Write headers
        headers = message.get("headers", [])
        has_date = False
        has_server = False
        has_connection = False
        
        for name, value in headers:
            if isinstance(name, bytes):
                name = name.decode("latin-1")
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            
            name_lower = name.lower()
            if name_lower == "date":
                has_date = True
            elif name_lower == "server":
                has_server = True
            elif name_lower == "connection":
                has_connection = True
            
            self.writer.write(f"{name}: {value}\r\n".encode("latin-1"))
        
        # Add default headers
        if not has_date:
            self.writer.write(f"Date: {_http_date()}\r\n".encode("latin-1"))
        if not has_server:
            self.writer.write(b"Server: minicorn\r\n")
        if not has_connection:
            if self.keep_alive:
                self.writer.write(
                    f"Connection: keep-alive\r\n"
                    f"Keep-Alive: timeout={int(KEEP_ALIVE_TIMEOUT)}, max={MAX_KEEP_ALIVE_REQUESTS}\r\n"
                    .encode("latin-1")
                )
            else:
                self.writer.write(b"Connection: close\r\n")
        
        self.writer.write(b"\r\n")
        await self.writer.drain()
    
    async def _send_response_body(self, message: dict):
        """Handle http.response.body message."""
        body = message.get("body", b"")
        if body:
            self.writer.write(body)
            await self.writer.drain()
        
        # Check if this is the final body chunk
        if not message.get("more_body", False):
            self.response_complete = True


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
        """Handle one TCP connection (potentially many keep-alive requests)."""
        client_addr = writer.get_extra_info("peername")
        if client_addr is None:
            client_addr = ("unknown", 0)
        
        requests_served = 0
        
        try:
            for request_num in range(1, MAX_KEEP_ALIVE_REQUESTS + 1):
                if self.should_exit:
                    break
                
                # Use shorter timeout for subsequent keep-alive requests
                timeout = RECV_TIMEOUT if request_num == 1 else KEEP_ALIVE_TIMEOUT
                
                # Read the HTTP request
                try:
                    request = await _read_request(reader, timeout=timeout)
                except ValueError as e:
                    error_msg = str(e)
                    if "timeout" in error_msg.lower():
                        # Timeout on keep-alive is normal, just close
                        if request_num > 1:
                            log.debug(
                                "%s:%s keep-alive timeout after %d request(s)",
                                client_addr[0], client_addr[1], requests_served
                            )
                            return
                        log.warning("%s:%s → 408 %s", client_addr[0], client_addr[1], e)
                        writer.write(_build_error_response(408, str(e)))
                    else:
                        log.warning("%s:%s → 400 %s", client_addr[0], client_addr[1], e)
                        writer.write(_build_error_response(400, str(e)))
                    await writer.drain()
                    return
                except Exception:
                    log.error("Unexpected error reading request", exc_info=True)
                    writer.write(_build_error_response(400))
                    await writer.drain()
                    return
                
                if request is None:
                    # Clean close by client
                    log.debug(
                        "%s:%s closed connection after %d request(s)",
                        client_addr[0], client_addr[1], requests_served
                    )
                    return
                
                # Determine keep-alive
                keep_alive = _wants_keep_alive(request)
                if request_num >= MAX_KEEP_ALIVE_REQUESTS:
                    keep_alive = False
                
                log.info(
                    '%s:%s - "%s %s %s"',
                    client_addr[0], client_addr[1],
                    request["method"], request["raw_path"], request["version"],
                )
                
                # Build ASGI scope
                scope = _build_scope(request, client_addr, self.host, self.port)
                
                # Create response handler
                handler = ASGIResponseHandler(
                    writer=writer,
                    request_body=request["body"],
                    keep_alive=keep_alive,
                )
                
                # Call the ASGI application
                try:
                    await self.app(scope, handler.receive, handler.send)
                except Exception as e:
                    log.error("ASGI app raised an exception: %s", e, exc_info=True)
                    if not handler.response_started:
                        writer.write(_build_error_response(500, "Internal Server Error"))
                        await writer.drain()
                    return
                
                log.info(
                    '%s:%s - "%s %s" %s',
                    client_addr[0], client_addr[1],
                    request["method"], request["raw_path"],
                    handler.response_status,
                )
                requests_served += 1
                
                # Stop if not keeping alive
                if not keep_alive:
                    return
        
        except Exception as e:
            log.error("Fatal error in connection handler: %s", e, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            log.debug(
                "%s:%s connection closed (%d request(s) served)",
                client_addr[0], client_addr[1], requests_served
            )


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

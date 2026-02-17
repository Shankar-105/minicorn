"""
minicorn/asgi_server.py — Production-grade asynchronous ASGI server core.
Designed to serve ASGI 3.0 compliant applications (FastAPI, Starlette, etc.)
using Python's asyncio for concurrent request handling.
Supports both HTTP/1.1 and WebSocket (RFC 6455) on the same port.
"""

import asyncio
import base64
import hashlib
import socket
import struct
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
WS_MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB max WebSocket message

# WebSocket constants (RFC 6455)
WS_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_OPCODE_CONTINUATION = 0x00
WS_OPCODE_TEXT = 0x01
WS_OPCODE_BINARY = 0x02
WS_OPCODE_CLOSE = 0x08
WS_OPCODE_PING = 0x09
WS_OPCODE_PONG = 0x0A

# WebSocket close codes
WS_CLOSE_NORMAL = 1000
WS_CLOSE_GOING_AWAY = 1001
WS_CLOSE_PROTOCOL_ERROR = 1002
WS_CLOSE_UNSUPPORTED_DATA = 1003
WS_CLOSE_NO_STATUS = 1005
WS_CLOSE_ABNORMAL = 1006
WS_CLOSE_INVALID_PAYLOAD = 1007
WS_CLOSE_POLICY_VIOLATION = 1008
WS_CLOSE_MESSAGE_TOO_BIG = 1009
WS_CLOSE_INTERNAL_ERROR = 1011

# Module-level logger (configured by CLI or calling code)
log = logging.getLogger("minicorn")

# HTTP status code helpers
_STATUS_PHRASES = {
    101: "Switching Protocols",
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    408: "Request Timeout",
    413: "Payload Too Large",
    426: "Upgrade Required",
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


# WebSocket helpers

def _compute_ws_accept_key(key: str) -> str:
    """
    Compute ``Sec-WebSocket-Accept`` value per RFC 6455 §4.2.2.
    accept = base64( sha1( key + MAGIC ) )
    """
    digest = hashlib.sha1(
        (key.strip() + WS_MAGIC_STRING).encode("ascii")
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def _is_websocket_upgrade(request: dict) -> bool:
    """
    Return True if the parsed HTTP request is a valid WebSocket upgrade.

    Checks:
        - ``Upgrade`` header contains ``websocket`` (case-insensitive)
        - ``Connection`` header contains ``upgrade`` (case-insensitive)
        - ``Sec-WebSocket-Version`` is ``13``
        - ``Sec-WebSocket-Key`` is present
    """
    headers = request["headers"]
    upgrade = headers.get("upgrade", "").lower()
    connection = headers.get("connection", "").lower()
    version = headers.get("sec-websocket-version", "")
    key = headers.get("sec-websocket-key", "")

    return (
        "websocket" in upgrade
        and "upgrade" in connection
        and version == "13"
        and len(key) > 0
    )


def _build_ws_accept_response(key: str, subprotocol: Optional[str] = None) -> bytes:
    """Build the HTTP 101 Switching Protocols response for WebSocket."""
    accept = _compute_ws_accept_key(key)
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept}",
        f"Server: minicorn",
        f"Date: {_http_date()}",
    ]
    if subprotocol:
        lines.append(f"Sec-WebSocket-Protocol: {subprotocol}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("latin-1")


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
    """
    Build ASGI scope dict from parsed request.

    Automatically detects WebSocket upgrade requests and returns a
    ``"websocket"`` scope instead of ``"http"`` when appropriate.
    """
    # Convert headers to ASGI format: list of [name, value] byte tuples
    headers = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in request["headers"].items()
    ]
    
    # Extract HTTP version number (e.g., "HTTP/1.1" -> "1.1")
    http_version = request["version"].replace("HTTP/", "")

    is_ws = _is_websocket_upgrade(request)

    if is_ws:
        # Parse requested subprotocols from Sec-WebSocket-Protocol header
        proto_header = request["headers"].get("sec-websocket-protocol", "")
        subprotocols = [
            p.strip() for p in proto_header.split(",") if p.strip()
        ] if proto_header else []

        return {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": http_version,
            "scheme": "ws",
            "path": request["path"],
            "raw_path": request["raw_path"].encode("latin-1"),
            "query_string": request["query_string"],
            "root_path": "",
            "headers": headers,
            "server": (server_host, server_port),
            "client": client_addr,
            "subprotocols": subprotocols,
        }

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


# WebSocket frame I/O and ASGI handler

async def _ws_read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """Read exactly *n* bytes from *reader*, raising on premature EOF."""
    data = b""
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            raise ConnectionError("WebSocket connection closed during read")
        data += chunk
    return data


def _ws_apply_mask(data: bytes, mask: bytes) -> bytes:
    """XOR *data* with 4-byte *mask* (RFC 6455 §5.3)."""
    ba = bytearray(data)
    for i in range(len(ba)):
        ba[i] ^= mask[i % 4]
    return bytes(ba)


def _ws_build_frame(
    opcode: int,
    payload: bytes = b"",
    fin: bool = True,
) -> bytes:
    """
    Build a WebSocket frame to send from the server.

    Server frames are never masked (RFC 6455 §5.1).
    Supports 7-bit, 16-bit, and 64-bit payload lengths.
    """
    first_byte = (0x80 if fin else 0x00) | (opcode & 0x0F)
    length = len(payload)

    if length <= 125:
        header = struct.pack("!BB",first_byte,length)
    elif length <= 0xFFFF:
        header = struct.pack("!BBH",first_byte,126,length)
    else:
        header = struct.pack("!BBQ",first_byte,127,length)
    return header + payload

class WebSocketHandler:
    """
    Manages the full lifecycle of a single WebSocket connection:
    handshake completion, frame I/O, and ASGI event translation.

    The handler exposes ``receive`` and ``send`` async callables that
    are passed to the ASGI application as the second and third arguments.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: dict,
        client_addr: tuple,
        ping_interval: Optional[float] = None,
        ping_timeout: Optional[float] = None,
    ):
        self.reader = reader
        self.writer = writer
        self.request = request
        self.client_addr = client_addr

        # Connection state
        self.accepted = False
        self.closed = False
        self.close_code: int = WS_CLOSE_NORMAL
        self.close_sent = False
        self.close_received = False
        self.chosen_subprotocol: Optional[str] = None

        # For continuation-frame reassembly
        self._frag_opcode: Optional[int] = None
        self._frag_buffer: bytearray = bytearray()

        # Transport-level ping/pong keep-alive
        self._ping_interval: Optional[float] = ping_interval
        self._ping_timeout: Optional[float] = ping_timeout
        self._pong_received: asyncio.Event = asyncio.Event()
        self._ping_task: Optional[asyncio.Task] = None

    # ASGI receive callable

    async def receive(self) -> dict:
        """
        ASGI receive callable for WebSocket connections.

        Before ``websocket.accept`` is sent by the app, returns a
        ``websocket.connect`` event.  After acceptance, reads frames
        and translates them into ``websocket.receive`` or
        ``websocket.disconnect`` events.
        """
        if not self.accepted:
            # The ASGI app has not yet accepted the connection.
            return {"type": "websocket.connect"}

        if self.closed:
            return {"type": "websocket.disconnect", "code": self.close_code}

        # Read frames until we have a complete application message
        while True:
            try:
                fin, opcode, payload = await self._read_frame()
            except (ConnectionError, asyncio.IncompleteReadError):
                if not self.closed:
                    self.close_code = WS_CLOSE_ABNORMAL
                self.closed = True
                return {"type": "websocket.disconnect", "code": self.close_code}
            except ValueError:
                # Protocol error — send close and disconnect
                await self._send_close(WS_CLOSE_PROTOCOL_ERROR)
                self.closed = True
                self.close_code = WS_CLOSE_PROTOCOL_ERROR
                return {"type": "websocket.disconnect", "code": self.close_code}

            # Control frames (always fin=1, payload ≤ 125)
            if opcode == WS_OPCODE_PING:
                # Auto-respond with pong (same payload)
                await self._write_frame(WS_OPCODE_PONG, payload)
                continue

            if opcode == WS_OPCODE_PONG:
                # Signal the ping loop that a pong was received
                self._pong_received.set()
                continue

            if opcode == WS_OPCODE_CLOSE:
                code = WS_CLOSE_NORMAL
                if len(payload) >= 2:
                    code = struct.unpack("!H", payload[:2])[0]
                self.close_received = True
                if not self.close_sent:
                    await self._send_close(code)
                self.closed = True
                self.close_code = code
                return {"type": "websocket.disconnect", "code": code}

            #  Data frames 
            if opcode in (WS_OPCODE_TEXT, WS_OPCODE_BINARY):
                if not fin:
                    # Start of a fragmented message
                    self._frag_opcode = opcode
                    self._frag_buffer = bytearray(payload)
                    continue
                # Unfragmented message
                return self._message_event(opcode, payload)

            if opcode == WS_OPCODE_CONTINUATION:
                if self._frag_opcode is None:
                    raise ValueError("Unexpected continuation frame")
                self._frag_buffer.extend(payload)
                if len(self._frag_buffer) > WS_MAX_MESSAGE_SIZE:
                    await self._send_close(WS_CLOSE_MESSAGE_TOO_BIG)
                    self.closed = True
                    self.close_code = WS_CLOSE_MESSAGE_TOO_BIG
                    return {"type": "websocket.disconnect", "code": self.close_code}
                if fin:
                    event = self._message_event(
                        self._frag_opcode, bytes(self._frag_buffer)
                    )
                    self._frag_opcode = None
                    self._frag_buffer = bytearray()
                    return event
                continue

            # Unknown opcode — protocol error
            await self._send_close(WS_CLOSE_PROTOCOL_ERROR)
            self.closed = True
            self.close_code = WS_CLOSE_PROTOCOL_ERROR
            return {"type": "websocket.disconnect", "code": self.close_code}

    # ASGI send callable

    async def send(self, message: dict):
        """
        ASGI send callable for WebSocket connections.

        Handles ``websocket.accept``, ``websocket.send``, and
        ``websocket.close`` message types.
        """
        msg_type = message.get("type", "")

        if msg_type == "websocket.accept":
            await self._do_accept(message)

        elif msg_type == "websocket.send":
            if not self.accepted or self.closed:
                raise RuntimeError(
                    "Cannot send on a WebSocket that is not accepted or is closed"
                )
            text = message.get("text")
            data = message.get("bytes")
            if text is not None:
                await self._write_frame(WS_OPCODE_TEXT, text.encode("utf-8"))
            elif data is not None:
                await self._write_frame(WS_OPCODE_BINARY, data)
            else:
                raise ValueError("websocket.send must include 'text' or 'bytes'")

        elif msg_type == "websocket.close":
            code = message.get("code", WS_CLOSE_NORMAL)
            if not self.accepted:
                # Reject before handshake — send HTTP 403
                self.writer.write(
                    _build_error_response(403, "WebSocket rejected")
                )
                await self.writer.drain()
                self.closed = True
                self.close_code = code
            elif not self.closed:
                await self._send_close(code)
                self.closed = True
                self.close_code = code

        elif msg_type == "websocket.http.response.start":
            # Some ASGI apps send an HTTP response to reject the upgrade
            pass

        elif msg_type == "websocket.http.response.body":
            pass

    # Internal handshake / framing

    async def _do_accept(self, message: dict):
        """Complete the WebSocket handshake by sending 101."""
        self.chosen_subprotocol = message.get("subprotocol")
        headers = message.get("headers", [])

        ws_key = self.request["headers"].get("sec-websocket-key", "")
        accept_key = _compute_ws_accept_key(ws_key)

        # Build 101 response
        lines = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Accept: {accept_key}",
            "Server: minicorn",
            f"Date: {_http_date()}",
        ]
        if self.chosen_subprotocol:
            lines.append(f"Sec-WebSocket-Protocol: {self.chosen_subprotocol}")

        # Extra headers from the ASGI app
        for name, value in headers:
            if isinstance(name, bytes):
                name = name.decode("latin-1")
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            lines.append(f"{name}: {value}")

        lines.append("")
        lines.append("")
        self.writer.write("\r\n".join(lines).encode("latin-1"))
        await self.writer.drain()

        self.accepted = True

        # Start the transport-level ping loop if configured
        if self._ping_interval is not None:
            self._ping_task = asyncio.create_task(self._ping_loop())

        log.info(
            "%s:%s - WebSocket accepted on %s",
            self.client_addr[0], self.client_addr[1],
            self.request["path"],
        )

    async def _ping_loop(self):
        """
        Background task: periodically send WebSocket ping frames.

        Runs for the lifetime of the connection.  Sends a ping every
        ``_ping_interval`` seconds.  If ``_ping_timeout`` is also set,
        waits up to that many seconds for a pong reply — on timeout
        the connection is closed with code 1001 (Going Away) and the
        underlying transport is shut down so that any blocked
        ``_read_frame()`` call unblocks immediately.
        """
        try:
            while not self.closed:
                # Sleep for the configured interval
                await asyncio.sleep(self._ping_interval)
                if self.closed:
                    break

                # Clear the flag so we can detect the *next* pong
                self._pong_received.clear()

                # Send a ping frame to the client
                try:
                    await self._write_frame(WS_OPCODE_PING, b"minicorn")
                except Exception:
                    break  # Socket already dead

                log.debug(
                    "%s:%s - WebSocket ping sent",
                    self.client_addr[0], self.client_addr[1],
                )

                # If a timeout is configured, wait for the pong
                if self._ping_timeout is not None:
                    try:
                        await asyncio.wait_for(
                            self._pong_received.wait(),
                            timeout=self._ping_timeout,
                        )
                        log.debug(
                            "%s:%s - WebSocket pong received",
                            self.client_addr[0], self.client_addr[1],
                        )
                    except asyncio.TimeoutError:
                        log.warning(
                            "%s:%s - WebSocket pong timeout "
                            "(no pong within %.1fs) — closing connection",
                            self.client_addr[0], self.client_addr[1],
                            self._ping_timeout,
                        )
                        # Mark as closed and send close frame
                        self.close_code = WS_CLOSE_GOING_AWAY
                        self.closed = True
                        await self._send_close(WS_CLOSE_GOING_AWAY)
                        # Shut down the transport to unblock _read_frame()
                        try:
                            self.writer.close()
                        except Exception:
                            pass
                        return
        except asyncio.CancelledError:
            # Normal: task is cancelled when the connection ends
            return
        except Exception as exc:
            log.debug("Ping loop error: %s", exc)

    async def _read_frame(self) -> tuple:
        """
        Read one WebSocket frame from the wire.

        Returns ``(fin: bool, opcode: int, payload: bytes)``.
        Client frames MUST be masked; unmasked frames raise ``ValueError``.
        """
        # First 2 bytes: FIN/RSV/opcode + MASK/length
        head = await _ws_read_exact(self.reader, 2)
        first, second = head[0], head[1]

        fin = bool(first & 0x80)
        rsv = (first >> 4) & 0x07
        if rsv:
            raise ValueError("RSV bits set without negotiated extension")
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F

        # Clients MUST mask frames
        if not masked:
            raise ValueError("Client frame is not masked")

        # Extended payload length
        if length == 126:
            raw = await _ws_read_exact(self.reader, 2)
            length = struct.unpack("!H", raw)[0]
        elif length == 127:
            raw = await _ws_read_exact(self.reader, 8)
            length = struct.unpack("!Q", raw)[0]

        if length > WS_MAX_MESSAGE_SIZE:
            raise ValueError("Frame payload too large")

        # Masking key (4 bytes)
        mask = await _ws_read_exact(self.reader, 4)

        # Payload
        payload = await _ws_read_exact(self.reader, length) if length else b""
        payload = _ws_apply_mask(payload, mask)

        return fin, opcode, payload

    async def _write_frame(self, opcode: int, payload: bytes = b""):
        """Write a single WebSocket frame (server → client, unmasked)."""
        self.writer.write(_ws_build_frame(opcode, payload))
        await self.writer.drain()

    async def _send_close(self, code: int = WS_CLOSE_NORMAL):
        """Send a WebSocket close frame with the given status code."""
        if self.close_sent:
            return
        self.close_sent = True
        payload = struct.pack("!H",code)
        try:
            await self._write_frame(WS_OPCODE_CLOSE, payload)
        except Exception:
            pass  # Ignore write errors during close

    @staticmethod
    def _message_event(opcode: int, payload: bytes) -> dict:
        """Translate a data frame into an ASGI websocket.receive event."""
        if opcode == WS_OPCODE_TEXT:
            return {
                "type": "websocket.receive",
                "text": payload.decode("utf-8", errors="replace"),
            }
        return {
            "type": "websocket.receive",
            "bytes": payload,
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
        ws_ping_interval: Optional[float] = None,
        ws_ping_timeout: Optional[float] = None,
    ):
        self.app = app
        self.host = host
        self.port = port
        self.ws_ping_interval = ws_ping_interval
        self.ws_ping_timeout = ws_ping_timeout
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
        # On Windows, reuse_address=True sets SO_REUSEADDR which allows multiple
        # processes to bind to the same port (port hijacking). Disable it on
        # Windows and rely on SO_EXCLUSIVEADDRUSE via start_server's default.
        # On Linux/macOS, SO_REUSEADDR is safe and only allows reusing TIME_WAIT ports.
        if sys.platform == "win32":
            self._server = await asyncio.start_server(
                self._handle_connection,
                self.host,
                self.port,
                reuse_address=False,
            )
            # Set SO_EXCLUSIVEADDRUSE on the underlying socket(s) to prevent
            # another process from binding to the same port.
            for sock in self._server.sockets:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_EXCLUSIVEADDRUSE,  # type: ignore[attr-defined]
                    1,
                )
        else:
            self._server = await asyncio.start_server(
                self._handle_connection,
                self.host,
                self.port,
                reuse_address=True,
            )
        
        log.info("Started ASGI server process [%d]", os.getpid())
        log.info("Listening on http://%s:%s", self.host, self.port)
        if self.ws_ping_interval is not None:
            log.info(
                "WebSocket ping: interval=%.1fs, timeout=%s",
                self.ws_ping_interval,
                f"{self.ws_ping_timeout:.1f}s" if self.ws_ping_timeout else "disabled",
            )
        
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

                #  WebSocket branch 
                if scope["type"] == "websocket":
                    await self._handle_websocket(
                        scope, request, reader, writer, client_addr,
                    )
                    # WebSocket connections are persistent — no keep-alive
                    # loop; exit after the WS session ends.
                    return

                #  HTTP branch 
                
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

    # WebSocket connection handler

    async def _handle_websocket(
        self,
        scope: dict,
        request: dict,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_addr: tuple,
    ):
        """
        Drive the ASGI WebSocket lifecycle for a single connection.
        1. Create a ``WebSocketHandler`` (receive/send callables).
        2. Invoke ``self.app(scope, receive, send)``.
        3. On exit, send a close frame if the app did not.
        """
        handler = WebSocketHandler(
            reader, writer, request, client_addr,
            ping_interval=self.ws_ping_interval,
            ping_timeout=self.ws_ping_timeout,
        )

        try:
            await self.app(scope, handler.receive, handler.send)
        except Exception as exc:
            log.error(
                "%s:%s - WebSocket app error: %s",
                client_addr[0], client_addr[1], exc,
                exc_info=True,
            )
        finally:
            # Cancel the ping task if it is running
            if handler._ping_task is not None:
                handler._ping_task.cancel()
                try:
                    await handler._ping_task
                except (asyncio.CancelledError, Exception):
                    pass
            # Ensure a close frame was sent
            if handler.accepted and not handler.close_sent:
                try:
                    await handler._send_close(WS_CLOSE_GOING_AWAY)
                except Exception:
                    pass
            log.info(
                "%s:%s - WebSocket closed (code=%d) on %s",
                client_addr[0], client_addr[1],
                handler.close_code, request["path"],
            )

def serve_asgi(
    app_path: str,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ws_ping_interval: Optional[float] = None,
    ws_ping_timeout: Optional[float] = None,
):
    """
    Load and serve an ASGI application.
    Args:
        app_path: Module path in format "module:attribute" (e.g., "main:app")
        host: Host address to bind to
        port: Port number to bind to
        ws_ping_interval: Seconds between WebSocket pings (None = disabled)
        ws_ping_timeout: Seconds to wait for pong before closing (None = no timeout)
    """
    app = load_app(app_path)
    server = ASGIServer(
        app, host, port,
        ws_ping_interval=ws_ping_interval,
        ws_ping_timeout=ws_ping_timeout,
    )
    server.serve()


def run_asgi(
    app: Callable,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ws_ping_interval: Optional[float] = None,
    ws_ping_timeout: Optional[float] = None,
):
    """
    Serve an ASGI application directly (already imported).
    Args:
        app: An ASGI callable
        host: Host address to bind to
        port: Port number to bind to
        ws_ping_interval: Seconds between WebSocket pings (None = disabled)
        ws_ping_timeout: Seconds to wait for pong before closing (None = no timeout)
    """
    server = ASGIServer(
        app, host, port,
        ws_ping_interval=ws_ping_interval,
        ws_ping_timeout=ws_ping_timeout,
    )
    server.serve()

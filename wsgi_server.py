"""
wsgi_server.py — Production-grade synchronous WSGI server (single-threaded).

Designed to serve any PEP 3333 compliant WSGI application (Flask, Django, etc.)
with Gunicorn-level robustness for the synchronous / blocking model.
"""

import socket
import sys
import datetime
import logging
import traceback
from io import BytesIO
from urllib.parse import unquote, urlparse

# Configuration
HOST = "127.0.0.1"
PORT = 8000
BACKLOG = 128                       # pending-connection queue depth
MAX_HEADER_SIZE = 64 * 1024         # 64 KB — reject oversized headers
MAX_BODY_SIZE = 1 * 1024 * 1024     # 1 MB — reject oversized bodies
RECV_TIMEOUT = 10                   # seconds before recv times out (408)
KEEP_ALIVE_TIMEOUT = 15             # idle timeout between kept-alive requests
MAX_KEEP_ALIVE_REQUESTS = 100       # max requests per single TCP connection
RECV_CHUNK = 8192                   # bytes per recv call

# Logging config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wsgi_server")

# Import the WSGI application currently hardcoded
try:
    from main import app as _flask_app
    WSGI_APP = _flask_app.wsgi_app          # Flask → pure WSGI callable
    log.info("Loaded WSGI application from main.py")
except Exception:
    log.critical("Failed to import WSGI app from main.py", exc_info=True)
    sys.exit(1)


# HTTP status code Error Helpers
_STATUS_PHRASES = {
    200: "OK",
    400: "Bad Request",
    408: "Request Timeout",
    413: "Payload Too Large",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
}

# helper for date in logs
def _http_date() -> str:
    """RFC 7231 date for the Date header."""
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )

# error response
def _build_error_response(status_code: int, message: str = "") -> bytes:
    """Build a minimal, valid HTTP/1.1 error response."""
    phrase = _STATUS_PHRASES.get(status_code,"Error")
    body = f"{status_code} {phrase}\r\n{message}".encode("utf-8")
    return (
        f"HTTP/1.1 {status_code} {phrase}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Date: {_http_date()}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8") + body


def _safe_send(sock: socket.socket,data: bytes) -> bool:
    """Send data, returning False if client disconnected."""
    try:
        sock.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
        return False


# Header-injection prevention
def _sanitize_header_value(value: str) -> str:
    """Strip CR / LF to prevent header injection attacks."""
    return value.replace("\r", "").replace("\n", "")


# custom exception class 
class _RequestError(Exception):
    """Raised when request parsing detects a client error."""
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)

# read the full data from user
def read_full_request(sock: socket.socket) -> dict | None:
    """
    Read and parse one full HTTP/1.x request from *sock*.
    Returns a dict with keys:
        method, path, raw_path, version, headers, body
    or None when the peer closes the connection cleanly (EOF).
    Raises _RequestError on malformed / oversized / timed-out requests.
    """
    # intialyy body  buffer
    buf = b""

    # ── Phase 1: accumulate bytes until we see the header terminator ──
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER_SIZE:
            raise _RequestError(431, "Headers exceed maximum allowed size")
        try:
            chunk = sock.recv(RECV_CHUNK)
        except socket.timeout:
            raise _RequestError(408, "Timed out waiting for request data")
        except OSError as exc:
            log.warning("recv error during header read: %s", exc)
            return None
        if not chunk:                       # clean EOF
            return None
        buf += chunk

    header_end = buf.index(b"\r\n\r\n")
    header_bytes = buf[: header_end]        # raw headers (no trailing CRLFCRLF)
    body_so_far = buf[header_end + 4 :]     # anything already read past headers

    # ── Phase 2: parse the request line ──
    try:
        header_text = header_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise _RequestError(400, "Headers not decodable")

    lines = header_text.split("\r\n")
    if not lines:
        raise _RequestError(400, "Empty request")

    request_line = lines[0]
    parts = request_line.split(None, 2)     # METHOD SP PATH SP VERSION
    if len(parts) != 3:
        raise _RequestError(400, f"Malformed request line: {request_line!r}")
    method, raw_path, version = parts
    method = method.upper()

    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise _RequestError(400, f"Unsupported HTTP version: {version}")

    # ── Phase 3: parse headers ──
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            raise _RequestError(400, f"Malformed header line: {line!r}")
        key, value = line.split(":",1) # KEY SP VALUE
        key = key.strip().lower()
        value = _sanitize_header_value(value.strip())
        headers[key] = value

    # ── Phase 4: read body bytes guided by Content-Length ──
    content_length = 0
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"])
        except ValueError:
            raise _RequestError(400, "Invalid Content-Length")
        if content_length < 0:
            raise _RequestError(400, "Negative Content-Length")

    if content_length > MAX_BODY_SIZE:
        raise _RequestError(413, f"Body of {content_length} bytes exceeds limit of {MAX_BODY_SIZE}")

    remaining = content_length - len(body_so_far)
    while remaining > 0:
        try:
            chunk = sock.recv(min(RECV_CHUNK, remaining))
        except socket.timeout:
            raise _RequestError(408, "Timed out reading request body")
        except OSError as exc:
            log.warning("recv error during body read: %s", exc)
            return None
        if not chunk:
            raise _RequestError(400, "Client disconnected before sending full body")
        body_so_far += chunk
        remaining -= len(chunk)

    # Trim body to declared length (discard pipelined bytes—simple server)
    body = body_so_far[:content_length]

    return {
        "method": method,
        "raw_path": raw_path,               # e.g. "/caf%C3%A9?q=1"
        "path": raw_path.split("?", 1)[0],  # e.g. "/caf%C3%A9"
        "version": version,
        "headers": headers,
        "body": body,
    }


# WSGI Environ Builder
def build_environ(request: dict, client_addr: tuple) -> dict:
    """
    Build a PEP 3333 compliant environ dictionary from a parsed request.
    """
    raw_path = request["raw_path"]
    path_part = raw_path.split("?", 1)[0]

    # URL-decode PATH_INFO so Flask routing works with encoded chars
    path_info = unquote(path_part)
    query_string = raw_path.split("?", 1)[1] if "?" in raw_path else ""

    headers = request["headers"]
    body = request["body"]

    environ = {
        # ── CGI / required variables (PEP 3333 §3.2) ──
        "REQUEST_METHOD":   request["method"],
        "SCRIPT_NAME":      "",                          # root-mounted
        "PATH_INFO":        path_info,
        "QUERY_STRING":     query_string,
        "CONTENT_TYPE":     headers.get("content-type", ""),
        "CONTENT_LENGTH":   str(len(body)),
        "SERVER_NAME":      HOST,
        "SERVER_PORT":      str(PORT),
        "SERVER_PROTOCOL":  request["version"],

        # ── WSGI-specific keys ──
        "wsgi.version":      (1, 0),
        "wsgi.url_scheme":   "http",
        "wsgi.input":        BytesIO(body),
        "wsgi.errors":       sys.stderr,
        "wsgi.multithread":  False,
        "wsgi.multiprocess": False,
        "wsgi.run_once":     False,
        "wsgi.file_wrapper": _FileWrapper,               # for efficient file serving

        # ── Client info ──
        "REMOTE_ADDR":      client_addr[0],
        "REMOTE_HOST":      client_addr[0],              # no reverse-DNS
        "REMOTE_PORT":      str(client_addr[1]),
    }

    # ── Promote HTTP headers into HTTP_* variables ──
    for key, value in headers.items():
        env_key = key.upper().replace("-", "_")
        if key in ("content-type", "content-length"):
            continue                                     # already set above for content-type,length
        environ[f"HTTP_{env_key}"] = value

    return environ


class _FileWrapper:
    """
    wsgi.file_wrapper — wraps a file-like object for efficient iteration.
    Matches the interface Gunicorn / uWSGI expose.
    """
    def __init__(self, filelike, blksize=8192):
        self.filelike = filelike
        self.blksize = blksize
        if hasattr(filelike, "close"):
            self.close = filelike.close

    def __iter__(self):
        while True:
            data = self.filelike.read(self.blksize)
            if not data:
                break
            yield data


# Response Writer (supports streaming + chunked)
def send_response(
    sock: socket.socket,
    status: str,
    response_headers: list[tuple[str, str]],
    body_iterable,
    keep_alive: bool,
) -> bool:
    """
    Serialise and send an HTTP response.
    Supports:
        - Content-Length bodies (known length → send as-is)
        - Chunked Transfer-Encoding (unknown length → stream chunks)
        - Streaming iterators (does not buffer entire body in RAM)
    Returns True if the response was sent successfully.
    """
    # Build header dict for easy look-up (keep original list for output)
    hdr_map: dict[str, str] = {}
    for k, v in response_headers:
        hdr_map[k.lower()] = v

    # Decide transfer strategy: Content-Length wins, else chunked
    has_content_length = "content-length" in hdr_map
    use_chunked = not has_content_length

    # ── Assemble header block ──
    status_line = f"HTTP/1.1 {status}\r\n"
    hdr_lines = ""

    # Server + Date (always)
    hdr_lines += f"Date: {_http_date()}\r\n"
    hdr_lines += "Server: wsgi_server/1.0\r\n"

    # Connection management
    if keep_alive:
        hdr_lines += "Connection: keep-alive\r\n"
        hdr_lines += f"Keep-Alive: timeout={KEEP_ALIVE_TIMEOUT}, max={MAX_KEEP_ALIVE_REQUESTS}\r\n"
    else:
        hdr_lines += "Connection: close\r\n"

    if use_chunked:
        hdr_lines += "Transfer-Encoding: chunked\r\n"

    # App-provided headers (sanitized)
    for name, value in response_headers:
        clean_val = _sanitize_header_value(value)
        hdr_lines += f"{name}: {clean_val}\r\n"

    head = (status_line + hdr_lines + "\r\n").encode("utf-8")
    if not _safe_send(sock, head):
        return False

    # ── Send body ──
    try:
        for chunk in body_iterable:
            if not chunk:
                continue
            if use_chunked:
                frame = f"{len(chunk):x}\r\n".encode("utf-8") + chunk + b"\r\n"
                if not _safe_send(sock, frame):
                    return False
            else:
                if not _safe_send(sock, chunk):
                    return False

        # Chunked terminator
        if use_chunked:
            if not _safe_send(sock, b"0\r\n\r\n"):
                return False
    finally:
        # WSGI spec: if iterable has .close(), server MUST call it
        if hasattr(body_iterable,"close"):
            try:
                body_iterable.close()
            except Exception:
                log.debug("Error closing body iterable", exc_info=True)

    return True


# start_response callable (per-request, closure-based)
def make_start_response():
    """
    Factory that returns (start_response_callable, state_dict).
    state_dict is mutated by start_response and read by the server after
    the WSGI app returns.
    """
    state = {
        "status": None,
        "headers": [],
        "exc_info": None,
        "headers_sent": False,
    }

    def start_response(status, headers, exc_info=None):
        if exc_info:
            try:
                if state["headers_sent"]:
                    # Headers already on the wire → must re-raise
                    raise exc_info[1].with_traceback(exc_info[2])
            finally:
                exc_info = None                      # avoid circular ref
        elif state["status"] is not None:
            raise RuntimeError("start_response already called without exc_info")

        state["status"] = status                     # e.g. "200 OK"
        state["headers"] = list(headers)             # list of (name, value)

        # The write() callable (PEP 3333 legacy, avoid in new code) probably not used now
        def write(data: bytes):
            raise NotImplementedError(
                "The legacy write() callable is not supported by this server. "
                "Return an iterable from the WSGI app instead."
            )
        return write

    return start_response, state


# Keep-alive decision helper
def _wants_keep_alive(request: dict) -> bool:
    """Return True if the client wants (and is allowed) to keep-alive."""
    conn = request["headers"].get("connection", "").lower()
    version = request["version"]
    # HTTP/1.1 defaults to keep-alive unless "close" is sent
    if version == "HTTP/1.1":
        return "close" not in conn
    # HTTP/1.0 defaults to close unless "keep-alive" is sent
    return "keep-alive" in conn


# Main accept-loop
def serve_forever():
    """Create, bind, listen, and accept connections in a blocking loop."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(BACKLOG)
        
        # On Windows, blocking accept() can ignore Ctrl+C.
        # Setting a timeout allows Python to check for signals periodically.
        server_socket.settimeout(1.0) 

        import os as _os
        log.info("Listening on http://%s:%s  (PID %d)", HOST, PORT, _os.getpid())

        while True:
            try:
                # ── Accept a new TCP connection ──
                client_socket, client_addr = server_socket.accept()
            except socket.timeout:
                # Just a heartbeat to allow KeyboardInterrupt to be processed
                continue
            except OSError:
                log.error("accept() failed", exc_info=True)
                continue
            
            log.info("New connection from %s:%s", client_addr[0], client_addr[1])
            _handle_connection(client_socket, client_addr)


def _handle_connection(client_socket: socket.socket, client_addr: tuple):
    """Handle one TCP connection (potentially many keep-alive requests)."""
    requests_served = 0

    try:
        for request_num in range(1, MAX_KEEP_ALIVE_REQUESTS + 1):
            # ── Set recv timeout ──
            # For the FIRST request we use RECV_TIMEOUT;
            # for subsequent keep-alive requests we use the idle timeout.
            timeout = RECV_TIMEOUT if request_num == 1 else KEEP_ALIVE_TIMEOUT
            client_socket.settimeout(timeout)

            # ── Read & parse one request ──
            try:
                request = read_full_request(client_socket)
            except _RequestError as exc:
                log.warning(
                    "%s:%s  → %d %s",
                    client_addr[0], client_addr[1],
                    exc.status_code, exc.detail,
                )
                _safe_send(client_socket, _build_error_response(exc.status_code, exc.detail))
                return                               # close connection
            except Exception:
                log.error("Unexpected error reading request", exc_info=True)
                _safe_send(client_socket, _build_error_response(400))
                return

            if request is None:
                # Clean EOF — client closed their side
                log.debug(
                    "%s:%s closed connection after %d request(s)",
                    client_addr[0], client_addr[1], requests_served,
                )
                return

            # ── Decide keep-alive BEFORE calling app (app may override) ──
            keep_alive = _wants_keep_alive(request)
            # Close after last allowed request regardless
            if request_num >= MAX_KEEP_ALIVE_REQUESTS:
                keep_alive = False

            log.info(
                '%s:%s  "%s %s %s"',
                client_addr[0], client_addr[1],
                request["method"], request["raw_path"], request["version"],
            )

            # ── Build WSGI environ ──
            environ = build_environ(request, client_addr)

            # ── Prepare start_response ──
            start_response,sr_state = make_start_response()

            # ── Call WSGI application ──
            try:
                body_iterable = WSGI_APP(environ,start_response)
            except Exception:
                log.error("WSGI app raised an exception", exc_info=True)
                _safe_send(
                    client_socket,
                    _build_error_response(500, "Internal Server Error"),
                )
                return

            # ── Validate that start_response was called ──
            status = sr_state["status"]
            resp_headers = sr_state["headers"]

            if status is None:
                log.error("WSGI app returned without calling start_response")
                _safe_send(client_socket, _build_error_response(500))
                if hasattr(body_iterable,"close"):
                    body_iterable.close()
                return

            # ── Send the response (streaming-capable) ──
            ok = send_response(
                client_socket,
                status,
                resp_headers,
                body_iterable,
                keep_alive,
            )

            status_code = status.split(" ", 1)[0]
            log.info(
                '%s:%s  → %s  (keep_alive=%s, req#%d)',
                client_addr[0], client_addr[1],
                status_code, keep_alive, request_num,
            )
            # increase the counter
            requests_served += 1

            if not ok:
                log.warning(
                    "%s:%s  client disconnected during response",
                    client_addr[0], client_addr[1],
                )
                return

            if not keep_alive:
                return

    except Exception:
        log.error("Fatal error in connection handler",exc_info=True)
    finally:
        try:
            client_socket.close()
        except OSError:
            pass
        log.debug(
            "%s:%s  connection closed (%d request(s) served)",
            client_addr[0], client_addr[1], requests_served,
        )


# Entry point
if __name__ == "__main__":
    try:
        serve_forever()
    except KeyboardInterrupt:
        log.info("Server stopped by user (Ctrl+C)")
        sys.exit(0)

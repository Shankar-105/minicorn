import socket

HOST = '127.0.0.1'      # localhost only (safer for learning)
PORT = 8000             # common dev port (above 1024 so no admin needed)

# Create the listening socket (OS level)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allows quick restart
server_socket.bind((HOST, PORT))
server_socket.listen(5)   # backlog = how many waiting connections allowed

print(f"Server listening on http://{HOST}:{PORT}")

def read_full_request(c_socket : socket):
    # Buffer to accumulate all bytes
    request_bytes = b''

    # Step 1: Read until we have full headers (look for \r\n\r\n)
    while b'\r\n\r\n' not in request_bytes:
        chunk = c_socket.recv(4096)  # bigger chunk = faster, still safe
        if not chunk:  # Connection closed early
            return None
        request_bytes += chunk

    # Now split at first \r\n\r\n
    header_end = request_bytes.find(b'\r\n\r\n')
    if header_end == -1:
        return None  # malformed

    headers_part = request_bytes[:header_end + 4]  # include the \r\n\r\n
    body_so_far = request_bytes[header_end + 4:]

    # Parse headers to get Content-Length (we reuse your previous parsing logic)
    headers_text = headers_part.decode('utf-8', errors='ignore')
    lines = headers_text.split('\r\n')
    request_line = lines[0]
    method, path, version = request_line.split()

    headers = {}
    for line in lines[1:]:
        if not line:
            break
        key, value = line.split(':', 1)
        headers[key.strip().lower()] = value.strip()

    # Step 2: Read the rest of the body if Content-Length exists
    content_length = int(headers.get('content-length', 0))

    # Security: limit max size (very important!)
    MAX_BODY_SIZE = 1024 * 1024  # 1 MB — change as you wish
    if content_length > MAX_BODY_SIZE:
        # In real server → send 413 Payload Too Large
        return {
            'method': method,
            'path': path,
            'headers': headers,
            'body': b'Too big!',
            'error': '413'
        }
 
    remaining = content_length - len(body_so_far)
    while remaining > 0:
        chunk = c_socket.recv(min(4096, remaining))
        if not chunk:
            break  # closed early — incomplete body
        body_so_far += chunk
        remaining -= len(chunk)
    parsed_body = parse_body(method=method,headers=headers,body_bytes=body_so_far)
    return {
        'method': method.upper(),
        'path': path,
        'version' : version,
        'headers': headers,
        'body': body_so_far,          # bytes — keep as bytes for now
        'body_text': parsed_body  # for printing
    }

def parse_body(method,headers,body_bytes):
    content_type = headers.get('content-type', '').lower().split(';')[0].strip()
    parsed_body = None

    if method in ('POST', 'PUT', 'PATCH'):
        if 'application/json' in content_type:
            try:
                import json
                parsed_body = json.loads(body_bytes.decode('utf-8'))
            except json.JSONDecodeError:
                parsed_body = {"error": "Invalid JSON"}

        elif 'application/x-www-form-urlencoded' in content_type:
            from urllib.parse import parse_qs
            body_str = body_bytes.decode('utf-8', errors='ignore')
            parsed_body = parse_qs(body_str)  # returns dict like {'name': ['M'], 'age': ['20']}

        elif 'multipart/form-data' in content_type:
            # For now: just say "multipart detected – too complex for simple parse"
            parsed_body = {"multipart_detected": True, "raw_length": len(body_bytes)}
            # (We'll touch real multipart parsing later – it's boundary hunting)

        else:
            # Unknown or binary – keep as bytes or text attempt
            parsed_body = body_bytes.decode('utf-8', errors='replace')
        return parsed_body
    
import datetime

def build_response(
    status_code: int,
    status_phrase: str,
    headers: dict = None,
    body: str | bytes = "",
    content_type: str = "application/json"
) -> bytes:
    if headers is None:
        headers = {}

    # Body handling
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body

    # Mandatory / useful headers (add if not set by app)
    final_headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body_bytes)),
        "Date": datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "Connection": "close",  # for now – later keep-alive
    }
    final_headers.update(headers)  # app headers override defaults

    # Status line
    status_line = f"HTTP/1.1 {status_code} {status_phrase}\r\n"

    # Headers block
    headers_block = ""
    for key, value in final_headers.items():
        headers_block += f"{key}: {value}\r\n"

    # Full response
    response = (
        status_line +
        headers_block +
        "\r\n"                    # empty line after headers
    ).encode("utf-8") + body_bytes

    return response

while True:
    # Wait for someone to connect (this blocks until browser connects)
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    keep_alive=True
    while True :
        request = read_full_request(c_socket=client_socket)
        if not request or 'error' in request:
        # handle error, send 400 or 413
            status = '400'
            body=b'Error from the Server'
            response = (
                f"HTTP/1.1 {status}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n"                          # end of headers
            ).encode('utf-8') + body
            client_socket.sendall(response)
            client_socket.close()
            break

        from io import BytesIO
        import sys

        environ = {
            'REQUEST_METHOD': request['method'],  # e.g., 'GET'
            'SCRIPT_NAME': '',  # Simple: root-mounted
            'PATH_INFO': request['path'].split('?')[0] if '?' in request['path'] else request['path'],  # e.g., '/hello'
            'QUERY_STRING': request['path'].split('?')[1] if '?' in request['path'] else '',  # e.g., 'name=M'
            'CONTENT_TYPE': request['headers'].get('content-type', ''),  # Lowercase ok, spec allows
            'CONTENT_LENGTH': str(len(request['body'])),  # Even if 0
            'SERVER_NAME': HOST,  # '127.0.0.1'
            'SERVER_PORT': str(PORT),  # '8000'
            'SERVER_PROTOCOL': request.get('version', 'HTTP/1.1'),
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'http',  # Add 'https' logic later
            'wsgi.input': BytesIO(request['body']),  # Readable stream—app calls .read()
            'wsgi.errors': sys.stderr,  # For app logging
            'wsgi.multithread': False,  # Update to True when threaded
            'wsgi.multiprocess': False,
            'wsgi.run_once': False,
        }

        # Add all headers as HTTP_UPPER_KEY (normalize)
        for key, value in request['headers'].items():
            upper_key = key.upper().replace('-', '_')  # e.g., 'User-Agent' → 'USER_AGENT'
            if key.lower() not in ('content-type', 'content-length'):  # Skip duplicates
                environ[f'HTTP_{upper_key}'] = value

        # Optional: Client info
        environ['REMOTE_ADDR'] = client_address[0]  # e.g., '127.0.0.1'
        environ['REMOTE_PORT'] = client_address[1]  # ephemeral port from client
        print("ENVIRON :")
        print(environ)
        response_status = None
        response_headers = []

        def start_response(status,headers,exc_info=None):
            global response_status, response_headers  # Or use class/nonlocal
            if exc_info:  # Error handling (advanced)
                raise exc_info[1].with_traceback(exc_info[2])
            response_status = status  # e.g., '200 OK'
            response_headers = headers  # e.g., [('Content-Type', 'text/plain')]
            return lambda *args: None  # Optional write func (ignore for now)
     
        print(f"Parsed: Method={request.get('method')}, Path={request.get('path')}, Version={request.get('version')}")
        print(f"Headers: {request.get('headers')}")
        print(f"Body: {request.get('body_text')}")

        connection = request.get('headers').get('connection','').lower()

        if 'close' in connection:
            keep_alive=False
            response_headers = {'Connection':'close'}
        else:
            response_headers = {'Connection':'keep-alive'}
        try:
            from main import app
            body_iterable = app.wsgi_app(environ,start_response)  # Call—app must be callable!
            # Collect chunks (simple; real servers stream send)
            body_chunks = []
            for chunk in body_iterable:  # Iterable yields bytes
                body_chunks.append(chunk)
            full_body = b''.join(body_chunks)
        except Exception as e:
            # App crash? Set 500
            response_status = '500 Internal Server Error'
            response_headers = [('Content-Type', 'text/plain')]
            full_body = b'Error!'

        # Format using your build_response
        status_code = int(response_status.split(' ')[0])  # 200
        phrase = ' '.join(response_status.split(' ')[1:])  # OK
        headers_dict = {k: v for k, v in response_headers}  # For build_response
        response_bytes = build_response(status_code, phrase, headers_dict,full_body)
        # Send it back
        client_socket.sendall(response_bytes)
        if not keep_alive:
            break
    # Close this connection (we'll improve later)
    client_socket.close()
    print("Response sent, connection closed\n")
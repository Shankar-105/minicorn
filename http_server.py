import socket

HOST = '127.0.0.1'      # localhost only (safer for learning)
PORT = 8000             # common dev port (above 1024 so no admin needed)

# Create the listening socket (OS level)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allows quick restart
server_socket.bind((HOST, PORT))
server_socket.listen(5)   # backlog = how many waiting connections allowed

print(f"Server listening on http://{HOST}:{PORT}")

def read_full_request(client_socket):
    # Buffer to accumulate all bytes
    request_bytes = b''

    # Step 1: Read until we have full headers (look for \r\n\r\n)
    while b'\r\n\r\n' not in request_bytes:
        chunk = client_socket.recv(4096)  # bigger chunk = faster, still safe
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
        chunk = client_socket.recv(min(4096, remaining))
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
    
while True:
    # Wait for someone to connect (this blocks until browser connects)
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    request = read_full_request(client_socket=client_socket)
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
        continue

    print(f"Parsed: Method={request.get('method')}, Path={request.get('path')}, Version={request.get('version')}")
    print(f"Headers: {request.get('headers')}")
    print(f"Body: {request.get('body_text')}")
    # Build response (as bytes — very important!)
    if request['method'] == 'POST' and request['path'] == '/echo':
        status = '200 OK'
        body = f"{request['body_text']}"
    else:
        status = '405 Method Not Allowed' if request['method'] != 'GET' else '200 OK'
        body = "Use POST /echo to see your data"
    body_bytes = body.encode("utf-8")

    response = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {request['headers'].get('content-type')}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"                          # end of headers
    ).encode('utf-8') + body_bytes      # headers as bytes + body as bytes

    # Send it back
    client_socket.sendall(response)

    # Close this connection (we'll improve later)
    client_socket.close()
    print("Response sent, connection closed\n")
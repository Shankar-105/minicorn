# minicorn 🐣🦄🔥

A lightweight, production-grade Python server that speaks both **WSGI** and **ASGI** — with full **WebSocket** support baked in.

minicorn gives you a Uvicorn/Gunicorn-like CLI experience with zero heavyweight dependencies, serving everything from classic Flask apps to modern async FastAPI services over the same port.

## Features

| | |
|---|---|
| 🐍 **WSGI** | Full PEP 3333 compliance — Flask, Django, and any WSGI app |
| ⚡ **ASGI** | Async support for FastAPI, Starlette, and ASGI 3.0 apps |
| 🔌 **WebSockets** | RFC 6455 compliant WebSocket handling in ASGI mode |
| 🔄 **Auto-reload** | File-watching hot reload for development |
| 🛠️ **Simple CLI** | One command to run any app, WSGI or ASGI |
| 📦 **Zero Core Deps** | Stdlib only — `watchdog` needed only for `--reload` |
| 📋 **Structured Logging** | Colored, leveled log output |

## Installation

```bash
pip install minicorn

# With dev/reload support
pip install "minicorn[dev]"
```

## Quick Start

### WSGI — Flask / Django

```bash
# Run a Flask or Django app
minicorn main:app

# Custom host and port
minicorn main:app --host 0.0.0.0 --port 8080

# Hot reload during development
minicorn main:app --reload
```

### ASGI — FastAPI / Starlette

Add `--asgi` to switch to async mode:

```bash
# Run a FastAPI app
minicorn main:app --asgi

# With hot reload
minicorn main:app --asgi --reload

# Custom port
minicorn main:app --asgi --port 8080
```

### WebSockets

WebSocket support is built into ASGI mode — no extra flags needed.  
Any endpoint that upgrades to WebSocket (HTTP 101) is handled automatically.

```bash
minicorn main:app --asgi
# ws://127.0.0.1:8000/ws is ready to accept connections
```

Enable keepalive pings to detect dead connections:

```bash
minicorn main:app --asgi --ws-ping-interval 20 --ws-ping-timeout 10
```

### Using with Python -m

```bash
python -m minicorn main:app --reload
python -m minicorn main:app --asgi --reload
```

## Example Apps

### Flask (WSGI)

```python
# main.py
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello from minicorn! 🔥"
```

```bash
minicorn main:app --reload
```

### FastAPI (ASGI)

```python
# main.py
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello from FastAPI!", "server": "minicorn-asgi"}
```

```bash
minicorn main:app --asgi --reload
```

### WebSocket with FastAPI

```python
# main.py
from fastapi import FastAPI, WebSocket

app = FastAPI()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Echo: {data}")
```

```bash
minicorn main:app --asgi
# Connect to ws://127.0.0.1:8000/ws
```

## Programmatic Usage

```python
# WSGI
from minicorn import serve, run

serve("main:app", host="0.0.0.0", port=8080)

# or pass the app object directly
from myapp import app
run(app, host="127.0.0.1", port=8000)
```

```python
# ASGI
from minicorn import serve_asgi, run_asgi

serve_asgi("main:app", host="0.0.0.0", port=8080)

from myapp import app
run_asgi(app, host="127.0.0.1", port=8000)
```

## CLI Reference

```
minicorn --help 
```

## Auto-Reload

`--reload` works for both WSGI and ASGI. minicorn watches `.py` files in your project and restarts the server on changes.

```bash
minicorn main:app --reload          # WSGI
minicorn main:app --asgi --reload   # ASGI
```

Automatically ignored: `__pycache__`, `.git`, `venv`, `.venv`, `node_modules`, `dist`, `build`, `.mypy_cache`, `.pytest_cache`

## Server Capabilities

| Capability | WSGI | ASGI |
|---|:---:|:---:|
| HTTP/1.0 & HTTP/1.1 | ✅ | ✅ |
| Keep-Alive connections | ✅ | ✅ |
| Chunked transfer encoding | ✅ | ✅ |
| Streaming responses | ✅ | ✅ |
| WebSocket (RFC 6455) | — | ✅ |
| WebSocket ping/pong | — | ✅ |
| asyncio-based concurrency | — | ✅ |
| Auto-reload | ✅ | ✅ |

## Configuration Defaults

| Setting | Default | Description |
|---|---|---|
| Host | `127.0.0.1` | Bind address |
| Port | `8000` | Bind port |
| Max Header Size | 64 KB | Reject oversized headers |
| Max Body Size | 1 MB | Reject oversized bodies |
| Recv Timeout | 10s | Timeout waiting for request data |
| Keep-Alive Timeout | 15s | Idle timeout between requests |
| Max Keep-Alive Requests | 100 | Max requests per connection |
| WS Max Message Size | 16 MB | Maximum WebSocket message size |
| WS Ping Interval | disabled | Ping clients every N seconds |
| WS Ping Timeout | disabled | Close if pong not received in N seconds |

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

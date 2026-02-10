# iotaX 🔥

A lightweight, production-grade synchronous WSGI server with auto-reload support.

iotaX provides a simple CLI experience similar to Uvicorn and Gunicorn, designed to serve any PEP 3333 compliant WSGI application (Flask, Django, etc.) with robust features for both development and production use.

## Features

- **Full PEP 3333 Compliance** - Works with any WSGI application
- **Production-grade Robustness** - Timeouts, keep-alive, streaming, chunked transfer encoding
- **Auto-reload** - Watch for file changes and automatically restart (development mode)
- **Simple CLI** - Uvicorn-like command interface
- **Zero Dependencies** - Core server requires only Python stdlib (watchdog optional for reload)
- **Structured Logging** - Clear, colored log output

## Installation

```bash
pip install iotaX

# Install with auto-reload support
pip install "iotaX[reload]"

# Or install all dev dependencies
pip install "iotaX[dev]"
```

## Quick Start

### Basic Usage

```bash
# Run a Flask app
iotaX main:app

# Run with custom host/port
iotaX main:app --host 0.0.0.0 --port 8080

# Run with auto-reload (development)
iotaX main:app --reload
```

### Using with Python -m

```bash
python -m iotaX main:app --reload
```

### Application Path Format

The application path follows the format `module:attribute`:

```bash
# Simple module
iotaX main:app              # from main import app

# Nested module
iotaX myproject.api:app     # from myproject.api import app

# Package
iotaX myapp.wsgi:application  # from myapp.wsgi import application
```

## CLI Reference

```
usage: iotaX [-h] [--host HOST] [--port PORT] [--reload] [--version] APP

iotaX - A lightweight, production-grade WSGI server

positional arguments:
  APP          WSGI application in format 'module:attribute' (e.g., 'main:app')

options:
  -h, --help   show this help message and exit
  --host HOST  Bind socket to this host (default: 127.0.0.1)
  --port PORT  Bind socket to this port (default: 8000)
  --reload     Enable auto-reload on code changes (development mode)
  --version    show program's version number and exit

Examples:
  iotaX main:app                         Run app from main.py
  iotaX myproject.api:app --port 8080    Run on custom port
  iotaX main:app --reload                Run with auto-reload
  iotaX app:create_app() --host 0.0.0.0  Bind to all interfaces
```

## Programmatic Usage

You can also use iotaX directly in Python code:

```python
from iotaX import serve, run

# Using module path
serve("main:app", host="0.0.0.0", port=8080)

# Using app directly
from myapp import app
run(app, host="127.0.0.1", port=8000)
```

Or use the Server class for more control:

```python
from iotaX.server import Server, load_app

app = load_app("main:app")
server = Server(app, host="127.0.0.1", port=8000)

# In a signal handler or elsewhere:
# server.signal_exit()  # Gracefully stop

server.serve()
```

## Auto-Reload Mode

When using `--reload`, iotaX watches for changes to `.py` files in your project directory:

```bash
iotaX main:app --reload
```

Output:
```
iotaX v0.1.0
Running main:app
Address: http://127.0.0.1:8000
Auto-reload enabled (development mode)

INFO:     Watching for file changes in: /path/to/project
INFO:     Starting server subprocess...
INFO:     Started server process [12345]
INFO:     Listening on http://127.0.0.1:8000

# When you edit a file:
INFO:     Detected modified: /path/to/project/main.py
INFO:     Restarting server...
```

### Excluded Directories

The reload watcher automatically excludes:
- `__pycache__`
- `.git`, `.svn`, `.hg`
- `venv`, `.venv`, `env`, `.env`
- `node_modules`
- `.tox`, `.eggs`, `*.egg-info`
- `dist`, `build`
- `.mypy_cache`, `.pytest_cache`

## Technical Details

### Architecture

iotaX is a **synchronous, single-threaded** WSGI server. Each connection is handled sequentially, making it simple and predictable. For high-concurrency production workloads, consider using it behind a reverse proxy or switching to an async server.

### Key Concepts

1. **Module Reloading** (`importlib.reload`)  
   When `--reload` is enabled, iotaX uses `importlib.reload()` to re-import the application module after detecting file changes, allowing code updates without a full process restart.

2. **Watchdog File Monitoring**  
   The [watchdog](https://pythonhosted.org/watchdog/) library provides cross-platform file system event monitoring. It watches for file creation, modification, and deletion events, triggering a reload when `.py` files change.

3. **Subprocess Management**  
   In reload mode, the actual server runs in a subprocess. The main process monitors for file changes and restarts the subprocess when needed, ensuring clean resource cleanup.

### Server Capabilities

- **HTTP/1.0 and HTTP/1.1** support
- **Keep-Alive** connections with configurable limits
- **Chunked Transfer-Encoding** for streaming responses
- **Timeouts** for request headers and body reads
- **Size limits** for headers (64KB) and body (1MB)
- **Graceful shutdown** on SIGINT/SIGTERM

## Configuration Defaults

| Setting | Default | Description |
|---------|---------|-------------|
| Host | 127.0.0.1 | Bind address |
| Port | 8000 | Bind port |
| Max Header Size | 64 KB | Maximum request header size |
| Max Body Size | 1 MB | Maximum request body size |
| Recv Timeout | 10s | Timeout waiting for request data |
| Keep-Alive Timeout | 15s | Idle timeout between requests |
| Max Keep-Alive Requests | 100 | Max requests per connection |

## Example Flask App

```python
# main.py
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello from iotaX! 🔥"

@app.route("/api/data")
def data():
    return {"message": "Hello", "server": "iotaX"}

if __name__ == "__main__":
    # For development without iotaX CLI:
    app.run()
```

Run with:
```bash
iotaX main:app --reload
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

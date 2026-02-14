# minicorn 🔥

A lightweight, production-grade synchronous WSGI server with auto-reload support.

minicorn provides a simple CLI experience similar to Uvicorn and Gunicorn, designed to serve any PEP 3333 compliant WSGI application (Flask, Django, etc.) with robust features for both development and production use.

## Features

- **Full PEP 3333 Compliance** - Works with any WSGI application
- **Production-grade Robustness** - Timeouts, keep-alive, streaming, chunked transfer encoding
- **Auto-reload** - Watch for file changes and automatically restart (development mode)
- **Simple CLI** - Uvicorn-like command interface
- **Zero Dependencies** - Core server requires only Python stdlib (watchdog optional for reload)
- **Structured Logging** - Clear, colored log output
- **ASGI Support** - (**BETA** feature)
## Installation

```bash
pip install minicorn

# Or install all dev dependencies
pip install "minicorn[dev]"
```

## Quick Start

### Basic Usage

```bash
# Run a WSGI app
minicorn main:app

# Run with custom host/port
minicorn main:app --host 0.0.0.0 --port 8080

# Run with auto-reload (development hot reload)
minicorn main:app --reload
```

### Using with Python -m

```bash
python -m minicorn main:app --reload
```

### Application Path Format

The application path follows the format `module:attribute`:

```bash
# Simple module
minicorn main:app              # from main import app

# Nested module
minicorn myproject.app:app     # from myproject.app import app

```

## CLI Reference

```
usage: minicorn [-h] [--host HOST] [--port PORT] [--reload] [--version] APP

minicorn - A lightweight, production-grade WSGI server

positional arguments:
  APP          WSGI application in format 'module:attribute' (e.g., 'main:app')

options:
  -h, --help   show this help message and exit
  --host HOST  Bind socket to this host (default: 127.0.0.1)
  --port PORT  Bind socket to this port (default: 8000)
  --reload     Enable auto-reload on code changes (development mode)
  --version    show program's version number and exit

Examples:
  minicorn main:app                         Run app from main.py
  minicorn myproject.api:app --port 8080    Run on custom port
  minicorn main:app --reload                Run with auto-reload
  minicorn app:create_app() --host 0.0.0.0  Bind to all interfaces
```

## Programmatic Usage

You can also use minicorn directly in Python code:

```python
from minicorn import serve, run

# Using module path
serve("main:app", host="0.0.0.0", port=8080)

# Using app directly
from myapp import app
run(app, host="127.0.0.1", port=8000)
```

## Auto-Reload Mode

When using `--reload`, minicorn watches for changes to `.py` files in your project directory:

```bash
minicorn main:app --reload
```

Output:
```
minicorn v0.1.0
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

minicorn is a **synchronous, single-threaded** WSGI server. Each connection is handled sequentially.

### Key Concepts

1. **Module Reloading** (`importlib.reload`)  
   When `--reload` is enabled, minicorn uses `importlib.reload()` to re-import the application module after detecting file changes, allowing code updates without a full process restart.

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
    return "Hello from minicorn! 🔥"

@app.route("/api/data")
def data():
    return {"message": "Hello", "server": "minicorn"}

if __name__ == "__main__":
    # For development without minicorn CLI:
    app.run()
```

Run with:
```bash
minicorn main:app --reload
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

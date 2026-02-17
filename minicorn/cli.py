"""
minicorn/cli.py — Command-line interface for the minicorn WSGI server.
Provides Uvicorn/Gunicorn-like CLI experience with auto-reload support.
"""
import argparse
import sys
import os
import signal
import time
import logging
import subprocess
from pathlib import Path
from typing import Optional

from minicorn import __version__
from minicorn.wsgi_server import Server, load_app, DEFAULT_HOST, DEFAULT_PORT

# Valid log level names (for CLI validation)
LOG_LEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}

# Configure logging with nice formatting
def setup_logging(level: int = logging.INFO):
    """Configure structured logging for the CLI."""
    logging.basicConfig(
        level=level,
        format="\033[32m%(levelname)s\033[0m:     %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Also configure the minicorn logger
    logger = logging.getLogger("minicorn")
    logger.setLevel(level)
    return logger


log = setup_logging()


# Reload Watcher using watchdog

class ReloadManager:
    """
    Manages the server process and restarts it when Python files change.
    
    Uses watchdog to monitor .py files in the current working directory.
    Excludes common directories like __pycache__, .git, venv, etc.
    """
    
    EXCLUDE_PATTERNS = {
        "__pycache__",
        ".git",
        ".svn",
        ".hg",
        "venv",
        ".venv",
        "env",
        ".env",
        "node_modules",
        ".tox",
        ".eggs",
        "*.egg-info",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
    }
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.process: Optional[subprocess.Popen] = None
        self.should_exit = False
        self.observer = None
    
    def _should_watch_path(self, path: str) -> bool:
        """Check if a path should be watched (not in excluded directories)."""
        path_obj = Path(path)
        parts = path_obj.parts
        
        for part in parts:
            if part in self.EXCLUDE_PATTERNS:
                return False
            for pattern in self.EXCLUDE_PATTERNS:
                if "*" in pattern and part.endswith(pattern.replace("*", "")):
                    return False
        return True
    
    def _build_subprocess_args(self) -> list[str]:
        """Build the command line args to run the server subprocess."""
        if getattr(self.args, 'asgi', False):
            # ASGI mode
            log_level = getattr(self.args, 'log_level', 'info')
            log_level_int = LOG_LEVELS.get(log_level,logging.INFO)
            return [
                sys.executable,
                "-c",
                f"""
import sys
import logging
logging.basicConfig(
    level={log_level_int},
    format="\\033[32m%(levelname)s\\033[0m:     %(message)s",
)
from minicorn.asgi_server import serve_asgi
try:
    serve_asgi({self.args.app!r}, {self.args.host!r}, {self.args.port}, ws_ping_interval={getattr(self.args, 'ws_ping_interval', None)!r}, ws_ping_timeout={getattr(self.args, 'ws_ping_timeout', None)!r})
except KeyboardInterrupt:
    pass
""",
            ]
        else:
            # WSGI mode (default)
            log_level = getattr(self.args, 'log_level', 'info')
            log_level_int = LOG_LEVELS.get(log_level, logging.INFO)
            return [
                sys.executable,
                "-c",
                f"""
import sys
import logging
logging.basicConfig(
    level={log_level_int},
    format="\\033[32m%(levelname)s\\033[0m:     %(message)s",
)
from minicorn.wsgi_server import serve
try:
    serve({self.args.app!r}, {self.args.host!r}, {self.args.port})
except KeyboardInterrupt:
    pass
""",
            ]
    
    def start_server(self):
        """Start the server as a subprocess."""
        log.info("Starting server subprocess...")
        self.process = subprocess.Popen(
            self._build_subprocess_args(),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    
    def stop_server(self):
        """Stop the running server subprocess."""
        if self.process and self.process.poll() is None:
            log.info("Stopping server subprocess...")
            # On Windows, use terminate; on Unix, could use SIGTERM
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log.warning("Server did not stop gracefully, killing...")
                self.process.kill()
                self.process.wait()
            self.process = None
    
    def restart_server(self):
        """Restart the server subprocess."""
        log.info("Restarting server...")
        self.stop_server()
        # Small delay to ensure port is released
        time.sleep(0.5)
        self.start_server()
    
    def run_with_reload(self):
        """Run the server with auto-reload enabled."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            log.error(
                "watchdog package is required for --reload. "
                "Install it with: pip install watchdog"
            )
            sys.exit(1)
        
        class PythonFileHandler(FileSystemEventHandler):
            """Handler that triggers reload on .py file changes."""
            
            def __init__(handler_self, manager: "ReloadManager"):
                handler_self.manager = manager
                handler_self.last_reload = 0
                handler_self.debounce_seconds = 0.5
            
            def on_any_event(handler_self, event):
                # Only care about .py files
                if event.is_directory:
                    return
                
                src_path = getattr(event, "src_path", "")
                if not src_path.endswith(".py"):
                    return
                
                # Check if path should be watched
                if not handler_self.manager._should_watch_path(src_path):
                    return
                
                # Debounce rapid events
                now = time.time()
                if now - handler_self.last_reload < handler_self.debounce_seconds:
                    return
                handler_self.last_reload = now
                
                event_type = type(event).__name__.replace("Event", "").lower()
                log.info("Detected %s: %s", event_type, src_path)
                handler_self.manager.restart_server()
        
        # Setup signal handler for graceful shutdown
        def signal_handler(signum, frame):
            log.info("Received shutdown signal")
            self.should_exit = True
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start the file watcher
        watch_path = os.getcwd()
        event_handler = PythonFileHandler(self)
        
        self.observer = Observer()
        self.observer.schedule(event_handler, watch_path, recursive=True)
        self.observer.start()
        
        log.info("Watching for file changes in: %s", watch_path)
        
        # Start the initial server
        self.start_server()
        
        try:
            while not self.should_exit:
                # Check if subprocess died unexpectedly
                if self.process and self.process.poll() is not None:
                    exit_code = self.process.returncode
                    if exit_code != 0:
                        log.warning("Server exited with code %d", exit_code)
                    # Don't auto-restart on crash, wait for file change
                    self.process = None
                
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_server()
            if self.observer:
                self.observer.stop()
                self.observer.join()
            log.info("Shutdown complete")


# Direct server runner (no reload)

def run_server_direct(args:argparse.Namespace):
    """Run the server directly in the current process (no reload)."""
    if getattr(args, 'asgi', False):
        # ASGI mode
        from minicorn.asgi_server import ASGIServer, load_app as load_asgi_app
        try:
            app = load_asgi_app(args.app)
        except (ValueError, ImportError, AttributeError, TypeError) as e:
            log.error("Failed to load ASGI application: %s", e)
            sys.exit(1)
        
        server = ASGIServer(
            app, args.host, args.port,
            ws_ping_interval=getattr(args, 'ws_ping_interval', None),
            ws_ping_timeout=getattr(args, 'ws_ping_timeout', None),
        )
        
        def signal_handler(signum, frame):
            log.info("Received shutdown signal")
            server.signal_exit()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            server.serve()
        except OSError as e:
            log.error("Server error: %s", e)
            sys.exit(1)
        except KeyboardInterrupt:
            log.info("Interrupted")
        finally:
            server.shutdown()
    else:
        # WSGI mode (default)
        try:
            app = load_app(args.app)
        except (ValueError, ImportError, AttributeError, TypeError) as e:
            log.error("Failed to load application: %s", e)
            sys.exit(1)
            
        server = Server(app,args.host,args.port)
        
        def signal_handler(signum, frame):
            log.info("Received shutdown signal")
            server.signal_exit()
        
        signal.signal(signal.SIGINT,signal_handler)
        signal.signal(signal.SIGTERM,signal_handler)
        
        try:
            server.serve()
        except OSError as e:
            log.error("Server error: %s", e)
            sys.exit(1)
        except KeyboardInterrupt:
            log.info("Interrupted")
        finally:
            server.shutdown()


# CLI Entry Point

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="minicorn",
        description="minicorn - A lightweight, production-grade WSGI server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  minicorn main:app                         Run app from main.py
  minicorn myproject.api:app --port 8080    Run on custom port
  minicorn main:app --reload                Run with auto-reload
  minicorn app:create_app() --host 0.0.0.0  Bind to all interfaces
        """,
    )
    
    parser.add_argument(
        "app",
        metavar="APP",
        help="WSGI application in format 'module:attribute' (e.g., 'main:app')",
    )
    
    parser.add_argument(
        "--host",
        type=str,
        default=DEFAULT_HOST,
        help=f"Bind socket to this host (default: {DEFAULT_HOST})",
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Bind socket to this port (default: {DEFAULT_PORT})",
    )
    
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload on code changes (development mode)",
    )
    
    parser.add_argument(
        "--asgi",
        action="store_true",
        default=False,
        help="Run as ASGI server (for FastAPI, Starlette, etc.)",
    )
    
    parser.add_argument(
        "--ws-ping-interval",
        type=float,
        default=None,
        help="WebSocket ping interval in seconds. The server sends a ping "
             "frame to each connected client every N seconds to detect "
             "dead connections. Only active in ASGI mode. Disabled by default.",
    )
    
    parser.add_argument(
        "--ws-ping-timeout",
        type=float,
        default=None,
        help="WebSocket ping timeout in seconds. Close the connection if no "
             "pong is received within N seconds after a ping was sent. "
             "Requires --ws-ping-interval. Disabled by default.",
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=LOG_LEVELS.keys(),
        help="Set the log level (default: info). Use 'debug' to see "
             "WebSocket ping/pong frames and other verbose output.",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    return parser

def main(args: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    # Apply log level from CLI
    level = LOG_LEVELS[parsed_args.log_level]
    setup_logging(level)
    
    # Print startup banner
    print(f"\033[1m\033[34mminicorn\033[0m v{__version__}")
    print(f"Running \033[1m{parsed_args.app}\033[0m")
    print(f"Address: http://{parsed_args.host}:{parsed_args.port}")
    if parsed_args.asgi:
        print("\033[36mASGI mode\033[0m")
        if parsed_args.ws_ping_interval is not None:
            timeout_str = (
                f"{parsed_args.ws_ping_timeout}s"
                if parsed_args.ws_ping_timeout is not None
                else "disabled"
            )
            print(
                f"\033[36mWebSocket ping: interval={parsed_args.ws_ping_interval}s, "
                f"timeout={timeout_str}\033[0m"
            )
    else:
        print("\033[35mWSGI mode\033[0m")
    if parsed_args.reload:
        print("\033[33mAuto-reload enabled (development mode)\033[0m")
    print()
    
    if parsed_args.reload:
        manager = ReloadManager(parsed_args)
        manager.run_with_reload()
    else:
        run_server_direct(parsed_args)
    return 0

if __name__ == "__main__":
    sys.exit(main())

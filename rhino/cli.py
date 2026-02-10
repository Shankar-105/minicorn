"""
rhino/cli.py — Command-line interface for the Rhino WSGI server.

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

from rhino import __version__
from rhino.server import Server, load_app, DEFAULT_HOST, DEFAULT_PORT

# Configure logging with nice formatting
def setup_logging(level: int = logging.INFO):
    """Configure structured logging for the CLI."""
    logging.basicConfig(
        level=level,
        format="\033[32m%(levelname)s\033[0m:     %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Also configure the rhino logger
    logger = logging.getLogger("rhino")
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
        return [
            sys.executable,
            "-c",
            f"""
import sys
import logging
logging.basicConfig(
    level=logging.INFO,
    format="\\033[32m%(levelname)s\\033[0m:     %(message)s",
)
from rhino.server import serve
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
            from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
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
        prog="rhino",
        description="Rhino - A lightweight, production-grade WSGI server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rhino main:app                         Run app from main.py
  rhino myproject.api:app --port 8080    Run on custom port
  rhino main:app --reload                Run with auto-reload
  rhino app:create_app() --host 0.0.0.0  Bind to all interfaces
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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    return parser

def main(args: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    # Print startup banner
    print(f"\033[1m\033[34mRhino\033[0m v{__version__}")
    print(f"Running \033[1m{parsed_args.app}\033[0m")
    print(f"Address: http://{parsed_args.host}:{parsed_args.port}")
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

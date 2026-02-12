"""
minicorn/__main__.py — Enables `python -m minicorn` invocation.
"""

import sys
from minicorn.cli import main

if __name__ == "__main__":
    sys.exit(main())

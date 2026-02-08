"""
rhino/__main__.py — Enables `python -m rhino` invocation.
"""

import sys
from rhino.cli import main

if __name__ == "__main__":
    sys.exit(main())

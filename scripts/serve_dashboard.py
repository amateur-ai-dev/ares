"""Serve the read-only ARES dashboard from a SQLite database."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.dashboard import serve


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8420)
    args = parser.parse_args()
    serve(args.db, args.port)


if __name__ == "__main__":
    main()

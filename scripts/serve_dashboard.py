#!/usr/bin/env python3
"""Serve the ARES dashboard on the loopback interface."""

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.dashboard import make_server
from ares.store import initialize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("data/demo/ares.db"))
    parser.add_argument("--port", type=int, default=8420)
    parser.add_argument(
        "--host",
        default=None,
        help="bind address (default 127.0.0.1, or $ARES_BIND - containers set 0.0.0.0)",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        help="where uploaded logs and archives are stored (default: alongside the database)",
    )
    args = parser.parse_args()

    # The dashboard can now create runs, so the schema has to exist before the
    # first request rather than being a precondition the operator remembers.
    args.db.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(args.db)
    try:
        initialize(connection)
    finally:
        connection.close()

    server = make_server(args.db, args.port, args.workdir, args.host)
    print(f"ARES dashboard: http://127.0.0.1:{args.port}/  (Ctrl-C to stop)")
    print(f"  bound to: {server.server_address[0]}")
    print(f"  database: {args.db}")
    print(f"  uploads:  {args.workdir or args.db.parent / 'work'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()

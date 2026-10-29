"""Hot-standby gate: waits for the port, then serves the same app/database."""
from __future__ import annotations
import os, socket, sys, time
import uvicorn
from .gate import app

PORT = int(os.environ.get("SIGIL_PORT", "18100"))

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            s.bind(("0.0.0.0", PORT))
            s.listen(256)
            print(f"sigil-standby: acquired port {PORT}", flush=True)
            break
        except OSError as e:
            print(f"sigil-standby: waiting ({e})", file=sys.stderr, flush=True)
            time.sleep(0.5)
    config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    server.run(sockets=[s])

if __name__ == "__main__":
    main()

from __future__ import annotations
import os
import uvicorn
from .mcp import create_proxy_app

GATE = os.environ.get("SIGIL_GATE", "http://127.0.0.1:18100")
UP = os.environ.get("SIGIL_MCP_UPSTREAM", "http://127.0.0.1:18080/mcp")
app = create_proxy_app(GATE, UP)

def main():
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18110")),
                log_level="warning")

if __name__ == "__main__":
    main()

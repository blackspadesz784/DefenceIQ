"""DefenceIQ - Render Cloud Deployment Entry Point.

Exports the FastAPI ASGI application for Uvicorn on Render.com.
Dynamically binds to Render's allocated PORT environment variable.
"""

import os
import sys

# Ensure repository root is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from sentinellayer.agent.comms.local_server import LocalServer

# Read port from Render's $PORT env (default 8765 if local)
port = int(os.environ.get("PORT", 8765))
token = os.environ.get("PAIRING_TOKEN", "DIQ-FUXN-G8CE")

# Instantiate LocalServer
server = LocalServer(
    host="0.0.0.0",
    port=port,
    pairing_token=token,
)

# ASGI application handle for Uvicorn
app = server.app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("render_app:app", host="0.0.0.0", port=port, log_level="info")

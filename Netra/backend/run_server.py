"""
Run the API server with Uvicorn. Execute from the backend directory so that
capture and processing packages are on the path:

  cd backend && python run_server.py

Or from project root:

  python backend/run_server.py
"""

import sys
from pathlib import Path

# Ensure project root is on path for backend.* absolute imports
backend_dir = Path(__file__).resolve().parent
project_root = backend_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )

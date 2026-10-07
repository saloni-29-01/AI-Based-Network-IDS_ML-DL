"""Start the IDS dashboard + API server (cross-platform)."""
from __future__ import annotations
import argparse, webbrowser, threading, time
import uvicorn
from app.config import settings

def main() -> int:
    ap = argparse.ArgumentParser(description="Run the AI Network IDS server")
    ap.add_argument("--host", default=settings.host)
    ap.add_argument("--port", type=int, default=settings.port)
    ap.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    ap.add_argument("--reload", action="store_true")
    args = ap.parse_args()
    if args.open:
        def _open():
            time.sleep(2.0); webbrowser.open(f"http://{args.host}:{args.port}/")
        threading.Thread(target=_open, daemon=True).start()
    print(f"IDS dashboard -> http://{args.host}:{args.port}/")
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload, log_level=settings.log_level.lower())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

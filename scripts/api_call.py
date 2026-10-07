"""Tiny helper used by run_project.bat (avoids JSON quoting in cmd.exe).

    python scripts/api_call.py health                     -> exit 0 if server is up
    python scripts/api_call.py /api/demo/start
    python scripts/api_call.py /api/capture/dataset/start rate=25 speed=1
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = f"http://127.0.0.1:{os.environ.get('APP_PORT', '8000')}"


def _val(v: str):
    for cast in (int, float):
        try:
            return cast(v)
        except ValueError:
            pass
    return {"true": True, "false": False}.get(v.lower(), v)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "health":
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=1)
            return 0
        except Exception:
            return 1
    body = {k: _val(v) for k, v in (a.split("=", 1) for a in argv[1:])}
    req = urllib.request.Request(BASE + argv[0], data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        data = json.loads(urllib.request.urlopen(req, timeout=30).read())
        src = data.get("source") or {}
        print("Started:", src.get("label", data))
        return 0
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        try:
            d = json.loads(detail).get("detail")
            detail = d.get("error") if isinstance(d, dict) else d
        except Exception:
            pass
        print("Could not start:", detail)
        return 1
    except Exception as exc:
        print("Server not reachable:", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

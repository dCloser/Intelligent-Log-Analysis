from fastapi import FastAPI, Request, Header, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timezone
import json
import uuid
import sqlite3
import os
import re
import urllib.request

TOKEN = "REDACTED_TOKEN"
LOG_DIR = Path("/tmp/webhooklogs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = LOG_DIR / "webhook.db"

OLLAMA_URL = os.getenv("OLLAMA_URL", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")


def _safe_decode(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS webhook_requests (
                id TEXT PRIMARY KEY,
                ts TEXT,
                client TEXT,
                method TEXT,
                path TEXT,
                headers_json TEXT,
                content_type TEXT,
                content_length TEXT,
                raw_text TEXT,
                parsed_json TEXT,
                monitor TEXT,
                trigger TEXT,
                period_start TEXT,
                period_end TEXT,
                match_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS webhook_events (
                id TEXT PRIMARY KEY,
                request_id TEXT,
                ts TEXT,
                idx INTEGER,
                wazuh_index TEXT,
                wazuh_id TEXT,
                agent_id TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                action TEXT,
                protocol TEXT,
                srcip TEXT,
                dstip TEXT,
                srcport TEXT,
                dstport TEXT,
                rule_id TEXT,
                rule_level INTEGER,
                decoder_name TEXT,
                location TEXT,
                timestamp TEXT,
                full_log TEXT,
                source_json TEXT,
                interpretation_json TEXT,
                interpreted_ts TEXT,
                FOREIGN KEY(request_id) REFERENCES webhook_requests(id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_request ON webhook_events(request_id);
            CREATE INDEX IF NOT EXISTS idx_events_action ON webhook_events(action);
            CREATE INDEX IF NOT EXISTS idx_events_dstport ON webhook_events(dstport);
            CREATE INDEX IF NOT EXISTS idx_events_agent ON webhook_events(agent_name);
            """
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    yield


app = FastAPI(lifespan=lifespan)


def _extract_fields(log_obj: dict) -> dict:
    src = log_obj.get("_source") or {}
    agent = src.get("agent") or {}
    data = src.get("data") or {}
    rule = src.get("rule") or {}
    decoder = src.get("decoder") or {}

    return {
        "wazuh_index": log_obj.get("_index"),
        "wazuh_id": log_obj.get("_id"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "action": data.get("action"),
        "protocol": data.get("protocol"),
        "srcip": data.get("srcip"),
        "dstip": data.get("dstip"),
        "srcport": data.get("srcport"),
        "dstport": data.get("dstport"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "decoder_name": decoder.get("name"),
        "location": src.get("location"),
        "timestamp": src.get("timestamp") or src.get("@timestamp"),
        "full_log": src.get("full_log"),
        "source_json": json.dumps(src, ensure_ascii=False),
    }


def _heuristic_interpret(fields: dict) -> dict:
    action = fields.get("action")
    proto = fields.get("protocol")
    srcip = fields.get("srcip")
    dstip = fields.get("dstip")
    dstport = fields.get("dstport")
    agent = fields.get("agent_name")
    decoder = fields.get("decoder_name")

    title = "Log event"
    if action == "block":
        title = "Blocked traffic"
    elif action == "pass":
        title = "Allowed traffic"

    hints = []
    if decoder == "pf" and action == "block":
        if dstip in ("REDACTED_IP_MULTICAST_1", "REDACTED_IP_MULTICAST_2", "REDACTED_IP_BROADCAST") or proto in ("igmp", "udp") and dstport in ("1900", "5353", "137", "138"):
            hints.append("Multicast/broadcast discovery traffic detected.")
        if dstport in ("22", "3389"):
            hints.append("Inbound scan target detected.")
        hints.append("Validate rule match.")

    summary = f"{agent} {action} {proto} {srcip} -> {dstip}:{dstport}"

    return {
        "title": title,
        "category": "network/firewall",
        "severity": "low" if action == "block" else "info",
        "summary": summary,
        "what_to_check_next": hints[:6],
        "confidence": 0.55,
    }


def _ollama_interpret(fields: dict) -> dict | None:
    if not OLLAMA_URL:
        return None

    prompt = {
        "role": "user",
        "content": (
            "Interpret this firewall/Wazuh event for troubleshooting.\n"
            "Return JSON only with keys: title, category, severity, summary, why_it_happened (list), what_to_check_next (list), confidence.\n\n"
            f"Structured fields:\n{json.dumps(fields, ensure_ascii=False)}\n"
        ),
    }

    body = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "prompt": prompt["content"],
            "stream": False,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            txt = (data.get("response") or "").strip()
            m = re.search(r"\{.*\}", txt, flags=re.S)
            if not m:
                return None
            return json.loads(m.group(0))
    except Exception:
        return None


def _interpret_event_row(event_id: str) -> None:
    with _db() as conn:
        row = conn.execute("SELECT * FROM webhook_events WHERE id = ?", (event_id,)).fetchone()
        if not row:
            return

        fields = {
            "action": row["action"],
            "protocol": row["protocol"],
            "srcip": row["srcip"],
            "dstip": row["dstip"],
            "srcport": row["srcport"],
            "dstport": row["dstport"],
            "agent_name": row["agent_name"],
            "agent_ip": row["agent_ip"],
            "rule_id": row["rule_id"],
            "rule_level": row["rule_level"],
            "decoder_name": row["decoder_name"],
            "location": row["location"],
            "timestamp": row["timestamp"],
            "full_log": row["full_log"],
        }

        interp = _ollama_interpret(fields) or _heuristic_interpret(fields)
        conn.execute(
            "UPDATE webhook_events SET interpretation_json = ?, interpreted_ts = ? WHERE id = ?",
            (json.dumps(interp, ensure_ascii=False), datetime.now(timezone.utc).isoformat(), event_id),
        )


def _html_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system; margin: 24px; }}
    .muted {{ color: #666; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin: 12px 0; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background:#f7f7f7; padding:12px; border-radius:10px; }}
    a {{ text-decoration:none; }}
  </style>
</head>
<body>
  <h2>{title}</h2>
  <div class="muted"><a href="/ui">UI Home</a> · <a href="/ui/requests">Requests</a></div>
  {body}
</body>
</html>"""
    )


@app.get("/ui", response_class=HTMLResponse)
def ui_home():
    body = """
    <div class="card">
      <b>What this UI shows</b>
      <ul>
        <li>Webhook POST data</li>
        <li>Individual log entries</li>
        <li>Event interpretations</li>
      </ul>
      <div>Go to <a href="/ui/requests">/ui/requests</a></div>
    </div>
    """
    return _html_page("Webhook UI", body)


@app.get("/ui/requests", response_class=HTMLResponse)
def ui_requests():
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, ts, client, monitor, trigger, period_start, period_end, match_count "
            "FROM webhook_requests ORDER BY ts DESC LIMIT 200"
        ).fetchall()

    cards = []
    for r in rows:
        cards.append(
            f"""
            <div class="card">
              <div><b><a href="/ui/request/{r['id']}">{r['monitor'] or 'Webhook Request'}</a></b></div>
              <div class="muted">{r['ts']} · client {r['client']} · matches {r['match_count']}</div>
              <div class="muted">trigger {r['trigger']} · {r['period_start']} → {r['period_end']}</div>
            </div>
            """
        )
    return _html_page("Recent Requests", "\n".join(cards) or "<div>No requests yet.</div>")


@app.get("/ui/request/{request_id}", response_class=HTMLResponse)
def ui_request_detail(request_id: str):
    with _db() as conn:
        req_row = conn.execute("SELECT * FROM webhook_requests WHERE id = ?", (request_id,)).fetchone()
        ev_rows = conn.execute(
            "SELECT id, ts, action, protocol, srcip, dstip, dstport, agent_name, rule_id, rule_level "
            "FROM webhook_events WHERE request_id = ? ORDER BY idx ASC",
            (request_id,),
        ).fetchall()

    if not req_row:
        return _html_page("Not found", "<div class='card'>Request not found</div>")

    header = f"""
    <div class="card">
      <div><b>{req_row['monitor'] or 'Request'}</b></div>
      <div class="muted">{req_row['ts']} · client {req_row['client']}</div>
      <div class="muted">trigger {req_row['trigger']} · matches {req_row['match_count']}</div>
      <div class="muted">{req_row['period_start']} → {req_row['period_end']}</div>
    </div>
    """

    items = []
    for e in ev_rows:
        items.append(
            f"""
            <div class="card">
              <div><b><a href="/ui/event/{e['id']}">{e['action']} {e['protocol']} {e['srcip']} → {e['dstip']}:{e['dstport']}</a></b></div>
              <div class="muted">{e['ts']} · agent {e['agent_name']} · rule {e['rule_id']} level {e['rule_level']}</div>
            </div>
            """
        )

    return _html_page("Request detail", header + ("\n".join(items) or "<div class='card'>No events extracted.</div>"))


@app.get("/ui/event/{event_id}", response_class=HTMLResponse)
def ui_event_detail(event_id: str):
    with _db() as conn:
        row = conn.execute("SELECT * FROM webhook_events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return _html_page("Not found", "<div class='card'>Event not found</div>")

    interp = None
    if row["interpretation_json"]:
        try:
            interp = json.loads(row["interpretation_json"])
        except Exception:
            interp = row["interpretation_json"]

    body = f"""
    <div class="card">
      <div><b>{row['action']} {row['protocol']} {row['srcip']} → {row['dstip']}:{row['dstport']}</b></div>
      <div class="muted">{row['ts']} · agent {row['agent_name']} ({row['agent_ip']}) · rule {row['rule_id']} level {row['rule_level']}</div>
      <div class="muted">request: <a href="/ui/request/{row['request_id']}">{row['request_id']}</a></div>
    </div>

    <div class="card">
      <b>LLM / Interpretation</b>
      <pre>{json.dumps(interp, ensure_ascii=False, indent=2) if interp else "Not interpreted yet."}</pre>
    </div>

    <div class="card">
      <b>full_log</b>
      <pre>{row['full_log'] or ""}</pre>
    </div>

    <div class="card">
      <b>_source (stored)</b>
      <pre>{row['source_json'] or ""}</pre>
    </div>
    """
    return _html_page("Event detail", body)


@app.post("/wazuh")
async def wazuh(
    req: Request,
    background: BackgroundTasks,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    ok = (x_api_key == TOKEN) or (authorization == f"Bearer {TOKEN}")
    if not ok:
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await req.body()

    parsed = None
    raw_text = None
    if body:
        try:
            parsed = json.loads(body)
        except Exception:
            raw_text = _safe_decode(body)

    ts = datetime.now(timezone.utc).isoformat()
    request_id = str(uuid.uuid4())
    event = {
        "id": request_id,
        "ts": ts,
        "client": req.client.host if req.client else None,
        "method": req.method,
        "path": str(req.url.path),
        "query": dict(req.query_params),
        "headers": dict(req.headers),
        "content_type": req.headers.get("content-type"),
        "content_length": req.headers.get("content-length"),
        "json": parsed,
        "raw": raw_text if parsed is None else None,
    }

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logfile = LOG_DIR / f"wazuh-webhook-{day}.jsonl"
    _append_jsonl(logfile, event)

    monitor = trigger = period_start = period_end = None
    match_count = None
    logs_list = []

    if isinstance(parsed, dict):
        monitor = parsed.get("monitor")
        trigger = parsed.get("trigger")
        period_start = parsed.get("periodStart")
        period_end = parsed.get("periodEnd")
        match_count = parsed.get("matchCount")
        logs_list = parsed.get("logs") or []

    with _db() as conn:
        conn.execute(
            """
            INSERT INTO webhook_requests
            (id, ts, client, method, path, headers_json, content_type, content_length, raw_text, parsed_json,
             monitor, trigger, period_start, period_end, match_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                ts,
                event["client"],
                event["method"],
                event["path"],
                json.dumps(event["headers"], ensure_ascii=False),
                event["content_type"],
                event["content_length"],
                raw_text,
                json.dumps(parsed, ensure_ascii=False) if parsed is not None else None,
                monitor,
                trigger,
                period_start,
                period_end,
                int(match_count) if isinstance(match_count, int) else None,
            ),
        )

        created_event_ids = []
        if isinstance(logs_list, list):
            for idx, log_obj in enumerate(logs_list):
                if not isinstance(log_obj, dict):
                    continue
                fields = _extract_fields(log_obj)
                ev_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO webhook_events
                    (id, request_id, ts, idx, wazuh_index, wazuh_id, agent_id, agent_name, agent_ip,
                     action, protocol, srcip, dstip, srcport, dstport, rule_id, rule_level, decoder_name,
                     location, timestamp, full_log, source_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev_id,
                        request_id,
                        ts,
                        idx,
                        fields["wazuh_index"],
                        fields["wazuh_id"],
                        fields["agent_id"],
                        fields["agent_name"],
                        fields["agent_ip"],
                        fields["action"],
                        fields["protocol"],
                        fields["srcip"],
                        fields["dstip"],
                        fields["srcport"],
                        fields["dstport"],
                        fields["rule_id"],
                        fields["rule_level"],
                        fields["decoder_name"],
                        fields["location"],
                        fields["timestamp"],
                        fields["full_log"],
                        fields["source_json"],
                    ),
                )
                created_event_ids.append(ev_id)

    for ev_id in created_event_ids[:200]:
        background.add_task(_interpret_event_row, ev_id)

    return {
        "ok": True,
        "saved_to": str(logfile),
        "request_id": request_id,
        "events_created": len(created_event_ids),
    }

Wazuh → Webhook Intelligent Logger
Deployment + alerting + webhook receiver + optional LLM interpretation
This guide shows how to:
•	Ingest pfSense/OPNsense firewall logs into Wazuh (archives/alerts indices).
•	Create a query-level monitor that detects blocked traffic and ships matching log details to a custom webhook.
•	Run a FastAPI webhook server that stores every request + each individual log entry, and (optionally) interprets events with a local LLM (Ollama) for troubleshooting.
•	View incoming webhook messages and interpretations in a lightweight built-in UI.
Architecture
Data flow (high-level):
pfSense/OPNsense → syslog → Wazuh manager
Wazuh → Filebeat → OpenSearch/Elasticsearch indices (wazuh-archives-*, wazuh-alerts-*)
Wazuh Dashboard (OpenSearch Dashboards) → Alerting (Query-level Monitor)
Alerting Action → Notifications Channel (Custom Webhook) → FastAPI receiver (/wazuh)
FastAPI → JSONL + SQLite → /ui (review + interpretation)
Optional: FastAPI → Ollama (local LLM) → per-event interpretation
Prerequisites
•	Wazuh server + Wazuh Dashboard running and ingesting events (you should see wazuh-archives-* / wazuh-alerts-* in Discover).
•	Firewall logs arriving in Wazuh (e.g., pfSense filterlog), producing fields like data.action, data.protocol, full_log.
•	A host to run the webhook receiver (can be the Wazuh server or another VM) reachable from the Wazuh Dashboard server.
•	Python 3.10+ (examples use Python 3.12).
Wazuh ingestion notes (pfSense/OPNsense)
If you already see firewall events in Discover and the fields include data.action and full_log, you can skip this section.
•	Configure pfSense/OPNsense to send syslog to the Wazuh manager (or an agent on the manager).
•	Ensure the Wazuh manager (or agent) is reading the syslog file and decoding pfSense filterlog entries.
•	Confirm the events show up in the archives index (wazuh-archives-*) and/or alerts index (wazuh-alerts-*).
Confirm indices
From the Wazuh server, you can verify indices exist (credentials shown here are placeholders):
curl -k -u 'admin:<REDACTED>' 'https://127.0.0.1:9200/_cat/indices/wazuh*?v'
Create a Discover filter for blocked traffic
In Discover (wazuh-archives-* or wazuh-alerts-*), you can filter blocked events with DQL:
data.action : "block"
If you want only pfSense firewall blocks:
decoder.name : "pf" and data.action : "block"
Create a query-level monitor that sends full log details to a webhook
Wazuh Dashboard uses OpenSearch Dashboards under the hood. Depending on your version, you may not see “Stack Management”; that’s OK. You typically create monitors under the Alerting plugin.
Step 1: Create a Notifications channel (Custom Webhook)
•	In Wazuh Dashboard, open the left menu (☰).
•	Go to Alerting / Notifications (naming varies by version) and create a Channel.
•	Choose: Custom webhook
•	Webhook URL: http://<WEBHOOK_HOST>:9000/wazuh
•	Method: POST
•	Headers:
Content-Type: application/json
X-API-Key: <YOUR_TOKEN>
Important: your webhook server enforces X-API-Key (or Authorization: Bearer <token>). Use a strong token and keep it out of screenshots/logs.
Step 2: Create a query-level monitor
•	Go to Alerting → Monitors → Create monitor
•	Monitor type: Query-level monitor
•	Select index: wazuh-archives-* (or wazuh-alerts-*)
•	Paste an extraction query like the one below
Example extraction query (find recent blocks and include _source so full_log is available):
{
  "size": 50,
  "_source": true,
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-1m" } } },
        { "term": { "data.action.keyword": "block" } }
      ]
    }
  }
}
Step 3: Trigger condition
Common trigger condition: “matchCount > 0” (or “hits.total.value > 0”). Set it to run every 1 minute to match the query window (or adjust both together).
Step 4: Action: send matching log details to your webhook
When configuring the Trigger Action, select your webhook channel and build a JSON message body using Mustache variables.
A practical pattern is to send an array of log hits so your receiver gets per-log details. Example message body:
{
  "monitor": "{{ctx.monitor.name}}",
  "trigger": "{{ctx.trigger.name}}",
  "periodStart": "{{ctx.periodStart}}",
  "periodEnd": "{{ctx.periodEnd}}",
  "matchCount": {{ctx.results.0.hits.total.value}},
  "logs": [
    {{#ctx.results.0.hits.hits}}
    {
      "_id": "{{_id}}",
      "_index": "{{_index}}",
      "_source": {{{_source}}}
    }{{^last}},{{/last}}
    {{/ctx.results.0.hits.hits}}
  ]
}
Notes:
•	The key piece is ctx.results.0.hits.hits, which contains the actual documents. If you don’t reference it, you’ll only see monitor metadata.
•	Some UI builders don’t provide a reliable {{^last}} helper. If your editor doesn’t support it, send a simpler payload (see below).
Simpler (no commas logic): send the first N hits as a rendered text list:
{
  "monitor": "{{ctx.monitor.name}}",
  "trigger": "{{ctx.trigger.name}}",
  "matchCount": {{ctx.results.0.hits.total.value}},
  "lines": [
    {{#ctx.results.0.hits.hits}}
    "{{_source.full_log}}"
    {{/ctx.results.0.hits.hits}}
  ]
}
If you still don’t see full_log in ctx.results, confirm that your query sets “_source”: true and that the index actually stores full_log.
Webhook receiver (FastAPI)
This is the receiver that:
•	Validates X-API-Key or Authorization: Bearer <token>
•	Writes raw requests to a daily JSONL file in /home/palpetine/webhooklogs
•	Stores the monitor request + each individual log event to SQLite
•	Optionally interprets each event using Ollama (local LLM) or a built-in heuristic fallback
•	Serves a small UI at /ui to browse requests and per-event interpretation
Environment variables (no passwords in code)
# Webhook auth token (required)
export WEBHOOK_TOKEN="<SET_A_STRONG_TOKEN>"

# Optional: local Ollama interpreter (recommended)
export OLLAMA_URL="http://127.0.0.1:11434/api/generate"
export OLLAMA_MODEL="llama3.1:8b"
Create a Python virtual environment (recommended)
On Debian/Ubuntu you may see “externally-managed-environment” if you try to pip install globally. Use a venv:
sudo apt-get update
sudo apt-get install -y python3-venv

python3 -m venv /opt/webhook-venv
source /opt/webhook-venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn[standard]
Run the server with Uvicorn
Start the service (replace the filename if you named it differently):
source /opt/webhook-venv/bin/activate
export WEBHOOK_TOKEN="<SET_A_STRONG_TOKEN>"
uvicorn intelligentlogger:app --host 0.0.0.0 --port 9000
Then browse: http://<WEBHOOK_HOST>:9000/ui
Systemd service (optional)
If you want it to run on boot, create a systemd unit (adjust paths/user):
sudo tee /etc/systemd/system/intelligentlogger.service >/dev/null <<'EOF'
[Unit]
Description=Intelligent Wazuh Webhook Logger
After=network.target

[Service]
Type=simple
User=palpetine
WorkingDirectory=/home/palpetine
Environment=WEBHOOK_TOKEN=<SET_A_STRONG_TOKEN>
Environment=OLLAMA_URL=http://127.0.0.1:11434/api/generate
Environment=OLLAMA_MODEL=llama3.1:8b
ExecStart=/opt/webhook-venv/bin/uvicorn intelligentlogger:app --host 0.0.0.0 --port 9000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now intelligentlogger
sudo systemctl status intelligentlogger --no-pager
How the receiver stores and displays logs
Storage locations
•	JSONL (append-only): /home/palpetine/webhooklogs/wazuh-webhook-YYYY-MM-DD.jsonl
•	SQLite DB: /home/palpetine/webhooklogs/webhook.db
Each POST from the monitor is a single “request”. Each individual log inside payload.logs[] is stored as a separate “event” row (so you can interpret and browse each log entry).
UI endpoints
•	/ui - home
•	/ui/requests - recent monitor runs (webhook requests)
•	/ui/request/<request_id> - all log events extracted from one monitor run
•	/ui/event/<event_id> - one event’s full_log, stored _source, and interpretation
Troubleshooting
Webhook test fails with 404 Not Found
•	Your channel URL must include the correct path: http://<WEBHOOK_HOST>:9000/wazuh
•	Verify the server is listening on 0.0.0.0:9000 and the host firewall allows inbound traffic from the dashboard server.
Webhook test fails with 401 Unauthorized
•	Ensure the header name is exactly X-API-Key (case-insensitive, but the UI must set it) and the value matches WEBHOOK_TOKEN.
•	Alternatively set Authorization: Bearer <WEBHOOK_TOKEN>.
500 Internal Server Error: JSONDecodeError
•	This happens when a request has Content-Type: application/json but the body is empty or not valid JSON.
•	The provided receiver reads the raw body once and safely stores it as raw text if JSON parsing fails.
Monitor payload has matchCount but no logs/full_log
•	Confirm your extraction query includes “_source”: true.
•	Confirm you’re querying the correct index (archives vs alerts) and that documents have full_log.
•	In the Action message, reference ctx.results.0.hits.hits (not only ctx.monitor/ctx.trigger).
•	Consider reducing time window size and increasing run frequency to avoid too many matches and truncation.
Security hardening (recommended)
•	Use a long random WEBHOOK_TOKEN and rotate it periodically.
•	Restrict inbound access to port 9000 with firewall rules (allow only the dashboard server).
•	If sending over untrusted networks, put the webhook behind HTTPS (reverse proxy like Nginx/Caddy) and require TLS.
•	Treat logs as sensitive. They may contain internal IPs, hostnames, usernames, and other metadata.
What to do next
•	Add correlation: group repetitive blocks by (srcip, dstip, dstport) and summarize trends.
•	Add enrichment: GeoIP, ASN, threat intel lookups, and pfSense rule mapping.
•	Add triage workflows: open a ticket, notify Slack/Teams, or enrich Wazuh active response rules.

"""Operational API + Event Inspector UI (build plan §25, §31, §33, §34).

stdlib http.server. Endpoints (operation/inspection only — NOT a SIEM):
  GET  /                  → event inspector UI (single page, no framework)
  GET  /health            → {"status":"ok","version":...}
  GET  /metrics           → §40 observability counters
  GET  /api/events        → recent events (full lossless JSON layers)
  GET  /api/events/{id}   → single event
  POST /api/parse         → body: raw telemetry text → parsed lossless event

The API binds loopback by default; exposure is a configuration decision.
Telemetry content is never executed, only JSON-serialized with escaping.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from . import __version__
from .errors import ConfigError
from .event import LosslessEvent
from .pipeline import Pipeline

_UI_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>ULSTP Event Inspector</title>
<style>
 body{font-family:Consolas,monospace;background:#111;color:#ddd;margin:0;padding:16px}
 h1{font-size:18px;color:#7fd}
 table{border-collapse:collapse;width:100%;font-size:12px}
 th,td{border:1px solid #333;padding:4px 8px;text-align:left}
 th{background:#1c2b2a;color:#7fd;cursor:pointer}
 tr:hover{background:#1a2440;cursor:pointer}
 #detail{margin-top:16px;border:1px solid #333;padding:12px;display:none}
 .layer{margin-bottom:10px}
 .layer h3{margin:2px 0;font-size:13px;color:#fc6}
 pre{white-space:pre-wrap;word-break:break-all;margin:2px 0;color:#9c9}
 .kv{margin:1px 0}
 .k{color:#7cf}.v{color:#fd7}
 button{background:#234;color:#cdf;border:1px solid #456;padding:4px 10px;margin-right:6px}
</style></head><body>
<h1>ULSTP Event Inspector <span id="ver"></span></h1>
<div><button onclick="load()">Refresh events</button>
<button onclick="loadMetrics()">Metrics</button>
<span id="count"></span></div>
<table id="events"><thead><tr>
<th>event_id</th><th>time</th><th>transport</th><th>source</th><th>vendor/product</th>
<th>format</th><th>parser</th><th>parse</th><th>validation</th><th>delivery</th>
</tr></thead><tbody></tbody></table>
<div id="metrics"></div>
<div id="detail"></div>
<script>
let EVENTS=[];
document.getElementById('ver').textContent='v'+location.search.slice(1);
async function load(){
 const r=await fetch('/api/events?limit=200');EVENTS=await r.json();
 const tb=document.querySelector('#events tbody');tb.innerHTML='';
 document.getElementById('count').textContent=EVENTS.length+' events';
 for(const e of EVENTS){
  const tr=document.createElement('tr');
  tr.onclick=()=>show(e);
  tr.innerHTML=`<td>${e.ingestion.event_id.slice(0,8)}</td>
   <td>${new Date(e.ingestion.ingested_at_unix_utc*1000).toISOString()}</td>
   <td>${e.transport.transport||''}</td>
   <td>${e.source.status}</td>
   <td>${e.source.vendor||''} ${e.source.product||''}</td>
   <td>${e.parser.format_detected||''}</td>
   <td>${e.parser.name||''}</td>
   <td>${e.parser.status}</td>
   <td>${e.validation.status}</td>
   <td>${e.delivery.status}</td>`;
  tb.appendChild(tr);
 }
}
async function loadMetrics(){
 const r=await fetch('/metrics');const m=await r.json();
 document.getElementById('metrics').innerHTML='<div class="layer"><h3>Metrics</h3><pre>'+
  JSON.stringify(m,null,1)+'</pre></div>';
}
function rows(obj){return Object.entries(obj).map(([k,v])=>
 `<div class="kv"><span class="k">${esc(k)}</span> = <span class="v">${esc(JSON.stringify(v))}</span></div>`).join('');}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function show(e){
 const d=document.getElementById('detail');d.style.display='block';
 d.innerHTML=`<div class="layer"><h3>Identity</h3>
  <div class="kv"><span class="k">event_id</span> = <span class="v">${e.ingestion.event_id}</span></div>
  <div class="kv"><span class="k">source</span> = <span class="v">${e.source.status} ${e.source.vendor||''} ${e.source.product||''}</span></div>
  <div class="kv"><span class="k">format/parser</span> = <span class="v">${e.parser.format_detected} / ${e.parser.name} ${e.parser.version||''}</span></div>
  <div class="kv"><span class="k">evidence</span> = <span class="v">${esc(JSON.stringify(e.source.evidence))}</span></div></div>
  <div class="layer"><h3>Normalized fields</h3>${rows(e.normalized)}</div>
  <div class="layer"><h3>Vendor fields</h3>${rows(e.vendor)}</div>
  <div class="layer"><h3>Unknown fields</h3>${rows(e.unknown)}</div>
  <div class="layer"><h3>Original representations</h3>${rows(e.original)}</div>
  <div class="layer"><h3>Decoded / protocol metadata</h3><pre>${esc(JSON.stringify(e.decoded,null,1))}\n${esc(JSON.stringify(e.protocol_metadata,null,1))}</pre></div>
  <div class="layer"><h3>Parse notes</h3><pre>${esc(e.parser.notes.join('\\n'))}</pre></div>
  <div class="layer"><h3>ORIGINAL RAW EVENT</h3><pre>${esc(e.raw.raw_message||'')}</pre></div>`;
}
load();setInterval(load,10000);
</script></body></html>"""


class ApiServer:
    def __init__(self, pipeline: Pipeline, host: str = "127.0.0.1",
                 port: int = 8080) -> None:
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None

    def start(self) -> None:
        pipeline = self.pipeline

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code: int, body: str, ctype: str = "application/json"):
                data = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                query = self.path.split("?", 1)[1] if "?" in self.path else ""
                if path == "/" or path.startswith("/index"):
                    self._send(200, _UI_HTML, "text/html; charset=utf-8")
                elif path == "/health":
                    self._send(200, json.dumps({"status": "ok", "version": __version__}))
                elif path == "/metrics":
                    self._send(200, json.dumps(pipeline.metrics.snapshot()))
                elif path == "/api/events":
                    limit = 100
                    if "limit=" in query:
                        try:
                            limit = min(int(query.split("limit=")[1].split("&")[0]), 1000)
                        except ValueError:
                            pass
                    events = [e.dict_event() for e in pipeline.history()[-limit:]]
                    self._send(200, json.dumps(events, ensure_ascii=False))
                elif path.startswith("/api/events/"):
                    event_id = path.rsplit("/", 1)[1]
                    found = [e for e in pipeline.history() if e.event_id == event_id]
                    if found:
                        self._send(200, json.dumps(found[0].dict_event(), ensure_ascii=False))
                    else:
                        self._send(404, json.dumps({"error": "event not found"}))
                else:
                    self._send(404, json.dumps({"error": "not found"}))

            def do_POST(self):
                if self.path == "/api/parse":
                    length = int(self.headers.get("Content-Length", 0))
                    if length > pipeline.limits.max_message_bytes * 4:
                        self._send(413, json.dumps({"error": "body too large"}))
                        return
                    raw = self.rfile.read(length).decode("utf-8", errors="replace")
                    ev = pipeline.process_text(raw, meta={"transport": "api"})
                    self._send(200, json.dumps(ev.dict_event(), ensure_ascii=False))
                else:
                    self._send(404, json.dumps({"error": "not found"}))

            def log_message(self, *args):
                pass

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]  # resolved ephemeral port
        t = threading.Thread(target=self._httpd.serve_forever, daemon=True,
                             name="ulstp-api")
        t.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()

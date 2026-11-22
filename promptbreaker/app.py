"""Flask web app around ShopBot: a chat page and a JSON API.

  GET  /            chat page
  POST /api/chat    {"message": str, "ticket": str (optional)} -> {"reply", "tool_calls", "blocked"}
  POST /api/reset   clear refund history (the harness calls this between attacks)
  GET  /api/config  which defenses are on
"""
from __future__ import annotations

from flask import Flask, jsonify, request

from .bot import ShopBot

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Orchid Outfitters support</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#1d1d1f}
#log{border:1px solid #ddd;border-radius:8px;padding:1rem;min-height:240px;margin-bottom:1rem}
.u{text-align:right;color:#0b57d0}.b{white-space:pre-wrap}.t{font-size:.8rem;color:#777}
textarea,input{width:100%;box-sizing:border-box;margin:.25rem 0;padding:.5rem;font:inherit}
button{padding:.5rem 1rem;font:inherit}
</style></head><body>
<h1>Orchid Outfitters support</h1>
<p class="t">Logged in as alice. Defenses: <span id="cfg"></span></p>
<div id="log"></div>
<input id="msg" placeholder="Message ShopBot" autocomplete="off">
<textarea id="ticket" rows="3" placeholder="Optional: paste support ticket text"></textarea>
<button id="send">Send</button>
<script>
const log=document.getElementById('log');
function add(cls,text){const d=document.createElement('div');d.className=cls;d.textContent=text;log.appendChild(d);}
fetch('/api/config').then(r=>r.json()).then(c=>{document.getElementById('cfg').textContent=c.defenses.join(', ')||'none';});
document.getElementById('send').onclick=async()=>{
  const message=document.getElementById('msg').value, ticket=document.getElementById('ticket').value;
  if(!message) return; add('u',message);
  const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message,ticket})});
  const j=await r.json(); add('b',j.reply);
  (j.tool_calls||[]).forEach(c=>add('t',`tool ${c.tool} ${JSON.stringify(c.args)}: ${c.result}`));
  document.getElementById('msg').value='';
};
</script></body></html>"""

MAX_INPUT = 4000


def create_app(llm, defenses=()) -> Flask:
    app = Flask(__name__)
    state = {"bot": ShopBot(llm, set(defenses))}

    @app.get("/")
    def index():
        return PAGE

    @app.get("/api/config")
    def config():
        return jsonify(defenses=sorted(state["bot"].defenses))

    @app.post("/api/reset")
    def reset():
        state["bot"] = ShopBot(llm, set(defenses))
        return jsonify(ok=True)

    @app.post("/api/chat")
    def chat():
        body = request.get_json(silent=True) or {}
        message, ticket = str(body.get("message", "")), str(body.get("ticket", ""))
        if not message or len(message) > MAX_INPUT or len(ticket) > MAX_INPUT:
            return jsonify(error=f"message required; message and ticket max {MAX_INPUT} chars"), 400
        t = state["bot"].chat(message, ticket)
        return jsonify(reply=t.reply, tool_calls=t.tool_calls, blocked=t.blocked)

    return app

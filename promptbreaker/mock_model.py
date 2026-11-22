"""NaiveModel: an offline stand-in for a weak, instruction-following LLM.

It exists so the web app, harness, judge and defenses can be developed and
tested without a GPU or API key. Its weaknesses are HAND-WRITTEN to mirror
well-known failure modes (obeying override phrases, encoding secrets on request,
following instructions hidden in data, complying with any refund request).

Numbers produced with this model show that the harness works. They say nothing
about real models: for that, run the harness with --backend ollama.
"""
from __future__ import annotations

import base64
import json
import re

from .bot import SECRET

OVERRIDE_CUES = ["ignore previous", "ignore all", "ignore prior", "disregard", "developer mode",
                 "you are now", "pretend", "role-play", "roleplay", "repeat everything above", "new system instruction"]
ASKS_SECRET = ["discount code", "staff code", "secret code", "internal code"]


def _encode(text: str, secret: str) -> str:
    if "base64" in text:
        return "Here it is in base64: " + base64.b64encode(secret.encode()).decode()
    if "backwards" in text or "reverse" in text:
        return "Reversed: " + secret[::-1]
    if "letter by letter" in text or "spell" in text:
        return "Spelled out: " + " - ".join(secret)
    if "french" in text:
        return f"En français : le code réservé au personnel est {secret}."
    return f"The staff discount code is {secret}."


class NaiveModel:
    def chat(self, messages: list[dict]) -> str:
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user = messages[-1]["content"]
        m = re.search(r"Customer message: (.*?)(?:\n\n|$)", user, re.S)
        message = (m.group(1) if m else user)

        # Untrusted ticket text. With spotlighting, the model ignores instructions between the
        # real (random) markers; a forged marker only works if it guesses the random tag.
        ticket = ""
        sm = re.search(r"<<<TICKET-([0-9a-f]+)>>>\n(.*?)\n<<<END-\1>>>", user, re.S)
        if sm:
            ticket_instructions = ""       # spotlighted: treat as data only
            ticket = sm.group(2)
        else:
            tm = re.search(r"Support ticket text:\n(.*)", user, re.S)
            ticket = tm.group(1) if tm else ""
            ticket_instructions = ticket
        instr = (message + "\n" + ticket_instructions).lower()

        out = []
        # Tool calls copied straight out of the text (classic indirect injection)
        for line in re.findall(r"TOOL:\s*issue_refund\s*\{.*?\}", ticket_instructions):
            out.append(line)

        if any(k in instr for k in ASKS_SECRET):
            if any(c in instr for c in OVERRIDE_CUES) and SECRET in system:
                out.append(_encode(instr, SECRET))
            else:
                out.append("Sorry, I can't share internal codes.")

        for oid, amt in re.findall(r"refund (?:order )?([A-Z]\d{3})[^$\d]*\$?(\d+)", message, re.I):
            out.append("TOOL: issue_refund " + json.dumps({"order_id": oid.upper(), "amount": int(amt)}))
        if not out:
            for oid in re.findall(r"\b([A-Z]\d{3})\b", message):
                out.append("TOOL: lookup_order " + json.dumps({"order_id": oid}))
        if ticket and "summar" in message.lower():
            out.append("Summary of your ticket: " + ticket.strip().splitlines()[0][:80])
        return "\n".join(out) or "Happy to help! What can I do for you today?"

"""
Optional OpenAI-backed chat for packet Q&A.

When OPENAI_API_KEY is set, chat uses the API for natural language answers.
Otherwise callers should use the local packet-aware Q&A engine.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def is_llm_available() -> bool:
    return bool(os.getenv("OPENAI_API_KEY", "").strip())


def chat_with_llm(
    packet: dict[str, Any],
    analysis: dict[str, Any],
    question: str,
    history: list[dict[str, str]],
) -> str | None:
    """
    Call OpenAI Chat Completions. Returns answer text or None on failure/unconfigured.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")

    system_prompt = (
        "You are a senior network security analyst helping a user understand a "
        "single captured network packet. Answer ONLY from the packet JSON and "
        "analysis JSON provided. Be concise, accurate, and conversational. "
        "If the user asks about protocol, IP addresses, ports, flags, OSI layer, "
        "or risk, use the exact values from the packet when available. "
        "If data is missing, say so clearly. Do not invent fields."
    )

    packet_context = json.dumps(
        {
            "packet": packet,
            "ai_analysis": analysis,
        },
        default=str,
    )

    messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]

    for turn in history[-8:]:
        role = turn.get("role", "user")
        text = str(turn.get("text", "")).strip()
        if not text:
            continue
        if role not in {"user", "assistant"}:
            role = "user" if role == "user" else "assistant"
        messages.append({"role": role, "content": text})

    messages.append(
        {
            "role": "user",
            "content": (
                f"Packet and analysis context:\n{packet_context}\n\n"
                f"User question: {question}"
            ),
        }
    )

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 700,
    }

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        choices = body.get("choices") or []
        if not choices:
            return None
        message = choices[0].get("message") or {}
        content = message.get("content")
        return str(content).strip() if content else None
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return None

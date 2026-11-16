"""
Local packet-aware Q&A engine (no external API required).

Answers networking questions using actual packet field values and
built-in protocol knowledge.
"""

from __future__ import annotations

import re
from typing import Any


PROTOCOL_KNOWLEDGE: dict[str, dict[str, str]] = {
    "TCP": {
        "layer": "Transport layer (OSI Layer 4)",
        "function": (
            "TCP provides reliable, connection-oriented communication with "
            "sequencing, acknowledgments, and retransmission. It is used when "
            "data integrity and delivery order matter (web, email, SSH, etc.)."
        ),
    },
    "UDP": {
        "layer": "Transport layer (OSI Layer 4)",
        "function": (
            "UDP provides connectionless, best-effort datagram delivery with "
            "lower overhead than TCP. Common for DNS, streaming, VoIP, and gaming."
        ),
    },
    "ICMP": {
        "layer": "Network layer (OSI Layer 3)",
        "function": (
            "ICMP carries control and diagnostic messages such as ping "
            "(echo request/reply) and unreachable notifications."
        ),
    },
    "IP": {
        "layer": "Network layer (OSI Layer 3)",
        "function": (
            "IP handles logical addressing and routing of packets between hosts "
            "across networks."
        ),
    },
    "IPv6": {
        "layer": "Network layer (OSI Layer 3)",
        "function": (
            "IPv6 is the newer Internet Protocol with larger address space and "
            "simplified header options compared to IPv4."
        ),
    },
    "Ethernet": {
        "layer": "Data link layer (OSI Layer 2)",
        "function": (
            "Ethernet frames carry traffic on local LAN segments using MAC addresses."
        ),
    },
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _mentions_any(text: str, phrases: list[str]) -> bool:
    return any(p in text for p in phrases)


def _field(packet: dict[str, Any], key: str, fallback: str = "not available") -> str:
    value = packet.get(key)
    if value is None or value == "":
        return fallback
    return str(value)


def answer_question_locally(
    packet: dict[str, Any],
    analysis: dict[str, Any],
    question: str,
) -> str:
    q = _norm(question)
    if not q:
        q = "explain this packet"

    proto = str(packet.get("protocol") or "unknown").upper()
    proto_name = packet.get("protocol_name") or proto
    info = PROTOCOL_KNOWLEDGE.get(proto, {})

    src = _field(packet, "source_ip")
    dst = _field(packet, "destination_ip")
    sport = packet.get("source_port")
    dport = packet.get("destination_port")
    flags = _field(packet, "flags", "none")
    size = packet.get("packet_size")
    ts = packet.get("human_readable_time") or packet.get("timestamp")
    summary = _field(packet, "summary", "no summary")
    payload = _field(packet, "payload", "no payload preview captured")

    risk = str(analysis.get("risk_level") or "LOW").upper()
    risk_score = analysis.get("risk_score", 0.0)
    reasons = analysis.get("reasons") or []

    # --- Intent: protocol type ---
    if _mentions_any(
        q,
        [
            "what protocol",
            "which protocol",
            "type of protocol",
            "protocol used",
            "protocol is this",
            "protocol in this packet",
        ],
    ):
        return (
            f"This packet uses {proto} ({proto_name}). "
            f"It operates at the {info.get('layer', 'unknown layer')}."
        )

    # --- Intent: OSI / layer ---
    if _mentions_any(q, ["osi", "what layer", "which layer", "network layer", "transport layer"]):
        layer = info.get("layer", "Layer depends on the highest parsed header in this capture.")
        return f"For this packet, {proto} is associated with the {layer}."

    # --- Intent: protocol function / purpose ---
    if _mentions_any(
        q,
        [
            "function",
            "functionality",
            "purpose",
            "what does",
            "used for",
            "why use",
        ],
    ) and ("protocol" in q or proto.lower() in q):
        fn = info.get(
            "function",
            f"{proto} is a network protocol identified in this capture.",
        )
        return f"{proto} functionality: {fn}"

    # --- Intent: source IP ---
    if _mentions_any(q, ["source ip", "source address", "src ip", "where from", "who sent"]):
        port_part = f" and source port {sport}" if sport is not None else ""
        return f"The source IP address is {src}{port_part}."

    # --- Intent: destination IP ---
    if _mentions_any(
        q,
        ["destination ip", "dest ip", "destination address", "dst ip", "where to", "sent to"],
    ):
        port_part = f" and destination port {dport}" if dport is not None else ""
        return f"The destination IP address is {dst}{port_part}."

    # --- Intent: ports ---
    if "source port" in q or ("port" in q and "source" in q):
        return (
            f"Source port: {sport if sport is not None else 'not present'}. "
            f"Destination port: {dport if dport is not None else 'not present'}."
        )
    if "destination port" in q or ("port" in q and ("dest" in q or "destination" in q)):
        return (
            f"Destination port: {dport if dport is not None else 'not present'}. "
            f"Source port: {sport if sport is not None else 'not present'}."
        )
    if "port" in q:
        return (
            f"Ports in this packet — source: {sport if sport is not None else 'N/A'}, "
            f"destination: {dport if dport is not None else 'N/A'}."
        )

    # --- Intent: flags ---
    if _mentions_any(q, ["flag", "tcp flag", "syn", "ack", "fin", "rst"]):
        if flags == "none":
            return (
                f"No explicit TCP flags were parsed for this packet. "
                f"Summary hint: {summary}"
            )
        return f"Parsed TCP flags for this packet: {flags}. Summary: {summary}"

    # --- Intent: size / length ---
    if _mentions_any(q, ["length", "size", "how big", "packet size", "bytes"]):
        return f"This packet size is {size if size is not None else 'unknown'} bytes."

    # --- Intent: timestamp ---
    if _mentions_any(q, ["time", "timestamp", "when", "captured"]):
        return f"This packet was captured at {ts}."

    # --- Intent: payload ---
    if _mentions_any(q, ["payload", "data", "content", "body"]):
        return (
            f"Safe payload preview (hex, truncated): {payload}. "
            "Full raw payload is not exposed for safety."
        )

    # --- Intent: risk / security ---
    if _mentions_any(
        q,
        ["risk", "dangerous", "safe", "malicious", "suspicious", "threat", "score"],
    ):
        reason_text = "; ".join(str(r) for r in reasons[:4]) if reasons else "No specific anomaly reasons."
        return (
            f"Risk level: {risk} (score {risk_score}). "
            f"Reasons: {reason_text}. "
            f"Recommended action: {analysis.get('recommended_action', 'Continue monitoring.')}"
        )

    # --- Intent: attack / scan ---
    if _mentions_any(q, ["attack", "scan", "port scan", "syn flood", "part of an attack"]):
        if risk == "HIGH":
            verdict = "Yes — current indicators suggest this may be part of hostile activity."
        elif risk == "MEDIUM":
            verdict = "Possibly — behavior looks suspicious and should be investigated."
        else:
            verdict = "No strong attack signature is present for this single packet."
        return f"{verdict} Risk: {risk}. Details: {'; '.join(str(r) for r in reasons[:3]) or 'none'}."

    # --- Intent: summary / explain packet ---
    if _mentions_any(q, ["summary", "explain", "describe", "overview", "tell me about"]):
        return (
            f"Packet #{packet.get('packet_id', '?')}: {src}:{sport if sport is not None else '-'} → "
            f"{dst}:{dport if dport is not None else '-'} over {proto} "
            f"({size} bytes). {summary}. Risk: {risk}."
        )

    # --- Default: answer using best-effort mapping from question keywords ---
    hints: list[str] = []
    if "ip" in q:
        hints.append(f"source IP={src}, destination IP={dst}")
    if "protocol" in q:
        hints.append(f"protocol={proto} ({proto_name})")
    if hints:
        return (
            f"Based on this packet: {', '.join(hints)}. "
            f"Ask specifically about source IP, destination IP, protocol, ports, layer, flags, or risk."
        )

    return (
        f"I can help with this packet: {proto} from {src} to {dst} "
        f"(ports {sport}/{dport}, {size} bytes). "
        f"Try asking: 'What protocol is used?', 'What is the destination IP?', "
        f"'At what OSI layer does {proto} operate?', or 'Is this packet risky?'"
    )

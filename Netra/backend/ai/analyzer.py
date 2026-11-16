"""
Lightweight in-memory AI analysis engine for packet risk classification.

Implements rule-based detections and returns a structured security assessment.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from backend.ai.chat_engine import answer_question_locally
from backend.ai.llm_client import chat_with_llm, is_llm_available


@dataclass
class _ConnectionAttempts:
    syn_timestamps: deque[float]
    established_count: int = 0


class PacketAnalyzer:
    """
    Stateful rule engine that scores packets in near real time.
    """

    _SENSITIVE_PORTS = {21, 22, 3389}

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests_per_ip: dict[str, deque[float]] = defaultdict(deque)
        self.ports_accessed_per_ip: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.connection_attempts: dict[str, _ConnectionAttempts] = defaultdict(
            lambda: _ConnectionAttempts(syn_timestamps=deque())
        )

    def reset(self) -> None:
        with self._lock:
            self.requests_per_ip.clear()
            self.ports_accessed_per_ip.clear()
            self.connection_attempts.clear()

    def analyze_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        """
        Analyze a packet and return a deterministic AI-style threat assessment.

        Output includes both Phase 4 fields and a strict structured output:
        - risk_level/label/reason/score
        - threat_level/attack_type/confidence_score/explanation/recommendation
        """
        if not isinstance(packet, dict) or not packet:
            return self._build_response(
                score=0,
                reasons=["Packet is empty or malformed"],
                attack_type="Unknown",
                source_ip="unknown",
            )

        source_ip = str(packet.get("source_ip") or "unknown")
        destination_port = packet.get("destination_port")
        packet_size = int(packet.get("packet_size") or 0)
        timestamp = self._safe_ts(packet.get("timestamp"))
        summary = str(packet.get("summary") or "")
        protocol = str(packet.get("protocol") or "unknown").upper()

        score = 0
        reasons: list[str] = []
        attack_type = "Normal"

        with self._lock:
            # Rule 1 + Rule 4: packet rate and burst tracking
            req_window = self.requests_per_ip[source_ip]
            req_window.append(timestamp)
            self._trim_timestamps(req_window, cutoff=timestamp - 10)
            one_sec_count = self._count_since(req_window, timestamp - 1)
            ten_sec_count = len(req_window)

            if one_sec_count >= 60:
                score += 35
                reasons.append(
                    f"Traffic spike detected: {one_sec_count} packets/sec from {source_ip}"
                )
                attack_type = "Suspicious"
            elif ten_sec_count >= 240:
                score += 25
                reasons.append(
                    f"High sustained volume from {source_ip} ({ten_sec_count} packets/10s)"
                )
                attack_type = "Suspicious"

            # Rule 1: port scan behavior
            if isinstance(destination_port, int):
                ports_window = self.ports_accessed_per_ip[source_ip]
                ports_window.append((timestamp, destination_port))
                self._trim_port_window(ports_window, cutoff=timestamp - 8)
                unique_ports = {p for _, p in ports_window}

                if len(unique_ports) >= 12:
                    score += 45
                    reasons.append(
                        f"Possible port scan: {len(unique_ports)} unique destination ports in 8s"
                    )
                    attack_type = "Suspicious"

                # Rule 3: repeated access to sensitive ports
                if destination_port in self._SENSITIVE_PORTS:
                    sensitive_hits = sum(
                        1 for ts, p in ports_window if p == destination_port and ts >= timestamp - 20
                    )
                    if sensitive_hits >= 8:
                        score += 25
                        reasons.append(
                            f"Repeated access to sensitive port {destination_port} ({sensitive_hits} hits/20s)"
                        )
                        attack_type = "Suspicious"

            # Rule 2: SYN flood pattern heuristic
            conn = self.connection_attempts[source_ip]
            summary_upper = summary.upper()
            has_syn = "FLAGS [S" in summary_upper or " SYN" in summary_upper
            has_ack = "FLAGS [A" in summary_upper or " ACK" in summary_upper
            has_syn_ack = "FLAGS [SA" in summary_upper or " SYN,ACK" in summary_upper

            if protocol == "TCP" and has_syn and not has_ack and not has_syn_ack:
                conn.syn_timestamps.append(timestamp)
            elif protocol == "TCP" and (has_ack or has_syn_ack):
                conn.established_count += 1

            self._trim_timestamps(conn.syn_timestamps, cutoff=timestamp - 10)
            syn_recent = len(conn.syn_timestamps)
            if syn_recent >= 40:
                ack_baseline = max(1, conn.established_count)
                syn_ratio = syn_recent / ack_baseline
                if syn_ratio >= 10:
                    score += 55
                    reasons.append(
                        f"SYN flood pattern: {syn_recent} SYNs in 10s with low ACK completion ratio"
                    )
                    attack_type = "Malicious"

            # Rule 5: unusually large packet
            if packet_size >= 1450:
                score += 15
                reasons.append(f"Large packet size observed ({packet_size} bytes)")
                if attack_type == "Normal":
                    attack_type = "Suspicious"

        return self._build_response(
            score=score,
            reasons=reasons,
            attack_type=attack_type,
            source_ip=source_ip,
        )

    @staticmethod
    def _safe_ts(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return time.time()

    @staticmethod
    def _trim_timestamps(items: deque[float], cutoff: float) -> None:
        while items and items[0] < cutoff:
            items.popleft()

    @staticmethod
    def _trim_port_window(items: deque[tuple[float, int]], cutoff: float) -> None:
        while items and items[0][0] < cutoff:
            items.popleft()

    @staticmethod
    def _count_since(items: deque[float], cutoff: float) -> int:
        return sum(1 for ts in items if ts >= cutoff)

    @staticmethod
    def _to_levels(score: int) -> tuple[str, str, str]:
        if score >= 80:
            return "High", "high", "Malicious"
        if score >= 45:
            return "Medium", "medium", "Suspicious"
        return "Low", "low", "Normal"

    def _build_response(
        self,
        *,
        score: int,
        reasons: list[str],
        attack_type: str,
        source_ip: str,
    ) -> dict[str, Any]:
        bounded_score = max(0, min(int(score), 100))
        risk_level, threat_level, label = self._to_levels(bounded_score)
        reason = "; ".join(reasons) if reasons else "Traffic pattern appears normal."
        recommendation = self._recommendation_for_level(threat_level)
        risk_score = round(bounded_score / 100.0, 3)
        strict_level = risk_level.upper()

        # Keep both key sets to satisfy current and planned consumers.
        return {
            "risk_score": risk_score,
            "risk_level": strict_level,
            "reasons": reasons if reasons else ["No anomaly signals matched current rules"],
            "explanation": reason,
            "recommended_action": recommendation,
            "legacy_risk_level": risk_level,
            "label": label,
            "reason": reason,
            "score": bounded_score,
            "threat_level": threat_level,
            "attack_type": attack_type if attack_type != "Normal" else label,
            "confidence_score": bounded_score,
            "recommendation": recommendation,
            "source_ip": source_ip,
            "tags": self._tags_for_reasons(reasons),
        }

    @staticmethod
    def _recommendation_for_level(level: str) -> str:
        if level == "high":
            return "Isolate source host, block IP temporarily, and inspect firewall and endpoint logs."
        if level == "medium":
            return "Monitor source IP closely, validate expected service exposure, and rate-limit if needed."
        return "No immediate action needed; continue monitoring."

    @staticmethod
    def _tags_for_reasons(reasons: list[str]) -> list[str]:
        tags: list[str] = []
        reason_text = " ".join(reasons).lower()
        if "scan" in reason_text or "ports" in reason_text:
            tags.append("port_scan")
        if "syn flood" in reason_text or "syns" in reason_text:
            tags.append("syn_flood")
        if "spike" in reason_text or "volume" in reason_text:
            tags.append("traffic_spike")
        if "large packet" in reason_text:
            tags.append("oversized_packet")
        return tags

    def answer_packet_question(
        self,
        packet: dict[str, Any],
        analysis: dict[str, Any],
        question: str,
        history: list[dict[str, str]],
    ) -> dict[str, Any]:
        """
        Answer a user question about a specific packet.

        Uses OpenAI when OPENAI_API_KEY is configured; otherwise uses the
        local intent-based networking Q&A engine (always packet-specific).
        """
        q = (question or "").strip()
        if not q:
            q = "Explain this packet."

        normalized_history = []
        for turn in history or []:
            role = turn.get("role", "user")
            text = str(turn.get("text", "")).strip()
            if not text:
                continue
            normalized_history.append(
                {
                    "role": "assistant" if role in {"ai", "assistant"} else "user",
                    "text": text,
                }
            )

        answer: str | None = None
        engine = "local"

        if is_llm_available():
            answer = chat_with_llm(packet, analysis, q, normalized_history)
            if answer:
                engine = "openai"

        if not answer:
            answer = answer_question_locally(packet, analysis, q)
            engine = "local"

        risk = str(analysis.get("risk_level") or "LOW").upper()
        risk_score = analysis.get("risk_score", 0.0)
        reasons = analysis.get("reasons") or []
        recommendation = analysis.get("recommended_action") or analysis.get(
            "recommendation", "Continue monitoring this source."
        )

        return {
            "answer": answer,
            "engine": engine,
            "risk_level": risk,
            "risk_score": risk_score,
            "reasons": reasons,
            "recommended_action": recommendation,
        }


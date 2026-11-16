"""
Packet processing module: transforms PacketData from the capture engine
into structured records for the UI (IDs, human-readable time, protocol names).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from capture.packet_capture import PacketData

# -----------------------------------------------------------------------------
# Protocol display names for the UI
# -----------------------------------------------------------------------------

PROTOCOL_DISPLAY_NAMES: dict[str, str] = {
    "TCP": "Transmission Control Protocol",
    "UDP": "User Datagram Protocol",
    "ICMP": "Internet Control Message Protocol",
    "IP": "Internet Protocol",
    "IPv6": "Internet Protocol Version 6",
    "Ethernet": "Ethernet",
    "unknown": "Unknown",
}


def get_protocol_display_name(protocol: str) -> str:
    """Return a human-readable protocol name for the UI."""
    return PROTOCOL_DISPLAY_NAMES.get(protocol, protocol)


def format_timestamp_for_ui(timestamp: float) -> str:
    """Convert Unix timestamp to ISO 8601 string for display."""
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# -----------------------------------------------------------------------------
# Processed packet record (UI-ready)
# -----------------------------------------------------------------------------


@dataclass
class ProcessedPacket:
    """
    UI-ready packet record with ids and human-readable fields.
    All fields are JSON-serializable.
    """

    packet_id: int
    timestamp: float
    human_readable_time: str
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    protocol_name: str
    source_port: int | None
    destination_port: int | None
    flags: str | None
    packet_size: int
    payload: str | None
    summary: str
    ai_analysis: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict for the frontend."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize this record to a JSON string."""
        return json.dumps(self.to_dict(), default=str)


# -----------------------------------------------------------------------------
# Parsing: PacketData -> ProcessedPacket
# -----------------------------------------------------------------------------


def parse_packet(packet_data: PacketData, packet_id: int) -> ProcessedPacket:
    """
    Transform a single PacketData from the capture engine into a UI-ready record.

    Args:
        packet_data: Raw packet from capture.packet_capture.
        packet_id: 1-based index for display (e.g. table row number).

    Returns:
        ProcessedPacket with packet_id, human_readable_time, protocol_name, etc.
    """
    human_time = format_timestamp_for_ui(packet_data.timestamp)
    protocol_name = get_protocol_display_name(packet_data.protocol)

    return ProcessedPacket(
        packet_id=packet_id,
        timestamp=packet_data.timestamp,
        human_readable_time=human_time,
        source_ip=packet_data.src_ip,
        destination_ip=packet_data.dst_ip,
        protocol=packet_data.protocol,
        protocol_name=protocol_name,
        source_port=packet_data.src_port,
        destination_port=packet_data.dst_port,
        flags=packet_data.tcp_flags,
        packet_size=packet_data.length,
        payload=packet_data.payload_preview,
        summary=packet_data.summary or "",
    )


def parse_packets(packets: list) -> list[ProcessedPacket]:
    """
    Transform a list of PacketData (or dicts with the same shape) into UI-ready records.

    Accepts PacketData instances or dicts with keys: timestamp, length, protocol,
    src_ip, dst_ip, src_port, dst_port, summary. This keeps the processor
    decoupled from the capture module at runtime if needed.

    Returns:
        List of ProcessedPacket in the same order, with packet_id 1, 2, 3, ...
    """
    result: list[ProcessedPacket] = []
    for i, raw in enumerate(packets, start=1):
        if hasattr(raw, "timestamp"):
            # PacketData-like object
            record = parse_packet(raw, packet_id=i)
        elif isinstance(raw, dict):
            record = _parse_packet_dict(raw, packet_id=i)
        else:
            continue
        result.append(record)
    return result


def _parse_packet_dict(raw: dict[str, Any], packet_id: int) -> ProcessedPacket:
    """Build ProcessedPacket from a dict (e.g. from JSON or capture.to_dict())."""
    ts = float(raw.get("timestamp", 0))
    return ProcessedPacket(
        packet_id=packet_id,
        timestamp=ts,
        human_readable_time=format_timestamp_for_ui(ts),
        source_ip=raw.get("src_ip"),
        destination_ip=raw.get("dst_ip"),
        protocol=str(raw.get("protocol", "unknown")),
        protocol_name=get_protocol_display_name(str(raw.get("protocol", "unknown"))),
        source_port=raw.get("src_port"),
        destination_port=raw.get("dst_port"),
        flags=raw.get("tcp_flags"),
        packet_size=int(raw.get("length", 0)),
        payload=raw.get("payload_preview"),
        summary=str(raw.get("summary", "")),
    )


# -----------------------------------------------------------------------------
# JSON output for the frontend
# -----------------------------------------------------------------------------


def processed_packets_to_json(processed: list[ProcessedPacket]) -> str:
    """
    Return a JSON array of packet records ready for the frontend.

    Each object has: packet_id, timestamp, human_readable_time, source_ip,
    destination_ip, protocol, protocol_name, source_port, destination_port,
    packet_size, summary.
    """
    payload = [p.to_dict() for p in processed]
    return json.dumps(payload, default=str)


def process_and_serialize(packets: list) -> str:
    """
    One-step: parse PacketData (or dict) list and return JSON for the frontend.
    """
    processed = parse_packets(packets)
    return processed_packets_to_json(processed)

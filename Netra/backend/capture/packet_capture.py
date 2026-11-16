"""
Packet capture engine using Scapy.

Captures packets in real time, extracts key fields, and returns
structured data suitable for JSON serialization. Designed for use
by the API layer; no business logic or storage.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Optional

# -----------------------------------------------------------------------------
# Structured packet representation (JSON-serializable)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PacketData:
    """
    Immutable snapshot of a captured packet's key fields.
    All optional fields are None when the layer is not present (e.g. no IP).
    """

    timestamp: float
    length: int
    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_preview: Optional[str] = None
    # Optional extra fields for display or analysis (e.g. Scapy summary)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize this packet to a JSON string."""
        return json.dumps(self.to_dict(), default=str)


# -----------------------------------------------------------------------------
# Extraction logic: Scapy packet -> PacketData
# -----------------------------------------------------------------------------


def _get_protocol_name(pkt: Any) -> str:
    """
    Derive a short protocol name from the topmost relevant layer.
    Handles TCP, UDP, ICMP, and generic IP; falls back to layer name or 'unknown'.
    """
    if pkt.haslayer("TCP"):
        return "TCP"
    if pkt.haslayer("UDP"):
        return "UDP"
    if pkt.haslayer("ICMP"):
        return "ICMP"
    if pkt.haslayer("IP"):
        return "IP"
    if pkt.haslayer("IPv6"):
        return "IPv6"
    if pkt.haslayer("Ether"):
        return "Ethernet"
    # Fallback: use the top layer's name if available
    if hasattr(pkt, "name"):
        return getattr(pkt, "name", "unknown")
    return "unknown"


def _get_summary(pkt: Any, max_len: int = 200) -> str:
    """Build a short human-readable summary of the packet."""
    if hasattr(pkt, "summary") and callable(pkt.summary):
        s = pkt.summary()
        return (s[:max_len] + "…") if len(s) > max_len else s
    return str(pkt)[:max_len]


def extract_packet_data(pkt: Any) -> PacketData:
    """
    Extract structured fields from a Scapy packet.

    Works with IPv4 and IPv6. Source/destination IP and ports are set
    only when the corresponding layers are present; otherwise they remain None.
    """
    # Prefer packet timestamp (e.g. from pcap); fallback to current time for live capture
    timestamp = float(getattr(pkt, "time", time.time()))
    length = len(pkt) if hasattr(pkt, "__len__") else 0
    protocol = _get_protocol_name(pkt)
    summary = _get_summary(pkt)

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_preview: Optional[str] = None

    # IP layer (IPv4 or IPv6)
    if pkt.haslayer("IP"):
        ip = pkt["IP"]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
    elif pkt.haslayer("IPv6"):
        ip6 = pkt["IPv6"]
        src_ip = str(ip6.src)
        dst_ip = str(ip6.dst)

    # TCP / UDP ports
    if pkt.haslayer("TCP"):
        tcp = pkt["TCP"]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        try:
            tcp_flags = str(tcp.flags)
        except Exception:
            tcp_flags = None
    elif pkt.haslayer("UDP"):
        udp = pkt["UDP"]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    if pkt.haslayer("Raw"):
        try:
            raw_bytes = bytes(pkt["Raw"].load)
            if raw_bytes:
                payload_preview = raw_bytes[:80].hex()
        except Exception:
            payload_preview = None

    return PacketData(
        timestamp=timestamp,
        length=length,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        payload_preview=payload_preview,
        summary=summary,
    )


# -----------------------------------------------------------------------------
# Live capture
# -----------------------------------------------------------------------------


def capture_packets(
    count: int = 100,
    timeout_seconds: Optional[int] = None,
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    *,
    on_packet: Optional[Callable[[PacketData], None]] = None,
) -> list[PacketData]:
    """
    Capture packets in real time and return a list of structured PacketData.

    Args:
        count: Maximum number of packets to capture (sniff stops when reached).
        timeout_seconds: Optional timeout in seconds; capture stops when reached.
        interface: Network interface name (e.g. 'eth0', 'Ethernet'). None = default.
        bpf_filter: Optional BPF filter expression (e.g. 'tcp port 80').
        on_packet: Optional callback invoked for each packet as it is captured.

    Returns:
        List of PacketData in capture order. Empty list on import or runtime errors.
    """
    packets: list[PacketData] = []

    def _process(pkt: Any) -> None:
        try:
            data = extract_packet_data(pkt)
            packets.append(data)
            if on_packet is not None:
                on_packet(data)
        except Exception:
            # Skip malformed packets; do not abort the capture
            pass

    try:
        from scapy.all import sniff

        sniff(
            iface=interface,
            count=count,
            timeout=timeout_seconds,
            filter=bpf_filter,
            prn=_process,
            store=False,
        )
    except ImportError:
        # Scapy not installed (e.g. in tests or minimal env)
        pass
    except Exception:
        # Interface or permission errors: return what we have so far
        pass

    return packets


def capture_packets_as_json(
    count: int = 100,
    timeout_seconds: Optional[int] = None,
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
) -> str:
    """
    Capture packets and return the result as a single JSON string.

    The output is a JSON array of objects with keys: timestamp, length,
    protocol, src_ip, dst_ip, src_port, dst_port, summary.
    """
    packets = capture_packets(
        count=count,
        timeout_seconds=timeout_seconds,
        interface=interface,
        bpf_filter=bpf_filter,
    )
    payload = [p.to_dict() for p in packets]
    return json.dumps(payload, default=str)

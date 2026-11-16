"""
FastAPI server for the AI Packet Analyzer.

Provides REST endpoints for capture control and packet listing,
and WebSocket for streaming packets to the frontend.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from queue import Empty, Queue
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.ai.analyzer import PacketAnalyzer
from backend.ai.llm_client import is_llm_available
from backend.capture.packet_capture import PacketData, capture_packets
from backend.processing.packet_parser import ProcessedPacket, parse_packet

logger = logging.getLogger("ai_packet_analyzer.api")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


# -----------------------------------------------------------------------------
# Request/response models
# -----------------------------------------------------------------------------

class CaptureStartRequest(BaseModel):
    """Optional parameters for starting a capture."""

    interface: Optional[str] = Field(None, description="Network interface")
    packet_count_per_chunk: int = Field(50, ge=1, le=500)
    timeout_seconds_per_chunk: int = Field(2, ge=1, le=30)
    bpf_filter: Optional[str] = Field(None, description="BPF filter")


class CaptureStatusResponse(BaseModel):
    """Status of the capture subsystem."""

    capturing: bool
    packet_count: int


class PacketActionRequest(BaseModel):
    packet_id: int = Field(..., ge=1)


class PacketChatRequest(BaseModel):
    packet_id: int = Field(..., ge=1)
    message: str = Field(..., min_length=1, max_length=4000)
    history: list[dict[str, str]] = Field(default_factory=list, max_length=50)


# -----------------------------------------------------------------------------
# Shared state
# -----------------------------------------------------------------------------

_processed_packets: list[ProcessedPacket] = []
_packets_lock = threading.Lock()

_analyzer = PacketAnalyzer()
_recent_ai_findings: deque[dict[str, Any]] = deque(maxlen=400)
_alerts: deque[dict[str, Any]] = deque(maxlen=250)

_capture_lock = threading.Lock()
_capture_thread: Optional[threading.Thread] = None
_capture_stop_event: Optional[threading.Event] = None
_capture_session_id: int = 0
_capture_chunk_timeout: int = 2

_stream_queue: Queue = Queue()
_ws_connections: set[WebSocket] = set()
_ws_lock = threading.Lock()

_MAX_BODY_BYTES = 128 * 1024
_RATE_LIMIT_WINDOW_SEC = 10
_RATE_LIMIT_MAX_REQUESTS = 80
_rate_limit_state: dict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = threading.Lock()


# -----------------------------------------------------------------------------
# Packet capture loop
# -----------------------------------------------------------------------------

def _is_capture_running_unlocked() -> bool:
    return _capture_thread is not None and _capture_thread.is_alive()


def _clear_queue(q: Queue) -> None:
    while True:
        try:
            q.get_nowait()
        except Empty:
            break
        except Exception:
            break


def _sanitize_bpf_filter(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    if len(value) > 256:
        raise HTTPException(status_code=400, detail="bpf_filter is too long")
    if any(ch in value for ch in ["\n", "\r", ";", "`", "|"]):
        raise HTTPException(status_code=400, detail="bpf_filter contains unsupported characters")
    return value


def _find_packet_by_id(packet_id: int) -> ProcessedPacket | None:
    with _packets_lock:
        for packet in _processed_packets:
            if packet.packet_id == packet_id:
                return packet
    return None


def _capture_loop(
    *,
    session_id: int,
    stop_event: threading.Event,
    interface: Optional[str],
    chunk_count: int,
    chunk_timeout: int,
    bpf_filter: Optional[str],
) -> None:
    """
    Capture packets in small chunks so the stop event can interrupt quickly.
    """

    global _capture_thread

    logger.info(
        "capture_loop_started session_id=%s interface=%s chunk_count=%s chunk_timeout=%s",
        session_id,
        interface,
        chunk_count,
        chunk_timeout,
    )

    try:
        while not stop_event.is_set():

            def on_packet(packet_data: PacketData):
                if stop_event.is_set():
                    return

                with _capture_lock:
                    if session_id != _capture_session_id:
                        return

                with _packets_lock:
                    packet_id = len(_processed_packets) + 1
                    processed = parse_packet(packet_data, packet_id)
                    ai_result = _analyzer.analyze_packet(processed.to_dict())
                    processed.ai_analysis = ai_result
                    _processed_packets.append(processed)

                    if ai_result.get("threat_level") in {"medium", "high"}:
                        _recent_ai_findings.append(
                            {
                                "packet_id": processed.packet_id,
                                "source_ip": processed.source_ip,
                                "destination_ip": processed.destination_ip,
                                "protocol": processed.protocol,
                                "analysis": ai_result,
                                "timestamp": processed.timestamp,
                            }
                        )

                    if ai_result.get("threat_level") == "high":
                        _alerts.appendleft(
                            {
                                "title": "High-risk packet detected",
                                "severity": "HIGH",
                                "packet_id": processed.packet_id,
                                "source_ip": processed.source_ip,
                                "risk_level": ai_result.get("risk_level", "HIGH"),
                                "score": ai_result.get("score", 0),
                                "reason": ai_result.get("reason", "High-risk traffic detected"),
                                "ai_explanation": ai_result.get(
                                    "explanation", "High-risk traffic detected"
                                ),
                                "suggested_action": ai_result.get(
                                    "recommended_action",
                                    ai_result.get("recommendation", "Investigate this source host"),
                                ),
                                "timestamp": processed.timestamp,
                            }
                        )

                try:
                    _stream_queue.put_nowait(processed.to_dict())
                except Exception:
                    pass

            capture_packets(
                count=chunk_count,
                timeout_seconds=chunk_timeout,
                interface=interface,
                bpf_filter=bpf_filter,
                on_packet=on_packet,
            )

    except Exception as exc:
        logger.exception("capture_loop_crashed session_id=%s error=%s", session_id, exc)
    finally:
        with _capture_lock:
            if _capture_thread is not None and threading.current_thread() is _capture_thread:
                _capture_thread = None
        logger.info("capture_loop_stopped session_id=%s", session_id)


# -----------------------------------------------------------------------------
# WebSocket broadcast worker
# -----------------------------------------------------------------------------

async def _broadcast_worker():

    while True:

        try:
            packet_dict = await asyncio.to_thread(_stream_queue.get, timeout=0.5)

        except Empty:
            await asyncio.sleep(0.05)
            continue

        except Exception:
            await asyncio.sleep(0.05)
            continue

        with _ws_lock:
            connections = list(_ws_connections)

        for ws in connections:
            try:
                await ws.send_json(packet_dict)
            except Exception:
                pass


# -----------------------------------------------------------------------------
# FastAPI lifespan
# -----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    broadcast_task = asyncio.create_task(_broadcast_worker())

    yield

    with _capture_lock:
        thread = _capture_thread
        stop_event = _capture_stop_event

    if stop_event is not None:
        stop_event.set()

    if thread and thread.is_alive():
        thread.join(timeout=max(5, _capture_chunk_timeout + 3))

    broadcast_task.cancel()

    try:
        await broadcast_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="AI Packet Analyzer API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except ValueError:
            pass
    return await call_next(request)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    now = time.time()
    client_ip = request.client.host if request.client else "unknown"

    with _rate_limit_lock:
        bucket = _rate_limit_state[client_ip]
        while bucket and bucket[0] < now - _RATE_LIMIT_WINDOW_SEC:
            bucket.popleft()

        if len(bucket) >= _RATE_LIMIT_MAX_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please retry shortly."},
            )

        bucket.append(now)

    return await call_next(request)


@app.middleware("http")
async def request_log_middleware(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000
    logger.info(
        "http_request method=%s path=%s status=%s duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled_exception path=%s error=%s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# -----------------------------------------------------------------------------
# REST endpoints
# -----------------------------------------------------------------------------

@app.get("/capture/status")
async def capture_status() -> CaptureStatusResponse:
    with _capture_lock:
        capturing = _is_capture_running_unlocked()

    with _packets_lock:
        count = len(_processed_packets)

    return CaptureStatusResponse(capturing=capturing, packet_count=count)


@app.post("/capture/start")
async def capture_start(body: Optional[CaptureStartRequest] = None) -> CaptureStatusResponse:

    global _capture_thread, _capture_stop_event, _capture_session_id, _capture_chunk_timeout

    req = body or CaptureStartRequest()
    safe_filter = _sanitize_bpf_filter(req.bpf_filter)

    with _capture_lock:
        if _is_capture_running_unlocked():
            with _packets_lock:
                count = len(_processed_packets)
            return CaptureStatusResponse(capturing=True, packet_count=count)

        _capture_session_id += 1
        session_id = _capture_session_id
        stop_event = threading.Event()
        _capture_stop_event = stop_event
        _capture_chunk_timeout = req.timeout_seconds_per_chunk

        thread = threading.Thread(
            target=_capture_loop,
            kwargs={
                "session_id": session_id,
                "stop_event": stop_event,
                "interface": req.interface,
                "chunk_count": req.packet_count_per_chunk,
                "chunk_timeout": req.timeout_seconds_per_chunk,
                "bpf_filter": safe_filter,
            },
            daemon=True,
            name=f"capture-session-{session_id}",
        )
        _capture_thread = thread

    with _packets_lock:
        _processed_packets.clear()
        _recent_ai_findings.clear()
        _alerts.clear()
        _clear_queue(_stream_queue)
    _analyzer.reset()

    thread.start()

    logger.info("capture_started session_id=%s", session_id)

    return CaptureStatusResponse(capturing=True, packet_count=0)


@app.post("/capture/stop")
async def capture_stop() -> CaptureStatusResponse:

    global _capture_thread

    with _capture_lock:
        thread = _capture_thread
        stop_event = _capture_stop_event
        timeout = max(5, _capture_chunk_timeout + 3)

    if stop_event is not None:
        stop_event.set()

    if thread and thread.is_alive():
        thread.join(timeout=timeout)

    still_running = bool(thread and thread.is_alive())

    if not still_running:
        with _capture_lock:
            if _capture_thread is thread:
                _capture_thread = None

    with _packets_lock:
        count = len(_processed_packets)

    logger.info("capture_stopped still_running=%s packet_count=%s", still_running, count)

    return CaptureStatusResponse(
        capturing=still_running,
        packet_count=count,
    )


@app.get("/packets")
async def get_packets() -> dict[str, Any]:

    with _packets_lock:
        packets = list(_processed_packets)

    payload = [p.to_dict() for p in packets]

    return {
        "packets": payload,
        "count": len(payload),
    }


@app.get("/packets/{packet_id}")
async def get_packet(packet_id: int) -> dict[str, Any]:
    packet = _find_packet_by_id(packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return {"packet": packet.to_dict()}


@app.get("/ai-analysis")
async def get_ai_analysis(limit: int = 50) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 200))
    with _packets_lock:
        findings = list(_recent_ai_findings)[:safe_limit]

    top_risky_ips: dict[str, int] = defaultdict(int)
    for item in findings:
        src = item.get("source_ip") or "unknown"
        score = int(item.get("analysis", {}).get("score", 0))
        top_risky_ips[src] += score

    ranked_ips = sorted(top_risky_ips.items(), key=lambda kv: kv[1], reverse=True)
    return {
        "findings": findings,
        "top_risky_ips": [{"ip": ip, "score": score} for ip, score in ranked_ips[:10]],
    }


@app.get("/alerts")
async def get_alerts(limit: int = 50) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 200))
    with _packets_lock:
        alerts = list(_alerts)[:safe_limit]

    return {
        "alerts": alerts,
        "count": len(alerts),
    }


@app.get("/ai/status")
async def ai_status() -> dict[str, Any]:
    return {
        "llm_enabled": is_llm_available(),
        "engine": "openai" if is_llm_available() else "local",
    }


@app.post("/ai/analyze")
async def analyze_packet_action(body: PacketActionRequest) -> dict[str, Any]:
    packet = _find_packet_by_id(body.packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")

    payload = packet.to_dict()
    analysis = _analyzer.analyze_packet(payload)
    packet.ai_analysis = analysis

    if analysis.get("threat_level") in {"medium", "high"}:
        _recent_ai_findings.appendleft(
            {
                "packet_id": packet.packet_id,
                "source_ip": packet.source_ip,
                "destination_ip": packet.destination_ip,
                "protocol": packet.protocol,
                "analysis": analysis,
                "timestamp": packet.timestamp,
            }
        )

    if analysis.get("threat_level") == "high":
        _alerts.appendleft(
            {
                "title": "Manual AI analysis flagged packet as high risk",
                "severity": "HIGH",
                "packet_id": packet.packet_id,
                "source_ip": packet.source_ip,
                "risk_level": analysis.get("risk_level", "HIGH"),
                "score": analysis.get("score", 0),
                "reason": analysis.get("reason", "High-risk traffic detected"),
                "ai_explanation": analysis.get("explanation", "High-risk traffic detected"),
                "suggested_action": analysis.get(
                    "recommended_action",
                    analysis.get("recommendation", "Investigate this source host"),
                ),
                "timestamp": packet.timestamp,
            }
        )

    return {"packet_id": packet.packet_id, "analysis": analysis}


@app.post("/ai/chat")
async def chat_about_packet(body: PacketChatRequest) -> dict[str, Any]:
    packet = _find_packet_by_id(body.packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")

    analysis = packet.ai_analysis or _analyzer.analyze_packet(packet.to_dict())
    packet.ai_analysis = analysis

    chat_result = await asyncio.to_thread(
        _analyzer.answer_packet_question,
        packet.to_dict(),
        analysis,
        body.message,
        body.history,
    )

    return {
        "packet_id": packet.packet_id,
        "analysis": analysis,
        "response": chat_result,
    }


# -----------------------------------------------------------------------------
# WebSocket endpoint
# -----------------------------------------------------------------------------

@app.websocket("/ws/packets")
async def websocket_packets(websocket: WebSocket):

    await websocket.accept()

    with _ws_lock:
        _ws_connections.add(websocket)

    try:
        while True:
            data = await websocket.receive_text()

            if data.strip().lower() == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        pass

    finally:
        with _ws_lock:
            _ws_connections.discard(websocket)
# AI Packet Analyzer

AI-powered interactive network intelligence platform built with FastAPI and React.

## Features

- Live packet capture and streaming over WebSockets
- Start/Stop capture lifecycle with backend state sync
- Interactive packet table:
  - Left-click: open packet intelligence side panel
  - Right-click context menu: view details, send to AI analysis, open AI chat
- Explainable AI risk analysis per packet:
  - `risk_score` (0-1)
  - `risk_level` (LOW/MEDIUM/HIGH)
  - `reasons`
  - `explanation`
  - `recommended_action`
- Per-packet AI chat sessions with context memory
- Optional OpenAI integration for natural-language chat (`OPENAI_API_KEY`)
- Alerts feed for high-risk detections
- Pattern detection:
  - Port scanning
  - SYN flood indicators
  - Sensitive port abuse
  - Traffic spikes
  - Oversized packet anomalies

## Project Structure

```text
backend/
  api/server.py                # FastAPI routes, capture lifecycle, AI/alerts APIs
  capture/packet_capture.py    # Scapy capture and packet extraction
  processing/packet_parser.py  # Packet normalization for UI
  ai/analyzer.py               # Stateful AI scoring + packet-aware chat response
frontend/packet-analyzer-ui/
  src/pages/AnalyzerPage.jsx
  src/components/PacketTable.jsx
  src/components/PacketIntelligencePanel.jsx
  src/components/dashboard/*
  src/services/api.js
```

## API Endpoints

- `POST /capture/start`
- `POST /capture/stop`
- `GET /capture/status`
- `GET /packets`
- `GET /packets/{packet_id}`
- `GET /ai-analysis`
- `GET /alerts`
- `POST /ai/analyze` (`{ "packet_id": number }`)
- `POST /ai/chat`
  - body:
    ```json
    {
      "packet_id": 12,
      "message": "Is this part of an attack?",
      "history": [{"role":"user","text":"..."}]
    }
    ```

## Run Locally

### Backend

```bash
python backend/run_server.py
```

Backend runs on `http://localhost:8000`.

### Frontend

```bash
cd frontend/packet-analyzer-ui
npm install
npm start
```

Frontend runs on `http://localhost:3000`.

### Optional: OpenAI chat (ChatGPT-style answers)

Set environment variables before starting the backend:

```bash
set OPENAI_API_KEY=sk-your-key-here
set OPENAI_MODEL=gpt-4o-mini
python backend/run_server.py
```

Without an API key, chat uses a **local packet-aware Q&A engine** that answers protocol, IP, port, layer, and risk questions from actual packet fields.

## Usage

1. Open **Live Capture**
2. Click **Start Capture**
3. Click any packet row:
   - Packet Details tab shows full packet fields
   - AI Insights tab shows explainable risk output
   - AI Chat tab supports packet-specific Q&A with memory
4. Right-click a packet row for context actions
5. Open **Alerts** for high-risk events and suggested actions

## GitHub Setup

After verifying locally, run:

```bash
git init
git add .
git commit -m "AI Packet Analyzer"
git branch -M main
git remote add origin https://github.com/<username>/<repo>.git
git push -u origin main
```

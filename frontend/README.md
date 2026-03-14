# CyberSentinel — Assessment Day Quick Start

## 1. Create folders (30 seconds)
```bash
mkdir projectname && cd projectname
mkdir backend frontend
```

## 2. Backend setup (2 minutes)
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows
pip install fastapi uvicorn pydantic-ai logfire[fastapi] python-dotenv mcp
```

## 3. Create .env
```
MODEL_NAME=Qwen2.5-7B-Instruct
MODEL_BASE_URL=http://localhost:8000/v1
MODEL_API_KEY=not-needed
```

## 4. Files to create — in this order
1. `models.py`     — Pydantic schemas
2. `tools.py`      — tool functions
3. `mcp_server.py` — MCP server
4. `agent.py`      — Pydantic AI agent
5. `main.py`       — FastAPI server

## 5. Run backend
```bash
uvicorn main:app --reload --port 8000
```

## 6. Frontend setup (2 minutes)
```bash
cd ../frontend
npm create vite@latest . -- --template react
npm install
npm run dev
```

## 7. Verify everything works
- http://localhost:8000/docs -> backend FastAPI dashboard
- http://localhost:8000/health → {"status":"ok"}
- http://localhost:5173 → React page loads
- Send a message → ThreatReport returned

## 8. Key endpoints
- POST /chat
- GET /health
- GET /metrics
- GET /pipeline/status
- GET /pipeline/versions

## 9. vLLM swap — just change .env
```
MODEL_NAME=whatever-they-say
MODEL_BASE_URL=http://their-url/v1
MODEL_API_KEY=not-needed
```
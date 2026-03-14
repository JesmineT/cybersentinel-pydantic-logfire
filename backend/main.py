from dotenv import load_dotenv
load_dotenv()

import logfire
logfire.configure(service_name="cybersentinel")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from uuid import uuid4

from models import ChatRequest
from agent import run_triage

app = FastAPI()

logfire.instrument_fastapi(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/chat")
async def chat(request: ChatRequest):
    try:
        session_id = request.session_id or str(uuid4())
        result = await run_triage(request.message, session_id)
        return {
            "session_id": result["session_id"],
            "report": result["output"].model_dump(mode="json"),  # AgentResponse
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# server/app.py
"""Sanitization microservice — wraps safety_dataclaw sanitization for server-side use."""

import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Add parent dir to path so we can import safety_dataclaw
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety_dataclaw.secrets import scan_text, redact_text, redact_custom_strings
from safety_dataclaw.anonymizer import Anonymizer

app = FastAPI(title="Safety DataClaw Sanitization Service", docs_url=None, redoc_url=None)

MAX_CONTENT_LENGTH = 10_000_000  # 10 MB


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal sanitization error"},
    )


class Finding(BaseModel):
    type: str
    start: int
    end: int


class SanitizeRequest(BaseModel):
    content: str = Field(..., max_length=MAX_CONTENT_LENGTH)
    redact_strings: list[str] | None = None
    anonymize_usernames: list[str] | None = None


class SanitizeResponse(BaseModel):
    sanitized: str
    findings: list[Finding]
    redaction_count: int


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(req: SanitizeRequest):
    text = req.content
    total_redactions = 0

    # Step 1: Regex-based secret detection and redaction
    # Note: scan_text is called twice (once here, once inside redact_text) because
    # redact_text doesn't expose its internal findings. The cost is negligible (regex-based).
    raw_findings = scan_text(text)
    findings = [Finding(type=f["type"], start=f["start"], end=f["end"]) for f in raw_findings]
    text, count = redact_text(text)
    total_redactions += count

    # Step 2: Custom string redaction
    if req.redact_strings:
        text, count = redact_custom_strings(text, req.redact_strings)
        total_redactions += count

    # Step 3: Username/path anonymization
    if req.anonymize_usernames:
        anon = Anonymizer(extra_usernames=req.anonymize_usernames)
        text = anon.text(text)

    return SanitizeResponse(
        sanitized=text,
        findings=findings,
        redaction_count=total_redactions,
    )


@app.get("/health")
def health():
    return {"status": "ok"}

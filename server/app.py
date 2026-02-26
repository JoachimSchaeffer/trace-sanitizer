# server/app.py
"""Sanitization microservice — wraps safety_dataclaw sanitization for server-side use."""

import sys
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

# Add parent dir to path so we can import safety_dataclaw
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety_dataclaw.secrets import redact_text, scan_text, redact_custom_strings
from safety_dataclaw.anonymizer import Anonymizer

app = FastAPI(title="Safety DataClaw Sanitization Service", docs_url=None, redoc_url=None)


class SanitizeRequest(BaseModel):
    content: str
    redact_strings: list[str] | None = None
    anonymize_usernames: list[str] | None = None


class SanitizeResponse(BaseModel):
    sanitized: str
    findings: list[dict]
    redaction_count: int


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(req: SanitizeRequest):
    text = req.content
    total_redactions = 0

    # Step 1: Regex-based secret detection and redaction
    findings = scan_text(text)
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

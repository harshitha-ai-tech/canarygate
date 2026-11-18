
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.gateway import process_prompt


app = FastAPI(
    title="Canary Gate",
    description=(
        "A two-way AI security gateway for PII redaction, "
        "prompt injection detection, output scanning, "
        "and canary leak detection."
    ),
    version="1.0.0",
)


class ChatRequest(BaseModel):
    prompt: str = Field(
        min_length=1,
        max_length=10000,
        description="The user's prompt to process securely.",
        examples=["Explain artificial intelligence in simple words."],
    )


@app.get("/health", tags=["System"])
def health_check():
    """Check whether the Canary Gate API is running."""

    return {
        "status": "ok",
        "service": "Canary Gate",
    }


@app.post("/chat", tags=["Security Gateway"])
def chat(request: ChatRequest) -> dict[str, Any]:
    """Submit a prompt to the two-way AI security gateway."""

    if not request.prompt.strip():
        raise HTTPException(
            status_code=400,
            detail="Prompt cannot be empty or contain only spaces.",
        )

    try:
        result = process_prompt(request.prompt)
        return result

    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid prompt.",
        )

    except RuntimeError:
        raise HTTPException(
            status_code=502,
            detail="AI service is unavailable or could not process the request.",
        )

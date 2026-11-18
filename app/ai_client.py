
import os

from dotenv import load_dotenv
from google import genai
from google.genai.errors import APIError


load_dotenv()


def generate_ai_response(prompt: str) -> str:
    """Send a security-checked prompt to Gemini."""

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    if not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is missing. Add it to your .env file."
        )

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model=model,
            contents=prompt,
        )

        if not response.text:
            raise RuntimeError("Gemini returned an empty response.")

        return response.text

    except APIError as exc:
        # Avoid exposing API details or credentials to the API caller.
        raise RuntimeError(
            "Gemini request failed. Check the model, API key, "
            "quota, and API availability."
        ) from exc

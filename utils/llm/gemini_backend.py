"""Google Gemini backend for LLM-based alert enrichment."""

import json
import logging
import os
from datetime import datetime, timezone

import google.genai as genai
import google.genai.types as genai_types

from utils.llm.base import LLMBackend
from utils.llm.prompt_builder import build_prompt

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gemini-2.5-flash"
_REQUIRED_FIELDS = {"summary", "security_context", "investigation_steps"}


class GeminiBackend(LLMBackend):
    """
    LLM backend powered by the Google Gemini API.

    Reads GEMINI_API_KEY (required) and GEMINI_MODEL (optional,
    default: gemini-2.5-flash) from environment variables.
    """

    def __init__(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GEMINI_API_KEY environment variable is not set. "
                "Export it or add it to .env before running with --llm."
            )

        self._model_id: str = os.environ.get("GEMINI_MODEL", _DEFAULT_MODEL)
        self._client = genai.Client(api_key=api_key)
        logger.debug("GeminiBackend initialised with model: %s", self._model_id)

    @property
    def model_name(self) -> str:
        """Return the Gemini model identifier in use."""
        return self._model_id

    def enrich(self, alert: dict) -> dict:
        """
        Call the Gemini API and return structured enrichment data.

        Uses ``system_instruction`` and ``response_mime_type=application/json``
        to guarantee a parseable JSON response.
        """
        prompts = build_prompt(alert)

        config = genai_types.GenerateContentConfig(
            system_instruction=prompts["system"],
            response_mime_type="application/json",
            temperature=0.2,
        )

        response = self._client.models.generate_content(
            model=self._model_id,
            contents=prompts["user"],
            config=config,
        )

        raw_content = response.text or ""
        enrichment = self._parse_and_validate(raw_content)
        enrichment["analysis_model"] = self._model_id
        enrichment["analysis_timestamp"] = datetime.now(timezone.utc).isoformat()

        return enrichment

    def _parse_and_validate(self, raw: str) -> dict:
        """Parse and validate the model's JSON response against the required schema."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Gemini returned non-JSON content. Raw response: {raw!r}"
            ) from exc

        missing = _REQUIRED_FIELDS - data.keys()
        if missing:
            raise ValueError(
                f"Gemini response is missing required fields: {missing}. "
                f"Raw response: {raw!r}"
            )

        if not isinstance(data.get("investigation_steps"), list):
            raise ValueError(
                "Gemini response field `investigation_steps` must be a list. "
                f"Got: {type(data.get('investigation_steps')).__name__}"
            )

        return {
            "summary": str(data["summary"]),
            "security_context": str(data["security_context"]),
            "investigation_steps": [str(s) for s in data["investigation_steps"]],
        }

"""
Google Gemini backend implementation for LLM-based alert enrichment.

Reads GEMINI_API_KEY and GEMINI_MODEL from environment variables.
All Gemini-specific logic is fully contained within this file.
"""

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

    Configuration (via environment variables):
        GEMINI_API_KEY  — Required. Your Google AI Studio or Vertex API key.
        GEMINI_MODEL    — Optional. Model identifier (default: gemini-2.5-flash).

    The client is initialised once at construction time. If the API key is
    absent, an EnvironmentError is raised immediately so the caller can
    surface a clear message before attempting any enrichment.
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
        Call the Google Gemini API and return enrichment data.

        The system prompt is passed via GenerateContentConfig.system_instruction.
        The user prompt is sent as the primary content. JSON output mode is
        requested explicitly to guarantee parseable responses.

        Args:
            alert: A fully-formed alert dictionary.

        Returns:
            A dict conforming to the `llm_enrichment` schema.

        Raises:
            EnvironmentError: If the API key is missing (raised at init).
            ValueError: If the model returns a response that cannot be parsed
                        or is missing required fields.
            Exception: Any google.genai API error is allowed to propagate so
                       the enricher orchestration layer can log and continue.
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
        """
        Parse the model's JSON response and validate required fields.

        Args:
            raw: The raw string content returned by the model.

        Returns:
            A validated enrichment dict (without meta fields yet).

        Raises:
            ValueError: If the content is not valid JSON, is missing required
                        fields, or has an incorrect field type.
        """
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

"""
OpenAI backend implementation for LLM-based alert enrichment.

Reads OPENAI_API_KEY and LLM_MODEL from environment variables.
All OpenAI-specific logic is fully contained within this file.
"""

import json
import logging
import os
from datetime import datetime, timezone

from openai import OpenAI, AuthenticationError, APIConnectionError, APIStatusError

from utils.llm.base import LLMBackend
from utils.llm.prompt_builder import build_prompt

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gpt-4.1-mini"
_REQUIRED_FIELDS = {"summary", "security_context", "investigation_steps"}


class OpenAIBackend(LLMBackend):
    """
    LLM backend powered by the OpenAI Chat Completions API.

    Configuration (via environment variables):
        OPENAI_API_KEY  — Required. Your OpenAI API key.
        LLM_MODEL       — Optional. Model identifier (default: gpt-4.1-mini).

    The client is initialised once at construction time. If the API key is
    absent, an EnvironmentError is raised immediately so the caller can
    surface a clear message before attempting any enrichment.
    """

    def __init__(self) -> None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY environment variable is not set. "
                "Export it before running with --llm."
            )

        self._model: str = os.environ.get("LLM_MODEL", _DEFAULT_MODEL)
        self._client: OpenAI = OpenAI(api_key=api_key)
        logger.debug("OpenAIBackend initialised with model: %s", self._model)

    @property
    def model_name(self) -> str:
        """Return the OpenAI model identifier in use."""
        return self._model

    def enrich(self, alert: dict) -> dict:
        """
        Call the OpenAI Chat Completions API and return enrichment data.

        Args:
            alert: A fully-formed alert dictionary.

        Returns:
            A dict conforming to the `llm_enrichment` schema.

        Raises:
            AuthenticationError: If the API key is invalid or revoked.
            APIConnectionError: If the OpenAI API cannot be reached.
            APIStatusError: For HTTP 4xx/5xx responses from the API.
            ValueError: If the model returns a response that cannot be parsed
                        or is missing required fields.
        """
        prompts = build_prompt(alert)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": prompts["system"]},
                    {"role": "user", "content": prompts["user"]},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
            )
        except AuthenticationError as exc:
            raise AuthenticationError(
                message=(
                    "OpenAI authentication failed. "
                    "Verify that OPENAI_API_KEY is correct and active."
                ),
                response=exc.response,
                body=exc.body,
            ) from exc
        except APIConnectionError as exc:
            raise APIConnectionError(
                message="Unable to reach the OpenAI API. Check your network connection.",
                request=exc.request,
            ) from exc
        except APIStatusError as exc:
            raise APIStatusError(
                message=f"OpenAI API returned an error: HTTP {exc.status_code}",
                response=exc.response,
                body=exc.body,
            ) from exc

        raw_content = response.choices[0].message.content or ""
        enrichment = self._parse_and_validate(raw_content)
        enrichment["analysis_model"] = self._model
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
            ValueError: If the content is not valid JSON or is missing
                        required fields.
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"LLM returned non-JSON content. Raw response: {raw!r}"
            ) from exc

        missing = _REQUIRED_FIELDS - data.keys()
        if missing:
            raise ValueError(
                f"LLM response is missing required fields: {missing}. "
                f"Raw response: {raw!r}"
            )

        if not isinstance(data.get("investigation_steps"), list):
            raise ValueError(
                "LLM response field `investigation_steps` must be a list. "
                f"Got: {type(data.get('investigation_steps')).__name__}"
            )

        return {
            "summary": str(data["summary"]),
            "security_context": str(data["security_context"]),
            "investigation_steps": [str(s) for s in data["investigation_steps"]],
        }

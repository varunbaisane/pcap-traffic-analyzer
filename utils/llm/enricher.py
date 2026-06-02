"""
Orchestration layer for LLM-based alert enrichment.

This module is responsible for attaching enrichment data to alerts.
It accepts any LLMBackend implementation via dependency injection and
degrades gracefully if enrichment fails, ensuring alert generation
always continues uninterrupted.
"""

from copy import deepcopy
import logging
from typing import Sequence

from utils.llm.base import LLMBackend

logger = logging.getLogger(__name__)


def enrich_alert(alert: dict, backend: LLMBackend) -> dict:
    """
    Attach LLM enrichment to a single alert.

    Always attaches an `llm_enrichment` key regardless of outcome:
    - On success: the enrichment dict with an added ``status: "success"`` field.
    - On failure: ``{"status": "failed", "error": "<short message>"}``.

    Detection data is never modified. Alert generation is never interrupted
    by enrichment failures.

    Args:
        alert: A fully-formed alert dictionary.
        backend: A concrete LLMBackend instance to use for enrichment.

    Returns:
        The alert dict with an `llm_enrichment` key always present.
    """
    alert_id = alert.get("alert_id", "unknown")
    alert_type = alert.get("alert_type", "unknown")

    try:
        logger.debug("Requesting LLM enrichment for alert %s (%s)", alert_id, alert_type)
        enrichment = backend.enrich(deepcopy(alert))
        enrichment["status"] = "success"
        alert["llm_enrichment"] = enrichment
        logger.debug("LLM enrichment attached to alert %s", alert_id)
    except Exception as exc:
        lines = str(exc).splitlines()
        error_message = lines[0][:120] if lines else "Unknown error"
        logger.warning(
            "LLM enrichment failed for alert %s (%s): %s",
            alert_id,
            alert_type,
            error_message,
        )
        alert["llm_enrichment"] = {
            "status": "failed",
            "error": error_message,
        }

    return alert


def enrich_alerts(alerts: Sequence[dict], backend: LLMBackend) -> list[dict]:
    """
    Attach LLM enrichment to each alert in a collection.

    Processes alerts sequentially. Individual failures do not stop
    processing of remaining alerts. Every alert will contain an
    `llm_enrichment` key on return.

    Args:
        alerts: A sequence of fully-formed alert dictionaries.
        backend: A concrete LLMBackend instance to use for enrichment.

    Returns:
        A list of alert dicts, each with `llm_enrichment` always present.
    """
    enriched: list[dict] = []
    for alert in alerts:
        enriched.append(enrich_alert(alert, backend))
    return enriched

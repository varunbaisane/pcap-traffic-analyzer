"""Orchestration layer for LLM-based alert enrichment."""

from copy import deepcopy
import logging
from typing import Sequence

from utils.llm.base import LLMBackend

logger = logging.getLogger(__name__)


def enrich_alert(alert: dict, backend: LLMBackend) -> dict:
    """
    Enrich a single alert, attaching ``llm_enrichment`` regardless of outcome.

    Detection data is never modified. Failures attach ``{status: failed}``
    rather than interrupting the pipeline.
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
    """Enrich each alert in a collection, processing sequentially."""
    enriched: list[dict] = []
    for alert in alerts:
        enriched.append(enrich_alert(alert, backend))
    return enriched

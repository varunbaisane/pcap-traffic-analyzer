"""Abstract backend interface for LLM-based alert enrichment."""

from abc import ABC, abstractmethod


class LLMBackend(ABC):
    """Pluggable base class for LLM enrichment backends."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model identifier string."""

    @abstractmethod
    def enrich(self, alert: dict) -> dict:
        """Enrich a single alert with LLM-generated security context."""

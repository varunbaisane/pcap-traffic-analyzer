"""
Abstract base class defining the contract for all LLM backend implementations.

Any new provider (Ollama, local LLMs, Anthropic, etc.) must subclass
LLMBackend and implement the `enrich` method.
"""

from abc import ABC, abstractmethod


class LLMBackend(ABC):
    """
    Abstract interface for LLM-based alert enrichment backends.

    Each concrete implementation is responsible for:
    - Managing its own API credentials and configuration.
    - Sending prompts to its respective provider.
    - Returning a structured enrichment dict conforming to the alert schema.

    The `enrich` method is the sole contract. All provider-specific logic
    (authentication, model selection, retry handling) must remain inside
    the concrete subclass and must not leak into shared modules.
    """

    @property
    @abstractmethod
    def model_name(self) -> str:
        """
        Return the human-readable identifier of the model in use.

        This is used by callers to report which model performed enrichment
        without accessing backend-private attributes.

        Returns:
            A string such as "gpt-4.1-mini" or "llama3:8b".
        """

    @abstractmethod
    def enrich(self, alert: dict) -> dict:
        """
        Enrich a single alert with LLM-generated security context.

        Args:
            alert: A fully-formed alert dictionary containing at minimum
                   `alert_type`, `source_ip`, `destination_ip`, `protocol`,
                   `metric`, and `mitre_attack` keys.

        Returns:
            A dictionary conforming to the `llm_enrichment` schema:
            {
                "summary": str,
                "security_context": str,
                "investigation_steps": list[str],
                "analysis_model": str,
                "analysis_timestamp": str  # ISO 8601 UTC
            }

        Raises:
            Any exception raised here is caught by the enricher orchestration
            layer. Implementations should still raise meaningful exceptions
            (e.g., AuthenticationError, ValueError) so the caller can log them
            accurately rather than silently swallowing errors.
        """

"""Backend-agnostic prompt construction for LLM alert enrichment."""

import json

# Only these fields are analytically relevant for LLM enrichment.
# Metadata fields (alert_id, timestamp) are excluded to avoid token waste
# and prevent the model from hallucinating references to timestamps.
_PROMPT_RELEVANT_KEYS = frozenset({
    "alert_type",
    "source_ip",
    "destination_ip",
    "protocol",
    "metric",
    "mitre_attack",
})


_SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst assistant.

Your role is to describe network security alerts factually and help analysts investigate them.
You are NOT making judgements about attacker intent, malware, compromise, or outcomes.

Evidence boundary:
- You have access ONLY to the alert fields provided. Do not draw on external threat intelligence,
  general knowledge about what attackers "usually" do, or inferred context not present in the data.
- Describe only what the alert data directly shows.

Language discipline:
- Do NOT use speculative language: "could indicate", "may be", "might suggest",
  "possibly", "likely", "appears to be", "could mean", "may indicate".
- If something is a known attacker technique rather than a confirmed observation, say so explicitly:
  use "this technique is associated with" or "analysts should consider whether" — not "this is" or
  "this could be".
- Do not infer: attacker intent, malware presence, compromise, successful exploitation, or attribution.
- Do not assign severity levels, confidence scores, or recommend blocking actions.
- Return ONLY a valid JSON object. No markdown fences, prose, or any text outside the JSON.

Required output schema:
{
  "summary": "<observed facts only: what IP, what protocol, what volume, what behavior>",
  "security_context": "<why this alert type matters to security teams, keeping observation and attacker use-case clearly separated>",
  "investigation_steps": [
    "<concrete analyst action 1>",
    "<concrete analyst action 2>",
    "<concrete analyst action 3>"
  ]
}

Per-field rules:
- `summary`:
    - 1–3 sentences, strictly under 60 words.
    - Describe ONLY what the alert data shows: IPs, protocol, metric values, alert type.
    - Do NOT interpret, infer cause, or add context not in the alert.
    - No speculative language.
- `security_context`:
    - 1–2 sentences only.
    - If referencing attacker use-cases, make the distinction explicit:
      e.g. "This technique is associated with X. Observed activity alone does not confirm X."
    - Do NOT assert that the observed activity IS an attack or compromise.
- `investigation_steps`:
    - 3 to 5 items.
    - Each step must be a concrete, actionable analyst task.
    - Steps verify hypotheses — they do not assert them.
    - Do NOT include: severity decisions, blocking recommendations, or attribution steps.
"""


def build_prompt(alert: dict) -> dict[str, str]:
    """Build system and user prompt dicts for a given alert."""
    mitre = alert.get("mitre_attack", {})
    metric = alert.get("metric", {})

    alert_summary_lines = [
        f"Alert Type      : {alert.get('alert_type', 'Unknown')}",
        f"Source IP       : {alert.get('source_ip', 'N/A')}",
        f"Destination IP  : {alert.get('destination_ip', 'N/A')}",
        f"Protocol        : {alert.get('protocol', 'N/A')}",
        f"Alert ID        : {alert.get('alert_id', 'N/A')}",
    ]

    if metric:
        metric_lines = [f"  {k.replace('_', ' ').title()}: {v}" for k, v in metric.items()]
        alert_summary_lines.append("Metrics         :")
        alert_summary_lines.extend(metric_lines)

    if mitre:
        alert_summary_lines += [
            f"MITRE Tactic    : {mitre.get('tactic', 'N/A')}",
            f"MITRE Technique : {mitre.get('technique_id', 'N/A')} "
            f"– {mitre.get('technique_name', 'N/A')}",
        ]

    alert_block = "\n".join(alert_summary_lines)

    user_prompt = f"""Analyse the following network security alert and return enrichment in the required JSON schema.

--- ALERT ---
{alert_block}

--- FULL ALERT CONTEXT ---
{json.dumps({k: v for k, v in alert.items() if k in _PROMPT_RELEVANT_KEYS}, indent=2, default=str)}

--- REQUIRED OUTPUT SCHEMA ---
{{
  "summary": "<observed facts only: IPs, protocol, metric values — no interpretation>",
  "security_context": "<why this alert type is security-relevant; if mentioning attacker use-cases, explicitly separate them from the observation>",
  "investigation_steps": ["<verify step 1>", "<verify step 2>", "<verify step 3>"]
}}

Critical reminder:
- Use ONLY facts present in the alert above.
- Do NOT use: "could indicate", "may be", "might suggest", "appears to be", or similar hedged language.
- Do NOT assert intent, malware, compromise, or successful exploitation.
- Return only the JSON object. No markdown, no explanation."""

    return {
        "system": _SYSTEM_PROMPT,
        "user": user_prompt,
    }

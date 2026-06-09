"""
ai/planner.py
AI-powered update planner and risk narrator.
Uses the Google Gemini API to generate prioritised update plans
and natural-language risk explanations.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Optional

import google.generativeai as genai

from app.core.config import get_settings
from app.core.models import Component, RiskLevel

logger = logging.getLogger(__name__)
settings = get_settings()

# Rate limiter: max 12 requests/min (free tier = 15, leave headroom)
_rate_lock = asyncio.Lock()
_last_call_time: float = 0.0
_MIN_CALL_INTERVAL = 5.0   # seconds between LLM calls


async def _rate_limited_generate(model, content, generation_config):
    """Enforce minimum interval between Gemini calls, then call in thread pool."""
    global _last_call_time
    async with _rate_lock:
        wait = _MIN_CALL_INTERVAL - (time.monotonic() - _last_call_time)
        if wait > 0:
            logger.debug("Rate limiter: sleeping %.1fs before next Gemini call", wait)
            await asyncio.sleep(wait)
        _last_call_time = time.monotonic()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: model.generate_content(content, generation_config=generation_config),
    )


def _parse_retry_delay(exc: Exception) -> float:
    """Extract retry_delay seconds from Gemini quota error, default 60s."""
    msg = str(exc)
    import re as _re
    m = _re.search(r"retry_delay\s*\{[^}]*seconds:\s*(\d+)", msg)
    return float(m.group(1)) if m else 60.0


# ─────────────────────────────────────────────
# System prompts
# ─────────────────────────────────────────────

SYSTEM_PROMPT_PLANNER = """You are an expert Android security engineer and dependency management specialist.

You receive a structured risk report for an Android project listing its risky dependencies.
Your task: generate a precise, actionable, prioritised update plan.

CRITICAL: Respond ONLY with valid JSON. No markdown fences, no preamble, no explanation outside the JSON.

Required format:
{
  "updates": [
    {
      "purl": "pkg:maven/group/artifact@version",
      "name": "artifact-name",
      "current_version": "x.y.z",
      "recommended_version": "a.b.c",
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "main_reason": "One sentence stating the primary risk driver",
      "breaking_risk": "LOW|MODERATE|HIGH",
      "migration_effort": "< 1h | 2-4h | 1 day | > 1 day",
      "action": "UPDATE|REPLACE|REMOVE|MONITOR",
      "replacement_suggestion": "alternative library if action is REPLACE, else null",
      "notes": "Specific migration tip or null"
    }
  ],
  "executive_summary": "3-5 sentences for non-technical management",
  "total_risk_reduction": "Estimated risk reduction percentage if all updates applied"
}

Rules:
- Sort by priority descending (CRITICAL first)
- For breaking_risk HIGH, always provide concrete migration notes
- action=REPLACE when the library is abandoned or has a clearly superior alternative
- action=REMOVE when the library adds risk with no production value (e.g. debug-only SDK in release)
- Be factual; cite CVE IDs in main_reason where relevant
"""

SYSTEM_PROMPT_NARRATOR = """You are a cybersecurity consultant writing an audit report.

For each component provided, produce two explanations:
1. TECHNICAL (2-3 sentences): CVE details, attack vector, exploitability, technical impact
2. MANAGEMENT (1-2 sentences): business risk, urgency justification, estimated cost if exploited

Rules:
- Cite CVE IDs by name (CVE-2021-44228 style)
- Be factual, no alarmism, no marketing language
- If no CVE exists, focus on licence risk or obsolescence risk
- Respond ONLY with valid JSON, no markdown

Format:
{
  "narratives": [
    {
      "purl": "...",
      "technical": "...",
      "management": "..."
    }
  ]
}
"""


# ─────────────────────────────────────────────
# Update Planner
# ─────────────────────────────────────────────

async def generate_update_plan(components: list[Component]) -> dict:
    """
    Generate a prioritised update plan for all components with score > 20.
    Falls back to a deterministic rule-based plan if LLM call fails.
    """
    risky = _select_risky_components(components)
    if not risky:
        return {"updates": [], "executive_summary": "No significant risks detected.", "total_risk_reduction": "0%"}

    context = _build_planner_context(risky)

    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name=settings.LLM_MODEL,
        system_instruction=SYSTEM_PROMPT_PLANNER,
    )

    for attempt in range(3):
        try:
            response = await _rate_limited_generate(
                model,
                context,
                genai.types.GenerationConfig(max_output_tokens=settings.LLM_MAX_TOKENS),
            )
            raw = response.text
            plan = _parse_json_response(raw)
            if plan and "updates" in plan:
                logger.info("Update plan generated by LLM (%d items)", len(plan["updates"]))
                return plan
            logger.warning("LLM attempt %d returned invalid JSON, retrying...", attempt + 1)
        except Exception as e:
            delay = _parse_retry_delay(e)
            logger.warning(
                "LLM call failed on attempt %d (rate limit or error) — waiting %.0fs: %s",
                attempt + 1, delay, e,
            )
            if attempt < 2:
                await asyncio.sleep(delay)

    logger.warning("All LLM attempts failed — using deterministic fallback plan")
    return _fallback_update_plan(risky)


def _select_risky_components(components: list[Component]) -> list[Component]:
    """Select and sort components that need attention."""
    risky = [c for c in components if c.scores.global_score > 20]
    risky.sort(key=lambda c: c.scores.global_score, reverse=True)
    return risky[: settings.MAX_COMPONENTS_FOR_LLM]


def _build_planner_context(components: list[Component]) -> str:
    lines = [
        "Dependency risk report for Android project.",
        f"Analysed {len(components)} risky components (score > 20/100).\n",
        "Format per line: name | current→latest | global_score | CVEs | licence | trackers | transitive_from",
    ]
    for c in components:
        cves = ", ".join(v.id for v in c.vulnerabilities[:3])
        if len(c.vulnerabilities) > 3:
            cves += f" (+{len(c.vulnerabilities) - 3} more)"
        lines.append(
            f"- {c.name} | {c.version}→{c.latest_version or '?'} | "
            f"score={c.scores.global_score} | CVE=[{cves or 'none'}] | "
            f"licence={c.license.spdx_id if c.license else 'UNKNOWN'} | "
            f"trackers={len(c.trackers)} | "
            f"transitive_from={c.direct_ancestor or 'direct'}"
        )
    return "\n".join(lines)


def _fallback_update_plan(components: list[Component]) -> dict:
    """
    Deterministic fallback: generate a basic plan without LLM.
    Used when the API is unavailable.
    """
    updates = []
    for c in components:
        if c.scores.global_score >= 75:
            priority = "CRITICAL"
        elif c.scores.global_score >= 50:
            priority = "HIGH"
        elif c.scores.global_score >= 20:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        top_cve = max(c.vulnerabilities, key=lambda v: v.cvss_v3 or 0, default=None)
        reason = (
            f"CVE {top_cve.id} (CVSS {top_cve.cvss_v3})"
            if top_cve
            else f"Score {c.scores.global_score}/100 — licence {c.license.spdx_id if c.license else 'unknown'}"
        )

        updates.append({
            "purl": c.purl,
            "name": c.artifact,
            "current_version": c.version,
            "recommended_version": c.latest_version or "latest",
            "priority": priority,
            "main_reason": reason,
            "breaking_risk": "MODERATE",
            "migration_effort": "2-4h",
            "action": "UPDATE",
            "replacement_suggestion": None,
            "notes": None,
        })

    return {
        "updates": updates,
        "executive_summary": (
            f"{len([u for u in updates if u['priority'] == 'CRITICAL'])} critical, "
            f"{len([u for u in updates if u['priority'] == 'HIGH'])} high-priority updates required. "
            "Review each item and apply updates in priority order."
        ),
        "total_risk_reduction": "~60%",
        "_fallback": True,
    }


# ─────────────────────────────────────────────
# Risk Narrator
# ─────────────────────────────────────────────

async def generate_risk_narratives(components: list[Component]) -> dict[str, dict]:
    """
    Generate technical + management narratives for top risky components.
    Returns a dict keyed by purl.
    """
    critical = [
        c for c in components
        if c.scores.risk_level in (RiskLevel.CRITICAL, RiskLevel.BLOCKING, RiskLevel.HIGH)
    ][:15]   # Limit to top 15 to stay within context

    if not critical:
        return {}

    context = _build_narrator_context(critical)
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name=settings.LLM_MODEL,
        system_instruction=SYSTEM_PROMPT_NARRATOR,
    )

    for attempt in range(3):
        try:
            response = await _rate_limited_generate(
                model,
                context,
                genai.types.GenerationConfig(max_output_tokens=2048),
            )
            raw = response.text
            result = _parse_json_response(raw)
            if result and "narratives" in result:
                return {n["purl"]: n for n in result["narratives"]}
            logger.warning("Narrator attempt %d returned invalid JSON, retrying...", attempt + 1)
        except Exception as e:
            delay = _parse_retry_delay(e)
            logger.warning(
                "Risk narrator failed on attempt %d — waiting %.0fs: %s",
                attempt + 1, delay, e,
            )
            if attempt < 2:
                await asyncio.sleep(delay)

    return {}


def _build_narrator_context(components: list[Component]) -> str:
    parts = []
    for c in components:
        vulns_text = "; ".join(
            f"{v.id} (CVSS {v.cvss_v3}, {'no fix' if not v.has_fix else 'fix available'})"
            for v in c.vulnerabilities[:5]
        )
        parts.append(
            f"Component: {c.name} v{c.version}\n"
            f"  PURL: {c.purl}\n"
            f"  Global score: {c.scores.global_score}/100\n"
            f"  CVEs: {vulns_text or 'none'}\n"
            f"  Licence: {c.license.spdx_id if c.license else 'UNKNOWN'}\n"
            f"  Trackers: {', '.join(t.name for t in c.trackers) or 'none'}\n"
            f"  Obsolescence score: {c.scores.obsolescence_score}/100\n"
        )
    return "\n---\n".join(parts)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _parse_json_response(text: str) -> Optional[dict]:
    """Strip markdown fences and parse JSON safely."""
    # Remove ```json ... ``` fences
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()
    # Remove trailing fence
    cleaned = cleaned.rstrip("`").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        logger.debug("JSON parse error: %s — raw text: %.200s", e, cleaned)
        return None

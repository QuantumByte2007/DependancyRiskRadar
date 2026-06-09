"""
core/pipeline.py
Main analysis pipeline. Orchestrates ingestion → enrichment → scoring → graph → AI → SBOM.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

from app.core.models import AnalysisReport, Component
from app.core.config import get_settings
from app.ingestion.gradle_parser import parse_project, resolve_dependency_tree, build_components
from app.ingestion.apk_analyzer import analyze_apk, build_components_from_apk
from app.ingestion.enricher import enrich_components
from app.scoring.engine import score_all, compute_project_summary
from app.graph.dependency_graph import DependencyGraph
from app.ai.planner import generate_update_plan, generate_risk_narratives
from app.sbom.generator import generate_cyclonedx, generate_spdx

logger = logging.getLogger(__name__)
settings = get_settings()

ProgressCallback = Callable[[str, int], None]   # (message, percent)


async def run_gradle_analysis(
    project_root: Path,
    output_dir: Path,
    progress: Optional[ProgressCallback] = None,
) -> AnalysisReport:
    """Full pipeline for a Gradle project directory."""

    def _progress(msg: str, pct: int):
        logger.info("[%3d%%] %s", pct, msg)
        if progress:
            progress(msg, pct)

    report_id = str(uuid.uuid4())
    project_name = project_root.name
    output_dir = output_dir / report_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Parse declared dependencies ──
    _progress("Parsing Gradle files...", 5)
    raw_declared = parse_project(project_root)
    _progress(f"Found {len(raw_declared)} declared dependencies", 10)

    # ── Step 2: Resolve full tree via Gradle ──
    _progress("Resolving full dependency tree (this may take a moment)...", 15)
    raw_tree = resolve_dependency_tree(project_root)
    if raw_tree:
        _progress(f"Tree resolved: {len(raw_tree)} components (incl. transitives)", 25)
        raw_deps = raw_tree
    else:
        _progress("Gradle not available — using declared dependencies only", 25)
        raw_deps = raw_declared

    # ── Step 3: Build Component objects ──
    components = build_components(raw_deps)
    _progress(f"Built {len(components)} component objects", 30)

    # ── Step 4: Enrich (CVE, version, licence, trackers) ──
    _progress("Fetching CVE data, versions, licenses, and trackers...", 35)
    components = await enrich_components(components)
    _progress("Enrichment complete", 60)

    # ── Step 5: Score ──
    _progress("Computing risk scores...", 62)
    components = score_all(components)

    # ── Step 6: Build graph + propagate transitive risk ──
    _progress("Building dependency graph...", 65)
    graph = DependencyGraph()
    graph.build(components)
    components = graph.propagate_transitive_risk(components)
    _progress("Graph analysis complete", 70)

    # ── Step 7: Generate SBOM ──
    _progress("Generating SBOM (CycloneDX + SPDX)...", 72)
    report = AnalysisReport(
        report_id=report_id,
        project_name=project_name,
        project_version="unknown",
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        components=components,
    )
    sbom_cdx_path = generate_cyclonedx(report, output_dir / "sbom_cyclonedx.json")
    generate_spdx(report, output_dir / "sbom_spdx.json")
    report.sbom_path = str(sbom_cdx_path)
    _progress("SBOM generated", 80)

    # ── Step 8: AI update plan ──
    _progress("Generating AI-powered update plan...", 82)
    if settings.GEMINI_API_KEY:
        update_plan = await generate_update_plan(components)
        narratives = await generate_risk_narratives(components)
    else:
        logger.warning("No GEMINI_API_KEY — skipping AI update plan")
        update_plan = {"updates": [], "executive_summary": "AI unavailable (no API key configured)."}
        narratives = {}

    report.update_plan = update_plan

    # Attach narratives to components
    for comp in components:
        if comp.purl in narratives:
            comp._narrative = narratives[comp.purl]   # type: ignore[attr-defined]

    _progress("Analysis complete", 100)
    logger.info(
        "Analysis %s complete: %d components, %d vulnerable, global score %.1f",
        report_id,
        report.total_components,
        len(report.vulnerable_components),
        report.global_risk_score,
    )
    return report


async def run_apk_analysis(
    apk_path: Path,
    output_dir: Path,
    progress: Optional[ProgressCallback] = None,
) -> AnalysisReport:
    """Full pipeline for a compiled APK file."""

    def _progress(msg: str, pct: int):
        logger.info("[%3d%%] %s", pct, msg)
        if progress:
            progress(msg, pct)

    report_id = str(uuid.uuid4())
    output_dir = output_dir / report_id
    output_dir.mkdir(parents=True, exist_ok=True)

    _progress("Analysing APK structure...", 10)
    apk_result = analyze_apk(apk_path)
    project_name = apk_result.get("metadata", {}).get("package_name", apk_path.stem)
    project_version = apk_result.get("metadata", {}).get("version_name", "unknown")

    _progress(f"APK: {project_name} v{project_version}", 20)

    strategy = apk_result.get("strategy_used", "unknown")
    errors = apk_result.get("errors", [])
    pkgs = len(apk_result.get("class_packages", []))
    if errors:
        logger.warning("APK analysis errors: %s", errors)
    logger.info("APK strategy=%s packages=%d", strategy, pkgs)

    components = build_components_from_apk(apk_result)
    _progress(f"Inferred {len(components)} components from APK (strategy: {strategy}, {pkgs} packages)", 25)

    _progress("Enriching components...", 30)
    components = await enrich_components(components)
    components = score_all(components)

    graph = DependencyGraph()
    graph.build(components)
    components = graph.propagate_transitive_risk(components)
    _progress("Graph analysis complete", 70)

    report = AnalysisReport(
        report_id=report_id,
        project_name=project_name,
        project_version=project_version,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        components=components,
    )

    generate_cyclonedx(report, output_dir / "sbom_cyclonedx.json")
    generate_spdx(report, output_dir / "sbom_spdx.json")

    if settings.GEMINI_API_KEY:
        report.update_plan = await generate_update_plan(components)
    else:
        report.update_plan = {"updates": [], "executive_summary": "AI unavailable."}

    _progress("Analysis complete", 100)
    return report

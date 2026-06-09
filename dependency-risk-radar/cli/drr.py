#!/usr/bin/env python3
"""
cli/drr.py
Command-line interface for Dependency Risk Radar.

Usage:
    drr analyze ./my-android-project
    drr analyze ./app.apk --format json,pdf
    drr report <report-id>
    drr list
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path


# ─────────────────────────────────────────────
# Colour helpers (no deps required)
# ─────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
BLUE   = "\033[34m"
CYAN   = "\033[36m"
GRAY   = "\033[90m"

def _c(text, *codes): return "".join(codes) + str(text) + RESET
def ok(msg):   print(_c(f"  ✓  {msg}", GREEN))
def warn(msg): print(_c(f"  ⚠  {msg}", YELLOW))
def err(msg):  print(_c(f"  ✗  {msg}", RED), file=sys.stderr)
def info(msg): print(_c(f"  ·  {msg}", GRAY))
def head(msg): print(_c(f"\n{msg}", BOLD, CYAN))


def _risk_color(score: float) -> str:
    if score >= 75: return RED
    if score >= 50: return YELLOW
    if score >= 20: return "\033[33m"
    return GREEN


def _progress_bar(pct: int, width: int = 30) -> str:
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {pct:3d}%"


# ─────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────

async def cmd_analyze(args):
    """Run a full analysis on a Gradle project or APK file."""
    # Bootstrap: add backend to path
    root = Path(__file__).parent.parent / "backend"
    sys.path.insert(0, str(root))

    try:
        from app.core.pipeline import run_gradle_analysis, run_apk_analysis
    except ImportError as e:
        err(f"Cannot import backend modules: {e}")
        err("Make sure you're running from the project root with dependencies installed.")
        sys.exit(1)

    target = Path(args.target).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        err(f"Target not found: {target}")
        sys.exit(1)

    # Header
    print(_c("\n╔══════════════════════════════════════╗", BOLD, BLUE))
    print(_c("║      Dependency Risk Radar  v1.0     ║", BOLD, BLUE))
    print(_c("╚══════════════════════════════════════╝", BOLD, BLUE))
    print(f"\n  Target  : {_c(target, BOLD)}")
    print(f"  Output  : {output_dir}")
    print(f"  AI plan : {'enabled' if os.getenv('ANTHROPIC_API_KEY') else _c('disabled (no API key)', YELLOW)}")
    print()

    last_pct = [-1]
    start_time = time.time()

    def progress(message: str, pct: int):
        if pct != last_pct[0]:
            last_pct[0] = pct
            bar = _progress_bar(pct)
            print(f"\r  {bar}  {_c(message, GRAY):<50}", end="", flush=True)
        if pct == 100:
            print()  # newline after completion

    # Run the right pipeline
    is_apk = target.suffix.lower() == ".apk"
    try:
        if is_apk:
            report = await run_apk_analysis(target, output_dir, progress)
        else:
            report = await run_gradle_analysis(target, output_dir, progress)
    except Exception as e:
        print()
        err(f"Analysis failed: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        sys.exit(1)

    elapsed = time.time() - start_time

    # ── Summary ──────────────────────────────
    head("Analysis Complete")
    print(f"  Time elapsed  : {elapsed:.1f}s")
    print(f"  Report ID     : {_c(report.report_id, BOLD)}")
    print()

    score = report.global_risk_score
    score_str = _c(f"{score}/100", _risk_color(score), BOLD)
    print(f"  Global Risk Score : {score_str}")
    print()

    s = report
    rows = [
        ("Total components",   s.total_components),
        ("Direct",             len(s.direct_components)),
        ("Transitive",         s.total_components - len(s.direct_components)),
        ("Vulnerable",         _c(len(s.vulnerable_components), RED if s.vulnerable_components else GREEN)),
        ("Critical (≥75)",     _c(len(s.critical_components),   RED if s.critical_components else GREEN)),
    ]
    for label, value in rows:
        print(f"  {label:<25} {value}")

    # ── CVE summary ──────────────────────────
    all_cves = [v for c in report.components for v in c.vulnerabilities]
    if all_cves:
        print()
        head("Top Vulnerabilities")
        top = sorted(all_cves, key=lambda v: v.cvss_v3 or 0, reverse=True)[:5]
        for v in top:
            cvss_str = _c(f"CVSS {v.cvss_v3:.1f}", _risk_color((v.cvss_v3 or 0) * 10))
            fix_str  = _c("✓ fix", GREEN) if v.has_fix else _c("✗ no fix", RED)
            print(f"  {v.id:<20} {cvss_str}  {fix_str}  {v.summary[:60]}")

    # ── Update plan summary ──────────────────
    if report.update_plan and report.update_plan.get("updates"):
        print()
        head("Update Plan (AI)")
        updates = report.update_plan["updates"]
        for u in updates[:8]:
            priority = u.get("priority", "?")
            p_color = RED if priority == "CRITICAL" else YELLOW if priority == "HIGH" else GRAY
            print(
                f"  {_c(f'[{priority:<8}]', p_color)}  "
                f"{u['name']:<30} "
                f"{_c(u['current_version'], GRAY)} → {_c(u.get('recommended_version','?'), GREEN)}  "
                f"{_c(u['main_reason'][:50], GRAY)}"
            )
        if len(updates) > 8:
            info(f"  … and {len(updates) - 8} more updates in the full report")

        if report.update_plan.get("executive_summary"):
            print()
            print(_c("  Executive Summary:", BOLD))
            summary = report.update_plan["executive_summary"]
            # Word-wrap at 80 chars
            words = summary.split()
            line, lines_out = [], []
            for w in words:
                line.append(w)
                if len(" ".join(line)) > 75:
                    lines_out.append("  " + " ".join(line[:-1]))
                    line = [w]
            if line:
                lines_out.append("  " + " ".join(line))
            print("\n".join(lines_out))

    # ── Output files ──────────────────────────
    report_out_dir = output_dir / report.report_id
    print()
    head("Output Files")
    for fname in ["sbom_cyclonedx.json", "sbom_spdx.json"]:
        fpath = report_out_dir / fname
        if fpath.exists():
            size = fpath.stat().st_size // 1024
            ok(f"{fname}  ({size} KB)")

    # Save JSON report
    report_json_path = report_out_dir / "report.json"
    report_data = {
        "report_id": report.report_id,
        "project_name": report.project_name,
        "project_version": report.project_version,
        "analyzed_at": report.analyzed_at,
        "global_risk_score": report.global_risk_score,
        "total_components": report.total_components,
        "vulnerable_components": len(report.vulnerable_components),
        "critical_components": len(report.critical_components),
        "update_plan": report.update_plan,
        "components": [c.to_dict() for c in report.components],
    }
    report_json_path.write_text(json.dumps(report_data, indent=2))
    ok(f"report.json  ({report_json_path.stat().st_size // 1024} KB)")

    # Threshold check
    if args.fail_threshold and report.global_risk_score > float(args.fail_threshold):
        print()
        err(f"Risk score {report.global_risk_score} exceeds threshold {args.fail_threshold} — FAILING")
        sys.exit(1)

    if args.fail_on_critical and report.critical_components:
        print()
        err(f"{len(report.critical_components)} critical component(s) detected — FAILING")
        sys.exit(1)

    print()
    ok("Done.")
    print()


def cmd_list(args):
    """List saved reports from the output directory."""
    output_dir = Path(args.output)
    if not output_dir.exists():
        warn("No reports directory found.")
        return

    reports = []
    for d in output_dir.iterdir():
        rjson = d / "report.json"
        if rjson.exists():
            try:
                data = json.loads(rjson.read_text())
                reports.append(data)
            except Exception:
                pass

    if not reports:
        info("No reports found.")
        return

    reports.sort(key=lambda r: r.get("analyzed_at", ""), reverse=True)
    head(f"Reports ({len(reports)} found)")
    print(f"  {'Project':<30} {'Score':>6}  {'Components':>10}  {'Vulnerable':>10}  {'Date'}")
    print(f"  {'─'*30} {'─'*6}  {'─'*10}  {'─'*10}  {'─'*20}")
    for r in reports:
        score = r.get("global_risk_score", 0)
        print(
            f"  {_c(r.get('project_name','?')[:30], BOLD):<30} "
            f"{_c(f'{score:>5.1f}', _risk_color(score))}  "
            f"{r.get('total_components',0):>10}  "
            f"{_c(r.get('vulnerable_components',0), RED):>10}  "
            f"{r.get('analyzed_at','')[:19]}"
        )
    print()


def cmd_report(args):
    """Show detail for a specific report."""
    output_dir = Path(args.output)
    rjson = output_dir / args.report_id / "report.json"
    if not rjson.exists():
        err(f"Report not found: {args.report_id}")
        sys.exit(1)

    data = json.loads(rjson.read_text())
    head(f"Report: {data.get('project_name')} v{data.get('project_version')}")
    print(f"  ID            : {data['report_id']}")
    print(f"  Analysed at   : {data.get('analyzed_at','')[:19]}")
    print(f"  Global score  : {_c(data.get('global_risk_score'), _risk_color(data.get('global_risk_score',0)), BOLD)}")
    print(f"  Components    : {data.get('total_components')}")
    print(f"  Vulnerable    : {_c(data.get('vulnerable_components'), RED)}")
    print(f"  Critical      : {_c(data.get('critical_components'), RED)}")

    components = data.get("components", [])
    critical = [c for c in components if c["scores"]["global"] >= 75]
    if critical:
        print()
        head("Critical Components")
        for c in sorted(critical, key=lambda x: -x["scores"]["global"])[:10]:
            cve_ids = [v["id"] for v in c.get("vulnerabilities", [])[:2]]
            print(
                f"  {_c(c['name'][:35], BOLD):<35} "
                f"score={_c(c['scores']['global'], RED, BOLD):>5}  "
                f"CVEs={','.join(cve_ids) or 'none'}"
            )
    print()


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="drr",
        description="Dependency Risk Radar — SBOM & Risk Analysis",
    )
    parser.add_argument("--output", "-o", default="./drr_reports", help="Output directory")
    parser.add_argument("--verbose", "-v", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyse a Gradle project or APK")
    p_analyze.add_argument("target", help="Path to project root or .apk file")
    p_analyze.add_argument("--fail-threshold", type=float, help="Exit 1 if global score exceeds threshold")
    p_analyze.add_argument("--fail-on-critical", action="store_true", help="Exit 1 if any component is CRITICAL")
    p_analyze.add_argument("--format", default="json", help="Output formats: json,pdf")

    # list
    sub.add_parser("list", help="List all saved reports")

    # report
    p_report = sub.add_parser("report", help="Show a specific report")
    p_report.add_argument("report_id", help="Report ID")

    args = parser.parse_args()

    if args.command == "analyze":
        asyncio.run(cmd_analyze(args))
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()

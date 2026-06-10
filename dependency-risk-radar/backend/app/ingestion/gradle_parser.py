"""
ingestion/gradle_parser.py
Parses build.gradle (Groovy DSL) and build.gradle.kts (Kotlin DSL) files,
then resolves the full dependency tree by invoking Gradle directly.
"""
from __future__ import annotations

import re
import subprocess
import os
from pathlib import Path
from typing import Optional

from app.core.models import Component, DependencyScope


# ─────────────────────────────────────────────
# Regex patterns for dependency declarations
# ─────────────────────────────────────────────

# Standard string form: implementation "group:artifact:version"
STANDARD_DEP = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|annotationProcessor'
    r'|kapt|ksp|testImplementation|androidTestImplementation|debugImplementation'
    r'|releaseImplementation)\s*[(\s]*["\']'
    r'(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<version>[\w.\-+${}]+)["\']'
)

# Map form: implementation group: "...", name: "...", version: "..."
MAP_DEP = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation)\s+'
    r'group:\s*["\'](?P<group>[\w.\-]+)["\'],\s*name:\s*["\'](?P<artifact>[\w.\-]+)["\']'
    r',\s*version:\s*["\'](?P<version>[\w.\-+]+)["\']'
)

# Version catalog reference: implementation libs.retrofit
VERSION_CATALOG_REF = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation)\s+'
    r'(?P<ref>libs\.[\w.]+)'
)

# Variable assignment: def retrofitVersion = "2.9.0"  OR  val retrofitVersion = "2.9.0"
VERSION_VAR = re.compile(
    r'(?:def|val|var)\s+(?P<name>\w+)\s*=\s*["\'](?P<value>[\w.\-+]+)["\']'
)

# Gradle tree line
TREE_LINE = re.compile(
    r'(?P<prefix>[| +\\-]+)\s*(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):'
    r'(?P<version>[\w.\-+]+)(?:\s+->\s+(?P<resolved>[\w.\-+]+))?(?:\s+\(\*\))?'
)


def _scope_from_string(raw: str) -> DependencyScope:
    mapping = {
        "implementation": DependencyScope.IMPLEMENTATION,
        "api": DependencyScope.API,
        "compileonly": DependencyScope.COMPILE_ONLY,
        "runtimeonly": DependencyScope.RUNTIME_ONLY,
        "testimplementation": DependencyScope.TEST,
        "androidtestimplementation": DependencyScope.ANDROID_TEST,
        "kapt": DependencyScope.KAPT,
        "ksp": DependencyScope.KSP,
        "annotationprocessor": DependencyScope.ANNOTATION_PROCESSOR,
    }
    return mapping.get(raw.lower(), DependencyScope.IMPLEMENTATION)


def _build_purl(group: str, artifact: str, version: str) -> str:
    return f"pkg:maven/{group}/{artifact}@{version}"


# ─────────────────────────────────────────────
# Parse declared dependencies from .gradle file
# ─────────────────────────────────────────────

def parse_gradle_file(gradle_path: Path) -> list[dict]:
    """
    Parse a single build.gradle or build.gradle.kts file.
    Returns a list of raw dependency dicts (not yet enriched).
    """
    text = gradle_path.read_text(encoding="utf-8", errors="replace")
    deps: list[dict] = []
    seen: set[str] = set()

    # Extract version variables for substitution
    vars_map: dict[str, str] = {}
    for m in VERSION_VAR.finditer(text):
        vars_map[m.group("name")] = m.group("value")

    def _substitute_version(v: str) -> str:
        """Replace $varName or ${varName} with the resolved value."""
        return re.sub(
            r'\$\{?(\w+)\}?',
            lambda m: vars_map.get(m.group(1), m.group(0)),
            v,
        )

    # Standard declarations
    for m in STANDARD_DEP.finditer(text):
        version = _substitute_version(m.group("version"))
        if "+" in version or "$" in version:
            # Dynamic version — keep as-is, will be resolved by Gradle tree
            version = version.replace("$", "").replace("{", "").replace("}", "")
        key = f"{m.group('group')}:{m.group('artifact')}"
        if key not in seen:
            seen.add(key)
            deps.append({
                "group": m.group("group"),
                "artifact": m.group("artifact"),
                "version": version,
                "scope": m.group("scope"),
                "is_direct": True,
                "depth": 0,
                "source_file": str(gradle_path),
            })

    # Map form declarations
    for m in MAP_DEP.finditer(text):
        key = f"{m.group('group')}:{m.group('artifact')}"
        if key not in seen:
            seen.add(key)
            deps.append({
                "group": m.group("group"),
                "artifact": m.group("artifact"),
                "version": _substitute_version(m.group("version")),
                "scope": m.group("scope"),
                "is_direct": True,
                "depth": 0,
                "source_file": str(gradle_path),
            })

    return deps


def parse_project(project_root: Path) -> list[dict]:
    """
    Walk the project directory and parse all build.gradle / build.gradle.kts files.
    Deduplicates across modules.
    """
    all_deps: list[dict] = []
    seen_keys: set[str] = set()

    gradle_files = list(project_root.rglob("build.gradle")) + \
                   list(project_root.rglob("build.gradle.kts"))

    for gf in gradle_files:
        # Skip build output directories
        if any(part in gf.parts for part in ("build", ".gradle", "cache")):
            continue
        for dep in parse_gradle_file(gf):
            key = f"{dep['group']}:{dep['artifact']}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_deps.append(dep)

    return all_deps


# ─────────────────────────────────────────────
# Resolve full dependency tree via Gradle
# ─────────────────────────────────────────────

def resolve_dependency_tree(
    project_root: Path,
    module: str = ":app",
    configuration: str = "releaseRuntimeClasspath",
) -> list[dict]:
    """
    Invokes `./gradlew :app:dependencies` and parses the tree output.
    Returns a flat list of all components (direct + transitive) with depth info.
    Falls back to parsed-only list if Gradle is unavailable.
    """
    gradlew = project_root / "gradlew"
    if not gradlew.exists():
        return []

    cmd = [
        str(gradlew),
        f"{module}:dependencies",
        f"--configuration={configuration}",
        "--no-daemon",
        "-q",
    ]
    try:
        result = subprocess.run(
            cmd,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=180,
        )
        return _parse_tree_output(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return []


def _parse_tree_output(output: str) -> list[dict]:
    """
    Parse the text output of `./gradlew dependencies`.
    Reconstructs parent-child relationships from indentation depth.
    """
    components: list[dict] = []
    seen: dict[str, dict] = {}
    parent_stack: list[tuple[int, str]] = []   # (depth, purl)
    in_config = False

    for line in output.splitlines():
        # Look for the configuration block header
        if "releaseRuntimeClasspath" in line or "runtimeClasspath" in line:
            in_config = True
            parent_stack = []
            continue
        # End of configuration block
        if in_config and line.strip() == "":
            in_config = False
            continue
        if not in_config:
            continue

        m = TREE_LINE.match(line)
        if not m:
            continue

        prefix = m.group("prefix")
        group = m.group("group")
        artifact = m.group("artifact")
        version = m.group("resolved") or m.group("version")

        # Each indentation level is 5 chars (e.g. "|    "); connector is 4 chars ("+---").
        # Subtract the connector width then divide by 5.
        normalized = prefix.replace("|", " ").replace("\\", " ").replace("+", " ")
        depth = max(0, (len(normalized) - 4) // 5)

        purl = _build_purl(group, artifact, version)

        # Determine parent
        while parent_stack and parent_stack[-1][0] >= depth:
            parent_stack.pop()

        parent_purl = parent_stack[-1][1] if parent_stack else None
        is_direct = depth == 0

        if purl not in seen:
            entry = {
                "group": group,
                "artifact": artifact,
                "version": version,
                "purl": purl,
                "scope": "implementation",
                "is_direct": is_direct,
                "depth": depth,
                "parent_purl": parent_purl,
                "children": [],
            }
            seen[purl] = entry
            components.append(entry)
        else:
            # Already seen (diamond dependency) — update if shallower
            if depth < seen[purl]["depth"]:
                seen[purl]["depth"] = depth
                seen[purl]["is_direct"] = is_direct
                seen[purl]["parent_purl"] = parent_purl

        if parent_purl and parent_purl in seen:
            if purl not in seen[parent_purl]["children"]:
                seen[parent_purl]["children"].append(purl)

        parent_stack.append((depth, purl))

    return components


# ─────────────────────────────────────────────
# Build Component objects from raw dicts
# ─────────────────────────────────────────────

def build_components(raw_deps: list[dict]) -> list[Component]:
    components = []
    for d in raw_deps:
        group = d.get("group", "")
        artifact = d.get("artifact", "")
        version = d.get("version", "0.0.0")
        purl = d.get("purl") or _build_purl(group, artifact, version)
        scope = _scope_from_string(d.get("scope", "implementation"))

        comp = Component(
            purl=purl,
            name=f"{group}:{artifact}",
            group=group,
            artifact=artifact,
            version=version,
            scope=scope,
            is_direct=d.get("is_direct", True),
            depth=d.get("depth", 0),
        )

        # Wire graph edges from tree output
        if d.get("parent_purl"):
            comp.direct_ancestor = d["parent_purl"]
            comp.dependents.append(d["parent_purl"])
        if d.get("children"):
            comp.dependencies.extend(d["children"])

        components.append(comp)

    return components

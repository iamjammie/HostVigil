#!/usr/bin/env python3
"""Validate HostVigil rule packs before they are bundled or committed.

Mirrors hunt-sage's scripts/validate_rules.py: every rule must carry the
metadata the server relies on, ATT&CK tags must be well-formed, IDs must be
unique, and YARA must compile. Exit code 1 on any failure so CI blocks the PR.

    python scripts/validate_rules.py            # validate rules/
    python scripts/validate_rules.py --dir path # another directory
"""
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    yaml = None

ATTACK_TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
}
TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
LEVELS = {"informational", "low", "medium", "high", "critical"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
SIGMA_CATEGORIES = {"process_creation", "registry_set", "registry_event", "ps_script", "logon", "file_event", "network_connection", "image_load"}
MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "base64", "base64offset", "cidr", "lt", "lte", "gt", "gte"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")

errors: list[str] = []
warnings: list[str] = []


def err(path: Path, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def warn(path: Path, msg: str) -> None:
    warnings.append(f"{path}: {msg}")


def check_sigma(path: Path, seen_ids: set[str]) -> None:
    if yaml is None:
        err(path, "PyYAML not installed (pip install pyyaml)")
        return
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as e:
        err(path, f"YAML parse error: {e}")
        return
    for rule in docs:
        if not isinstance(rule, dict):
            err(path, "rule document is not a mapping")
            continue
        for k in ("id", "title", "level", "logsource", "detection"):
            if k not in rule:
                err(path, f"missing required key '{k}'")
        rid = str(rule.get("id", ""))
        if not ID_RE.match(rid):
            err(path, f"id '{rid}' must match {ID_RE.pattern}")
        if rid in seen_ids:
            err(path, f"duplicate rule id '{rid}'")
        seen_ids.add(rid)
        if rule.get("level") not in LEVELS:
            err(path, f"level '{rule.get('level')}' not in {sorted(LEVELS)}")
        tags = rule.get("tags", [])
        if not isinstance(tags, list) or not tags:
            err(path, "tags must be a non-empty list with at least one attack.tNNNN technique")
        else:
            if not any(TECH_RE.match(str(t)) for t in tags):
                err(path, "no ATT&CK technique tag (attack.tNNNN[.NNN])")
            for t in tags:
                t = str(t)
                if t.startswith("attack.") and not TECH_RE.match(t) and t[7:] not in ATTACK_TACTICS:
                    err(path, f"unknown ATT&CK tag '{t}'")
        ls = rule.get("logsource", {})
        if not isinstance(ls, dict) or ls.get("product") != "windows":
            err(path, "logsource.product must be 'windows' (agent is Windows-only)")
        if isinstance(ls, dict) and ls.get("category") not in SIGMA_CATEGORIES:
            err(path, f"logsource.category '{ls.get('category')}' not supported by hv-analytics")
        det = rule.get("detection", {})
        if not isinstance(det, dict) or "condition" not in det:
            err(path, "detection.condition is required")
        else:
            blocks = {k for k in det if k != "condition"}
            if not blocks:
                err(path, "detection has no selection blocks")
            cond = str(det["condition"])
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", cond):
                if tok in ("and", "or", "not", "of", "all"):
                    continue
                if tok.isdigit():
                    continue
                if tok.endswith("*"):
                    if not any(b.startswith(tok[:-1]) for b in blocks):
                        err(path, f"condition references '{tok}' but no block matches")
                elif tok not in blocks:
                    err(path, f"condition references unknown block '{tok}'")
            for name, block in det.items():
                if name == "condition" or not isinstance(block, dict):
                    continue
                for field in block:
                    parts = str(field).split("|")
                    for m in parts[1:]:
                        if m not in MODIFIERS:
                            err(path, f"unknown Sigma modifier '{m}' in '{field}'")


def check_yara(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    names = re.findall(r"^\s*rule\s+([A-Za-z0-9_]+)", text, re.M)
    if not names:
        err(path, "no rule definitions found")
    for n in names:
        if not n.startswith("HV_"):
            warn(path, f"rule '{n}' should be prefixed HV_ for namespace hygiene")
    for n in names:
        block = text.split(f"rule {n}", 1)[1].split("\nrule ", 1)[0]
        if "condition:" not in block:
            err(path, f"rule '{n}' has no condition")
        if 'severity' not in block:
            warn(path, f"rule '{n}' has no meta severity")
    try:
        import yara  # type: ignore

        yara.compile(filepath=str(path))
    except ImportError:
        warn(path, "yara-python not installed; skipped compile check")
    except Exception as e:  # noqa: BLE001
        err(path, f"YARA compile error: {e}")


def check_cis(path: Path, seen_ids: set[str]) -> None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        err(path, f"TOML parse error: {e}")
        return
    checks = data.get("check", [])
    if not checks:
        err(path, "no [[check]] tables")
    for c in checks:
        for k in ("id", "title", "key", "expected", "severity"):
            if k not in c:
                err(path, f"check missing '{k}': {c}")
        cid = str(c.get("id", ""))
        if cid in seen_ids:
            err(path, f"duplicate check id '{cid}'")
        seen_ids.add(cid)
        if c.get("severity") not in SEVERITIES:
            err(path, f"check '{cid}' severity '{c.get('severity')}' not in {sorted(SEVERITIES)}")
        if not re.match(r"^[a-z0-9_]+$", str(c.get("key", ""))):
            err(path, f"check '{cid}' key must be snake_case (matches agent baseline keys)")
        if "remediation" in c and len(str(c["remediation"])) > 4000:
            err(path, f"check '{cid}' remediation too long")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="rules")
    args = ap.parse_args()
    root = Path(args.dir)
    if not root.is_dir():
        print(f"no such directory: {root}", file=sys.stderr)
        return 2
    sigma_ids: set[str] = set()
    cis_ids: set[str] = set()
    n = 0
    for p in sorted((root / "sigma").glob("*.yml")) + sorted((root / "sigma").glob("*.yaml")):
        check_sigma(p, sigma_ids); n += 1
    for p in sorted((root / "yara").glob("*.yar")) + sorted((root / "yara").glob("*.yara")):
        check_yara(p); n += 1
    for p in sorted((root / "cis").glob("*.toml")):
        check_cis(p, cis_ids); n += 1
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    print(f"{n} rule files, {len(sigma_ids)} Sigma rules, {len(cis_ids)} CIS checks, {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

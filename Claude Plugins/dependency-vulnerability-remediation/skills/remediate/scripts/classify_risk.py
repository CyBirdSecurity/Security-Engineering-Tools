#!/usr/bin/env python3
"""
Classify Dependabot alerts (from fetch_alerts.py) into remediation buckets
by upgrade risk (patch/minor/major) and severity, then group them into
PR-sized batches.

Decision matrix:
  - patch bump available            -> bulk_patch   (bundled, capped batches)
  - minor bump available            -> bulk_minor    (bundled, capped batches)
  - major bump / breaking required:
      severity critical or high     -> isolated_critical_high (1 PR/package)
      severity medium or low        -> deferred_major_low_severity (report only)
  - current version unknown, or
    version strings aren't numeric  -> manual_review (report only)
  - no fix published yet            -> no_fix_available (report only)
  - patched version <= current      -> no_action_needed

Usage:
    python3 classify_risk.py --alerts alerts.json \
        --installed-versions installed_versions.json \
        --out groups.json [--max-batch-size 18]

installed_versions.json maps a lookup key to the currently installed/pinned
version string. Claude builds this by reading the target repo's manifests
and lockfiles for every package named in alerts.json. Preferred key format:
    "<ecosystem>::<package_name>::<manifest_path>"
Falls back to "<ecosystem>::<package_name>" if the manifest-specific key
isn't present (useful for single-manifest repos).
"""
import argparse
import json
import re
import sys
from collections import defaultdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_version(v):
    if not v:
        return None
    m = VERSION_RE.match(v.strip())
    if not m:
        return None
    return tuple(int(g) if g is not None else 0 for g in m.groups())


def diff_class(current, patched):
    cur = parse_version(current)
    pat = parse_version(patched)
    if cur is None or pat is None:
        return "manual-non-semver"
    if cur >= pat:
        return "no-action-needed"
    if cur[0] != pat[0]:
        return "major"
    if cur[1] != pat[1]:
        return "minor"
    return "patch"


def lookup_installed(installed_versions, ecosystem, package_name, manifest_path):
    key_specific = f"{ecosystem}::{package_name}::{manifest_path}"
    if key_specific in installed_versions:
        return installed_versions[key_specific]
    key_generic = f"{ecosystem}::{package_name}"
    return installed_versions.get(key_generic)


def chunk(items, size):
    return [items[i:i + size] for i in range(0, len(items), size)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--installed-versions", required=True)
    parser.add_argument("--out", default="groups.json")
    parser.add_argument("--max-batch-size", type=int, default=18)
    args = parser.parse_args()

    with open(args.alerts) as f:
        alerts = json.load(f)
    with open(args.installed_versions) as f:
        installed_versions = json.load(f)

    buckets = defaultdict(list)
    isolated_by_package = defaultdict(list)

    for alert in alerts:
        if not alert.get("first_patched_version"):
            buckets["no_fix_available"].append(alert)
            continue

        current = lookup_installed(
            installed_versions, alert["ecosystem"], alert["package_name"], alert["manifest_path"]
        )
        if current is None:
            buckets["manual_review"].append({**alert, "reason": "no installed version found"})
            continue

        tier = diff_class(current, alert["first_patched_version"])
        alert = {**alert, "current_version": current, "risk_tier": tier}

        if tier == "no-action-needed":
            buckets["no_action_needed"].append(alert)
        elif tier == "manual-non-semver":
            buckets["manual_review"].append({**alert, "reason": "non-numeric version string"})
        elif tier == "patch":
            buckets["bulk_patch"].append(alert)
        elif tier == "minor":
            buckets["bulk_minor"].append(alert)
        elif tier == "major":
            sev = alert.get("severity", "")
            if sev in ("critical", "high"):
                isolated_by_package[(alert["ecosystem"], alert["package_name"])].append(alert)
            else:
                buckets["deferred_major_low_severity"].append(alert)

    def sort_key(a):
        return (SEVERITY_ORDER.get(a.get("severity", ""), 4), a["package_name"])

    output = {"buckets": {}}

    for name in ("bulk_patch", "bulk_minor"):
        items = sorted(buckets[name], key=sort_key)
        batches = chunk(items, args.max_batch_size)
        output["buckets"][name] = [
            {
                "batch_id": f"{name}-{i + 1}-of-{len(batches)}",
                "items": batch,
            }
            for i, batch in enumerate(batches)
        ]

    output["buckets"]["isolated_critical_high"] = [
        {
            "ecosystem": eco,
            "package_name": pkg,
            "items": sorted(items, key=sort_key),
        }
        for (eco, pkg), items in sorted(
            isolated_by_package.items(), key=lambda kv: (SEVERITY_ORDER.get(kv[1][0].get("severity", ""), 4), kv[0][1])
        )
    ]

    for name in ("deferred_major_low_severity", "manual_review", "no_fix_available", "no_action_needed"):
        output["buckets"][name] = sorted(buckets[name], key=sort_key)

    output["summary"] = {
        "total_alerts": len(alerts),
        "bulk_patch_count": len(buckets["bulk_patch"]),
        "bulk_patch_batches": len(output["buckets"]["bulk_patch"]),
        "bulk_minor_count": len(buckets["bulk_minor"]),
        "bulk_minor_batches": len(output["buckets"]["bulk_minor"]),
        "isolated_critical_high_prs": len(output["buckets"]["isolated_critical_high"]),
        "deferred_major_low_severity_count": len(buckets["deferred_major_low_severity"]),
        "manual_review_count": len(buckets["manual_review"]),
        "no_fix_available_count": len(buckets["no_fix_available"]),
        "no_action_needed_count": len(buckets["no_action_needed"]),
    }

    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)

    print(json.dumps(output["summary"], indent=2), file=sys.stderr)
    print(f"\nWrote grouped remediation plan -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()

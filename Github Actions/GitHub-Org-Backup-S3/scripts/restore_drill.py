#!/usr/bin/env python3
"""Restore drill: prove the latest backups can actually be restored.

Uses the *read-only* restore role. For a few repositories from the latest
complete snapshot it:
  1. downloads every git and metadata file and checks size + SHA-256 against
     the manifest,
  2. runs `git bundle verify`, clones the bundle with `--mirror`, and checks
     that the restored refs hash to the value recorded at backup time,
  3. checks the wiki bundle the same way and that metadata files are valid
     gzipped JSON.

Opens / comments on a `restore-drill-failure` issue when anything fails.
Nothing is pushed anywhere; see RESTORE.md for a real restore.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys

from common import (S3, env, gha_summary, layout_from_env, log, parse_iso, report_issue, run_url, sha256_file,
                    utcnow, work_root)

LABEL = "restore-drill-failure"


def pick_manifest(s3: S3, layout) -> tuple[dict | None, list[str]]:
    """Newest full snapshot whose run succeeded, plus notes about newer
    snapshots that were skipped because their run had problems."""
    root = f"{layout.prefix}/snapshots/{layout.org}/"
    notes: list[str] = []
    for prefix in reversed(s3.list_prefixes(root)):
        try:
            m = s3.get_json(prefix + "manifest.json")
        except RuntimeError as e:
            if "InvalidObjectState" in str(e):
                # Lifecycle moved this (and therefore every older) snapshot to Deep Archive.
                notes.append(f"Snapshots from `{prefix.rstrip('/').rsplit('/', 1)[-1]}` back are in Deep Archive "
                             "and weren't checked.")
                break
            notes.append(f"Could not read `{prefix}manifest.json`: {str(e)[-200:]}")
            continue
        if not m or m.get("partial"):
            continue
        if m.get("success"):
            return m, notes
        failed = (m.get("counts") or {}).get("failed", 0)
        notes.append(f"Snapshot `{m['snapshot_id']}` had problems ({failed} repos failed); not used for the drill.")
    return None, notes


def refs_hash(repo_dir: str) -> tuple[int, str]:
    out = subprocess.run(["git", "for-each-ref", "--format=%(objectname) %(refname)"], cwd=repo_dir,
                         capture_output=True, check=True).stdout
    lines = sorted(l for l in out.splitlines() if l.strip())
    return len(lines), hashlib.sha256(b"\n".join(lines) + (b"\n" if lines else b"")).hexdigest()


def drill_repo(s3: S3, entry: dict) -> list[str]:
    errors: list[str] = []
    dest = entry["destinations"][0]
    root = os.path.join(work_root(), "drill", entry["node_id"].replace("/", "_"))
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    try:
        files = {f"git/{k}": v for k, v in (entry["git"].get("files") or {}).items()}
        # Release assets can be large; the drill checks everything else.
        files.update({k: v for k, v in (entry["metadata"].get("files") or {}).items()
                      if not k.startswith("metadata/release-assets/")})
        local = {}
        for rel, info in files.items():
            path = os.path.join(root, rel.replace("/", "__"))
            s3.get_file(f"{dest}/{rel}", path)
            if os.path.getsize(path) != info["size"] or sha256_file(path) != info["sha256"]:
                errors.append(f"{rel}: size/checksum mismatch")
            local[rel] = path

        for bundle_name, count_key, hash_key in (("git/repo.bundle", "ref_count", "refs_sha256"),
                                                 ("git/wiki.bundle", "wiki_ref_count", "wiki_refs_sha256")):
            if bundle_name not in local:
                continue
            target = os.path.join(root, bundle_name.split("/")[1] + ".git")
            # Verify in a fresh, empty repo (verify needs a repo, but one cloned
            # from this same bundle would make the check meaningless): a full
            # backup bundle must be self-contained, with no prerequisites.
            empty = os.path.join(root, "verify-empty.git")
            shutil.rmtree(empty, ignore_errors=True)
            subprocess.run(["git", "init", "--quiet", "--bare", empty], check=True, capture_output=True)
            v = subprocess.run(["git", "bundle", "verify", "--quiet", local[bundle_name]], cwd=empty,
                               capture_output=True)
            shutil.rmtree(empty, ignore_errors=True)
            if v.returncode:
                errors.append(f"{bundle_name}: verify failed (not self-contained or corrupt): "
                              f"{v.stderr.decode()[-300:]}")
                continue
            c = subprocess.run(["git", "clone", "--mirror", "--quiet", local[bundle_name], target],
                               capture_output=True)
            if c.returncode:
                errors.append(f"{bundle_name}: clone failed: {c.stderr.decode()[-300:]}")
                continue
            count, digest = refs_hash(target)
            if digest != entry["git"].get(hash_key):
                errors.append(f"{bundle_name}: restored {count} refs, expected {entry['git'].get(count_key)} "
                              "(ref hash mismatch)")
            fsck = subprocess.run(["git", "fsck", "--no-progress", "--connectivity-only"], cwd=target,
                                  capture_output=True)
            if fsck.returncode:
                errors.append(f"{bundle_name}: git fsck failed: {fsck.stderr.decode()[-300:]}")

        for rel, path in local.items():
            if rel.endswith(".json.gz"):
                try:
                    with gzip.open(path, "rt", encoding="utf-8") as f:
                        json.load(f)
                except Exception as e:  # noqa: BLE001
                    errors.append(f"{rel}: not valid gzipped JSON ({e})")
    except Exception as e:  # noqa: BLE001
        errors.append(str(e)[-400:])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return errors


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", default=env("DRILL_COUNT", "3"))
    ap.add_argument("--repo", default=env("DRILL_REPO", ""), help="Drill this repo name instead of random ones")
    args = ap.parse_args()

    layout = layout_from_env()
    failures: list[str] = []   # anything here fails the drill and keeps/opens the issue
    rows: list[str] = []
    # Validate inputs here (not in argparse) so a bad value is reported as an
    # issue instead of crashing before report_issue runs.
    try:
        args.count = int(args.count)
        if args.count < 1:
            raise ValueError
    except ValueError:
        failures.append(f"Invalid drill count {args.count!r}; using 3.")
        args.count = 3
    try:
        max_age_days = float(env("DRILL_MAX_AGE_DAYS", "15"))
    except ValueError:
        failures.append(f"Invalid DRILL_MAX_AGE_DAYS {env('DRILL_MAX_AGE_DAYS')!r}; using 15.")
        max_age_days = 15.0
    s3 = S3(env("BACKUP_S3_BUCKET"))

    try:
        manifest, notes = pick_manifest(s3, layout)
    except Exception as e:  # noqa: BLE001 - e.g. role/KMS misconfigured: still report it
        manifest, notes = None, []
        failures.append(f"Could not read snapshots: {str(e)[-300:]}")

    if manifest is None:
        if not failures:
            failures.append("No successful full snapshot found to drill.")
    else:
        finished = parse_iso(manifest.get("finished_at"))
        if finished and (utcnow() - finished).days > max_age_days:
            failures.append(f"Newest successful snapshot `{manifest['snapshot_id']}` is "
                            f"{(utcnow() - finished).days} days old (limit {max_age_days:.0f}).")
        candidates = [e for e in manifest["repos"] if e["status"] == "backed-up" and e.get("git")
                      and e["git"].get("status") == "ok"]
        if args.repo:
            chosen = [e for e in candidates if e["name"] == args.repo]
            if not chosen:
                failures.append(f"`{args.repo}` has no successful git backup in snapshot "
                                f"`{manifest['snapshot_id']}`.")
        else:
            chosen = random.sample(candidates, min(args.count, len(candidates)))
        if not chosen and not args.repo:
            failures.append(f"Snapshot `{manifest['snapshot_id']}` has no restorable repositories.")
        for e in chosen:
            log(f"Drilling {e['full_name']} ...")
            errs = drill_repo(s3, e)
            rows.append(f"| `{e['full_name']}` | "
                        f"{'✅ restored and verified' if not errs else '❌ ' + '; '.join(errs)[:400]} |")
            if errs:
                failures.append(f"`{e['full_name']}` failed to restore.")

    title = f"### Restore drill — snapshot `{manifest['snapshot_id']}`" if manifest else "### Restore drill"
    lines = [title, ""]
    if rows:
        lines += ["| Repo | Result |", "|---|---|", *rows, ""]
    if failures:
        lines += ["#### Problems", *[f"- {f}" for f in failures], ""]
    if notes:
        lines += ["#### Notes", *[f"- {n}" for n in notes], ""]
    lines.append(f"Run: {run_url()}")
    body = "\n".join(lines)
    gha_summary(body)
    report_issue(bool(failures), LABEL, f"GitHub org backup restore drill failing for {layout.org}", body)
    if failures:
        log("Restore drill failed:\n- " + "\n- ".join(failures))
        sys.exit(1)


if __name__ == "__main__":
    main()

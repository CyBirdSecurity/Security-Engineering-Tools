#!/usr/bin/env python3
"""Combine shard results into manifest.json, update the archive tracker,
and open / update / close the `backup-failure` GitHub issue.

Runs with `if: always()`, so it also reports when an earlier job crashed,
timed out or never produced results. Exits non-zero when anything failed so
the workflow run is red as well.

Per-repo status in the manifest:
  backed-up           weekly snapshot (and final copy, if recently archived) written
  final-copy-created  one-time permanent copy of a long-archived repo written
  skipped-archived    archived longer than the grace period; final copy already stored
  failed              git or metadata export failed, or results are missing
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from common import (S3, env, gha_summary, iso, layout_from_env, load_json, log, report_issue, run_url, utcnow)

LABEL = "backup-failure"
MAX_LISTED = 50


def load_results(results_dir: str):
    git, meta = {}, {}
    for path in sorted(glob.glob(os.path.join(results_dir, "**", "*.json"), recursive=True)):
        data = load_json(path)
        kind = data.get("kind")
        if kind == "git":
            git.update(data["repos"])
        elif kind == "metadata":
            meta.update(data["repos"])
    return git, meta


def summarize(r: dict | None) -> dict | None:
    if r is None:
        return None
    keep = ("status", "errors", "warnings", "ref_count", "refs_sha256", "head", "lfs", "wiki", "counts",
            "files", "duration_s", "wiki_ref_count", "wiki_refs_sha256")
    return {k: r[k] for k in keep if k in r}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", default="plan.json")
    ap.add_argument("--results", default="results")
    args = ap.parse_args()

    now = utcnow()
    org = env("BACKUP_ORG", required=True)
    layout = layout_from_env()
    problems: list[str] = []

    # Jobs that failed / were cancelled / timed out.
    needs = json.loads(env("NEEDS_JSON", "{}") or "{}")
    for job, info in needs.items():
        if info.get("result") not in ("success", "skipped"):
            problems.append(f"Job `{job}` finished with result `{info.get('result')}`.")

    plan = load_json(args.plan) if os.path.exists(args.plan) else None
    if plan is None:
        problems.append("No backup plan was produced — the discover job failed before listing repositories.")
    git, meta = load_results(args.results)

    entries, failed_repos = [], []
    counts: dict[str, int] = {}
    for r in (plan or {}).get("repos", []):
        e = {k: r.get(k) for k in ("node_id", "name", "full_name", "archived", "archived_at", "archived_at_source",
                                   "action", "reason", "destinations", "visibility", "fork", "default_branch")}
        if r["action"] == "skip":
            e["status"] = "skipped-archived"
        else:
            g, m = git.get(r["node_id"]), meta.get(r["node_id"])
            e["git"], e["metadata"] = summarize(g), summarize(m)
            g_ok = bool(g) and g["status"] in ("ok", "empty")
            m_ok = bool(m) and m["status"] == "ok"
            if g_ok and m_ok:
                e["status"] = "final-copy-created" if r["action"] == "final-only" else "backed-up"
            else:
                e["status"] = "failed"
                why = []
                if not g:
                    why.append("git: no result (shard job crashed or timed out)")
                elif not g_ok:
                    why.append("git: " + "; ".join(g["errors"]))
                if not m:
                    why.append("metadata: no result (shard job crashed or timed out)")
                elif not m_ok:
                    why.append("metadata: " + "; ".join(m["errors"]))
                failed_repos.append((r["full_name"], " | ".join(why)))
        counts[e["status"]] = counts.get(e["status"], 0) + 1
        entries.append(e)

    if failed_repos:
        problems.append(f"{len(failed_repos)} repositories failed.")

    # Wikis on private/internal repos that answered "not found" can't be told
    # apart from a token that can't read wikis - unless this same run cloned
    # at least one private wiki successfully, which proves the token can.
    notes: list[str] = []
    visibility = {r["node_id"]: r.get("visibility") for r in (plan or {}).get("repos", [])}
    unverified = [g["name"] for g in git.values() if g.get("wiki") == "not-found-unverified"]
    private_ok = any(g.get("wiki") == "ok" and visibility.get(nid) != "PUBLIC" for nid, g in git.items())
    if unverified and not private_ok:
        notes.append(f"{len(unverified)} private/internal repo(s) have wikis enabled but none could be cloned, "
                     "and no private wiki was cloned in this run, so it's unconfirmed that the GitHub App can read "
                     "private wikis. Check one that has pages: " + ", ".join(f"`{n}`" for n in unverified[:10]))

    s3 = None
    try:
        s3 = S3(env("BACKUP_S3_BUCKET"))
    except SystemExit as e:
        problems.append(f"Cannot write manifest: {e}")

    gone: list[str] = []
    if plan is not None and s3 is not None:
        try:
            # ---- archive tracker -------------------------------------------
            tracker_key = layout.state("archive-tracker.json")
            tracker = s3.get_json(tracker_key) or {"version": 1, "repos": {}}
            status_by_id = {e["node_id"]: e["status"] for e in entries}
            for r in plan["repos"]:
                t = tracker["repos"].setdefault(r["node_id"], {})
                t.update(name=r["name"], full_name=r["full_name"], archived=r["archived"],
                         last_seen=plan["generated_at"])
                t.pop("missing_since", None)
                if r["archived"]:
                    t.setdefault("first_seen_archived", r["archived_at"] if r["archived_at_source"] == "first-seen"
                                 else plan["generated_at"])
                    t["archived_at"] = r["archived_at"]
                    if r.get("write_final") and status_by_id.get(r["node_id"]) in ("backed-up", "final-copy-created"):
                        t["final_copy"] = {"archived_at": r["archived_at"], "prefix": r["destinations"][-1],
                                           "snapshot_id": plan["snapshot_id"], "written_at": iso(now)}
                else:
                    t.pop("first_seen_archived", None)
                    t.pop("archived_at", None)
            if not plan["partial"]:
                present = {r["node_id"] for r in plan["repos"]}
                for node_id, t in tracker["repos"].items():
                    if node_id not in present and "missing_since" not in t:
                        # Report each deleted/renamed/transferred repo once, in the
                        # run that first notices it; the tracker keeps the date.
                        t["missing_since"] = plan["generated_at"]
                        gone.append(t.get("full_name", node_id))
            tracker["updated_at"] = iso(now)
            s3.put_json(tracker, tracker_key)

            # ---- manifest (written last = snapshot complete marker) -------
            manifest = {
                "version": 1, "org": org, "snapshot_id": plan["snapshot_id"], "started_at": plan["generated_at"],
                "finished_at": iso(now), "run_url": run_url(), "partial": plan["partial"],
                "repo_filter": plan["repo_filter"], "grace_days": plan["grace_days"],
                "success": not problems, "problems": problems, "counts": counts,
                "repos_newly_missing_from_org": sorted(gone), "notes": notes, "repos": entries,
            }
            s3.put_json(manifest, f"{plan['snapshot_root']}/manifest.json")
            marker = {"snapshot_id": plan["snapshot_id"], "finished_at": iso(now), "run_url": run_url(),
                      "success": not problems, "partial": plan["partial"], "counts": counts}
            s3.put_json(marker, layout.state("last-run.json"))
            if not problems and not plan["partial"]:
                s3.put_json(marker, layout.state("last-success.json"))
        except Exception as e:  # noqa: BLE001
            problems.append(f"Writing manifest/state to S3 failed: {str(e)[-300:]}")

    # ---- summary + issue -----------------------------------------------------
    snapshot = (plan or {}).get("snapshot_id", "n/a")
    lines = [f"### Backup result for `{org}` — snapshot `{snapshot}`", "",
             "| Status | Repos |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(counts.items())]
    if gone:
        lines += ["", f"**{len(gone)} repo(s) newly missing from the org** (deleted, renamed or transferred "
                      "since the last full run). Their existing snapshots stay in S3 until the snapshot lifecycle "
                      "expires them: " + ", ".join(f"`{g}`" for g in gone[:MAX_LISTED])]
    if notes:
        lines += ["", "#### Notes"] + [f"- {n}" for n in notes]
    if problems:
        lines += ["", "#### Problems"] + [f"- {p}" for p in problems]
    if failed_repos:
        lines += ["", "#### Failed repositories", "| Repo | Error |", "|---|---|"]
        lines += [f"| `{n}` | {err.replace('|', '/')[:400]} |" for n, err in failed_repos[:MAX_LISTED]]
        if len(failed_repos) > MAX_LISTED:
            lines.append(f"\n…and {len(failed_repos) - MAX_LISTED} more (see manifest.json).")
    lines += ["", f"Run: {run_url()}"]
    body = "\n".join(lines)
    gha_summary(body)

    try:
        partial = (plan or {}).get("partial", False)
        if problems or not partial:  # a filtered test run that succeeds shouldn't close a real failure
            report_issue(bool(problems), LABEL, f"GitHub org backup failing for {org}", body)
    except Exception as e:  # noqa: BLE001
        log(f"Could not update the {LABEL} issue: {e}")
        problems.append("issue reporting failed")

    if problems:
        log("Backup finished with problems:\n- " + "\n- ".join(problems))
        sys.exit(1)
    log("Backup finished successfully.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""List every repository in the org, decide what to do with each one, and
split the work into shards.

Output: a plan JSON file (uploaded as a workflow artifact) plus the
`snapshot_id` and `shards` step outputs used to build the job matrix.

Archived-repo filter (on by default, ARCHIVED_GRACE_DAYS=14):
  not archived                                  -> backup
  archived <= grace days ago                    -> backup + write permanent final copy
  archived  > grace days ago, final copy exists -> skip
  archived  > grace days ago, no final copy yet -> final-only (one-time final copy)
  ARCHIVED_GRACE_DAYS=-1                         -> archived repos always backed up
"""

from __future__ import annotations

import argparse
import datetime as dt
import heapq
import re

from common import (GitHub, Layout, S3, auth_from_env, compact_ts, env, gha_output, gha_summary,
                    gha_warning, iso, layout_from_env, log, parse_iso, utcnow, write_json)

REPO_QUERY = """
query($org: String!, $after: String) {
  organization(login: $org) {
    repositories(first: 100, after: $after, orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id name nameWithOwner isArchived archivedAt isEmpty isFork isPrivate visibility
        hasWikiEnabled diskUsage pushedAt createdAt
        defaultBranchRef { name }
      }
    }
  }
}
"""


def list_repos(gh: GitHub, org: str) -> list[dict]:
    repos, after = [], None
    while True:
        data = gh.graphql(REPO_QUERY, {"org": org, "after": after})
        conn = data["organization"]["repositories"]
        repos.extend(conn["nodes"])
        if not conn["pageInfo"]["hasNextPage"]:
            return repos
        after = conn["pageInfo"]["endCursor"]


def decide(repo: dict, tracker_entry: dict | None, grace_days: int, now: dt.datetime) -> dict:
    """Pure decision function for one repo (unit-tested in tests/).

    Returns {"action", "archived_at", "archived_at_source", "write_final", "reason"}.
    """
    entry = tracker_entry or {}
    if not repo.get("isArchived"):
        return {"action": "backup", "archived_at": None, "archived_at_source": None,
                "write_final": False, "reason": "active"}

    # GraphQL archivedAt is authoritative; repos archived before GitHub
    # recorded it fall back to the first time this tool saw them archived.
    if repo.get("archivedAt"):
        archived_at, source = repo["archivedAt"], "github"
    elif entry.get("first_seen_archived"):
        archived_at, source = entry["first_seen_archived"], "first-seen"
    else:
        archived_at, source = iso(now), "first-seen"

    final = entry.get("final_copy") or {}
    has_final = compact_ts(final.get("archived_at", "")) == compact_ts(archived_at) and bool(final)
    age_days = (now - parse_iso(archived_at)).total_seconds() / 86400

    base = {"archived_at": archived_at, "archived_at_source": source}
    if grace_days < 0 or age_days <= grace_days:
        why = "archive filter disabled" if grace_days < 0 else f"archived {age_days:.1f}d ago (within {grace_days}d grace)"
        return {**base, "action": "backup", "write_final": True, "reason": why}
    if has_final:
        return {**base, "action": "skip", "write_final": False,
                "reason": f"archived {age_days:.0f}d ago; final copy already stored"}
    return {**base, "action": "final-only", "write_final": True,
            "reason": f"archived {age_days:.0f}d ago; creating one-time final copy"}


def assign_shards(repos: list[dict], shard_count: int) -> int:
    """Greedy size-balanced sharding (largest repos first). Returns shard count used."""
    work = [r for r in repos if r["action"] != "skip"]
    n = max(1, min(shard_count, len(work)))
    heap = [(0, i) for i in range(n)]
    for r in sorted(work, key=lambda r: r.get("diskUsage") or 0, reverse=True):
        load, idx = heapq.heappop(heap)
        r["shard"] = idx
        heapq.heappush(heap, (load + (r.get("diskUsage") or 0) + 1024, idx))  # +1MB per repo for overhead
    for r in repos:
        r.setdefault("shard", None)
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="plan.json")
    args = ap.parse_args()

    org = env("BACKUP_ORG", required=True)
    layout: Layout = layout_from_env()
    s3 = S3(env("BACKUP_S3_BUCKET"))
    gh = GitHub(auth_from_env(org))

    grace_raw = env("ARCHIVED_GRACE_DAYS", "14")
    try:
        grace_days = int(grace_raw)
    except ValueError:
        raise SystemExit(f"ARCHIVED_GRACE_DAYS must be an integer (got {grace_raw!r}); use -1 to disable.")
    shard_count = int(env("SHARD_COUNT", "8"))
    repo_filter = env("REPO_FILTER", "")
    now = utcnow()
    snapshot_id = env("SNAPSHOT_ID") or now.strftime("%Y-%m-%dT%H%M%SZ")

    tracker = s3.get_json(layout.state("archive-tracker.json")) or {"version": 1, "repos": {}}
    repos = list_repos(gh, org)
    log(f"Found {len(repos)} repositories in {org}.")
    if not repos:
        gha_warning(f"No repositories visible in {org}. Is the GitHub App installed on 'All repositories'?")

    if repo_filter:
        rx = re.compile(repo_filter)
        repos = [r for r in repos if rx.search(r["name"])]
        log(f"REPO_FILTER={repo_filter!r} matched {len(repos)} repositories.")

    plan_repos = []
    for r in repos:
        d = decide(r, tracker["repos"].get(r["id"]), grace_days, now)
        destinations = []
        if d["action"] == "backup":
            destinations.append(layout.snapshot_repo(snapshot_id, r["name"]))
        if d["write_final"]:
            destinations.append(layout.final_copy(r["id"], d["archived_at"], snapshot_id))
        plan_repos.append({
            "node_id": r["id"], "name": r["name"], "full_name": r["nameWithOwner"],
            "archived": r["isArchived"], "is_empty": r["isEmpty"], "fork": r["isFork"],
            "visibility": r["visibility"], "has_wiki": r["hasWikiEnabled"],
            "diskUsage": r["diskUsage"], "default_branch": (r.get("defaultBranchRef") or {}).get("name"),
            "pushed_at": r["pushedAt"], **d, "destinations": destinations,
        })

    used = assign_shards(plan_repos, shard_count)
    plan = {
        "version": 1, "org": org, "snapshot_id": snapshot_id, "generated_at": iso(now),
        "grace_days": grace_days, "repo_filter": repo_filter, "partial": bool(repo_filter),
        "snapshot_root": layout.snapshot_root(snapshot_id), "shard_count": used, "repos": plan_repos,
    }
    write_json(plan, args.out)

    counts: dict[str, int] = {}
    for r in plan_repos:
        counts[r["action"]] = counts.get(r["action"], 0) + 1
    gha_output("snapshot_id", snapshot_id)
    gha_output("shards", "[" + ",".join(str(i) for i in range(used)) + "]")
    gha_summary(
        f"### Backup plan for `{org}` — snapshot `{snapshot_id}`\n\n"
        f"| Action | Repos |\n|---|---|\n"
        + "".join(f"| {k} | {v} |\n" for k, v in sorted(counts.items()))
        + f"\nArchived grace days: `{grace_days}` · shards: `{used}`"
        + (f" · **partial run** (filter `{repo_filter}`)" if repo_filter else "")
    )
    log(f"Plan: {counts}, {used} shard(s).")


if __name__ == "__main__":
    main()

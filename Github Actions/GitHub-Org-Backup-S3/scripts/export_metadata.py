#!/usr/bin/env python3
"""Export repository metadata and repo-level configuration for one shard.

Metadata (gzipped JSON under <destination>/metadata/):
  issues.json.gz    issues + all comments
  pulls.json.gz     pull requests + comments, reviews, review threads/comments
  labels.json.gz, milestones.json.gz, releases.json.gz
  release-assets/<release_id>/<asset_id>-<name>   (BACKUP_RELEASE_ASSETS=true)

Repo configuration (JSON under <destination>/config/):
  repository, rulesets, branch-protection, hooks, teams, collaborators,
  custom-properties, actions-permissions, environments, actions-secrets
  (names only - values can't be read), actions-variables, deploy-keys, autolinks

Endpoints that are unavailable for a repo (feature not on the plan, archived
repo, missing App permission) are recorded under "warnings" rather than
failing the repo; real API errors on core metadata fail it.

Not covered by the API surface used here: issue/PR timeline events,
attachments uploaded into issue/PR bodies, Discussions, Projects.
"""

from __future__ import annotations

import argparse
import os
import shutil
import time
import urllib.parse

from common import (GitHub, GitHubError, S3, auth_from_env, env, gha_error, iso, load_json, log, safe_name,
                    sha256_file, shard_repos, utcnow, work_root, write_json, write_json_gz)

RELEASE_ASSETS = (env("BACKUP_RELEASE_ASSETS", "true") or "true").lower() == "true"

ACTOR = "author { login }"
REACTIONS = "reactionGroups { content reactors { totalCount } }"
PAGE = "pageInfo { hasNextPage endCursor }"

COMMENT = f"id databaseId url body createdAt updatedAt isMinimized minimizedReason {ACTOR} {REACTIONS}"
COMMON_ITEM = (
    f"id databaseId number url title body state createdAt updatedAt closedAt locked activeLockReason {ACTOR} "
    f"{REACTIONS} assignees(first: 50) {{ nodes {{ login }} }} labels(first: 100) {{ nodes {{ name }} }} "
    "milestone { number title }"
)
ISSUE = f"{COMMON_ITEM} stateReason comments(first: 100) {{ {PAGE} totalCount nodes {{ {COMMENT} }} }}"
REVIEW = f"id databaseId url state body submittedAt {ACTOR} commit {{ oid }}"
THREAD_COMMENT = (f"id databaseId url body createdAt updatedAt path diffHunk {ACTOR} {REACTIONS} "
                  "originalCommit { oid } commit { oid } replyTo { id }")
THREAD = (f"id path line originalLine startLine diffSide isResolved isOutdated resolvedBy {{ login }} "
          f"comments(first: 50) {{ {PAGE} nodes {{ {THREAD_COMMENT} }} }}")
PULL = (
    f"{COMMON_ITEM} isDraft merged mergedAt mergedBy {{ login }} baseRefName headRefName baseRefOid headRefOid "
    "headRepository { nameWithOwner } mergeCommit { oid } "
    f"comments(first: 50) {{ {PAGE} nodes {{ {COMMENT} }} }} "
    f"reviews(first: 50) {{ {PAGE} nodes {{ {REVIEW} }} }} "
    f"reviewThreads(first: 30) {{ {PAGE} nodes {{ {THREAD} }} }}"
)

TOP_QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    %s(first: %d, after: $after, orderBy: {field: CREATED_AT, direction: ASC}%s) {
      pageInfo { hasNextPage endCursor }
      nodes { %s }
    }
  }
}
"""
NODE_QUERY = """
query($id: ID!, $after: String) {
  node(id: $id) {
    ... on %s {
      %s(first: 100, after: $after) { pageInfo { hasNextPage endCursor } nodes { %s } }
    }
  }
}
"""


def complete_connection(gh: GitHub, node: dict, typename: str, field: str, fragment: str) -> None:
    """Replace node[field] (a GraphQL connection) with the complete list of nodes."""
    conn = node[field]
    items = list(conn["nodes"])
    page = conn["pageInfo"]
    while page["hasNextPage"]:
        data = gh.graphql(NODE_QUERY % (typename, field, fragment), {"id": node["id"], "after": page["endCursor"]})
        c = data["node"][field]
        items.extend(c["nodes"])
        page = c["pageInfo"]
    node[field] = items


def flatten(item: dict) -> dict:
    for key in ("assignees", "labels"):
        if isinstance(item.get(key), dict):
            item[key] = [n["login"] if "login" in n else n["name"] for n in item[key]["nodes"]]
    return item


def export_items(gh: GitHub, owner: str, name: str, kind: str) -> list[dict]:
    if kind == "issues":
        top_field, fragment, page_size, extra = "issues", ISSUE, 25, ""
    else:
        top_field, fragment, page_size, extra = "pullRequests", PULL, 10, ", states: [OPEN, CLOSED, MERGED]"
    query = TOP_QUERY % (top_field, page_size, extra, fragment)
    out, after = [], None
    while True:
        data = gh.graphql(query, {"owner": owner, "name": name, "after": after})
        conn = data["repository"][top_field]
        for item in conn["nodes"]:
            if kind == "issues":
                complete_connection(gh, item, "Issue", "comments", COMMENT)
            else:
                complete_connection(gh, item, "PullRequest", "comments", COMMENT)
                complete_connection(gh, item, "PullRequest", "reviews", REVIEW)
                complete_connection(gh, item, "PullRequest", "reviewThreads", THREAD)
                for thread in item["reviewThreads"]:
                    complete_connection(gh, thread, "PullRequestReviewThread", "comments", THREAD_COMMENT)
            out.append(flatten(item))
        if not conn["pageInfo"]["hasNextPage"]:
            return out
        after = conn["pageInfo"]["endCursor"]


# ---- repo configuration ----------------------------------------------------

def optional(warnings: list, label: str, fn):
    """Call fn(); on 403/404/409/422 record a warning and return None."""
    try:
        return fn()
    except GitHubError as e:
        if e.status in (403, 404, 409, 410, 422):
            warnings.append(f"{label}: HTTP {e.status}")
            return None
        raise


def export_config(gh: GitHub, full: str, warnings: list) -> dict[str, object]:
    base = f"/repos/{full}"
    cfg: dict[str, object] = {"repository": gh.get(base)}

    rulesets = optional(warnings, "rulesets", lambda: gh.paginate(f"{base}/rulesets", {"includes_parents": "false"}))
    if rulesets is not None:
        details = [optional(warnings, f"ruleset {r['id']}", lambda r=r: gh.get(f"{base}/rulesets/{r['id']}"))
                   for r in rulesets]
        cfg["rulesets"] = [d for d in details if d is not None]

    branches = optional(warnings, "protected branches", lambda: gh.paginate(f"{base}/branches", {"protected": "true"}))
    if branches is not None:
        prot = {}
        for b in branches:
            q = urllib.parse.quote(b["name"], safe="")
            prot[b["name"]] = optional(warnings, f"branch protection {b['name']}",
                                       lambda q=q: gh.get(f"{base}/branches/{q}/protection"))
        cfg["branch-protection"] = prot

    simple = {
        "hooks": (f"{base}/hooks", None),
        "teams": (f"{base}/teams", None),
        "collaborators": (f"{base}/collaborators", None),
        "deploy-keys": (f"{base}/keys", None),
        "autolinks": (f"{base}/autolinks", None),
        "environments": (f"{base}/environments", "environments"),
        "actions-secrets": (f"{base}/actions/secrets", "secrets"),
        "actions-variables": (f"{base}/actions/variables", "variables"),
    }
    for key, (path, item_key) in simple.items():
        params = {"affiliation": "direct"} if key == "collaborators" else None
        value = optional(warnings, key, lambda p=path, ik=item_key, pr=params: gh.paginate(p, pr, ik))
        if value is not None:
            cfg[key] = value
    for key, path in {"custom-properties": f"{base}/properties/values",
                      "actions-permissions": f"{base}/actions/permissions"}.items():
        value = optional(warnings, key, lambda p=path: gh.get(p))
        if value is not None:
            cfg[key] = value
    return cfg


# ---- per repo ----------------------------------------------------------------

def export_repo(gh: GitHub, s3: S3, repo: dict) -> dict:
    started = time.time()
    owner, name = repo["full_name"].split("/", 1)
    result = {"node_id": repo["node_id"], "name": name, "status": "ok", "errors": [], "warnings": [],
              "destinations": repo["destinations"], "counts": {}, "files": {}}
    root = os.path.join(work_root(), "meta", safe_name(repo["node_id"]))
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, "metadata"))
    os.makedirs(os.path.join(root, "config"))
    try:
        issues = export_items(gh, owner, name, "issues")
        write_json_gz(issues, os.path.join(root, "metadata", "issues.json.gz"))
        pulls = export_items(gh, owner, name, "pulls")
        write_json_gz(pulls, os.path.join(root, "metadata", "pulls.json.gz"))
        labels = gh.paginate(f"/repos/{repo['full_name']}/labels")
        write_json_gz(labels, os.path.join(root, "metadata", "labels.json.gz"))
        milestones = gh.paginate(f"/repos/{repo['full_name']}/milestones", {"state": "all"})
        write_json_gz(milestones, os.path.join(root, "metadata", "milestones.json.gz"))
        releases = gh.paginate(f"/repos/{repo['full_name']}/releases")
        write_json_gz(releases, os.path.join(root, "metadata", "releases.json.gz"))
        result["counts"] = {"issues": len(issues), "pulls": len(pulls), "labels": len(labels),
                            "milestones": len(milestones), "releases": len(releases)}

        for key, value in export_config(gh, repo["full_name"], result["warnings"]).items():
            write_json(value, os.path.join(root, "config", f"{key}.json"))

        # Upload everything except release assets, which are streamed one by one.
        for sub in ("metadata", "config"):
            for fname in sorted(os.listdir(os.path.join(root, sub))):
                path = os.path.join(root, sub, fname)
                result["files"][f"{sub}/{fname}"] = {"size": os.path.getsize(path), "sha256": sha256_file(path)}
                for dest in repo["destinations"]:
                    s3.put_file(path, f"{dest}/{sub}/{fname}")

        if RELEASE_ASSETS:
            n_assets = 0
            for rel in releases:
                for asset in rel.get("assets", []):
                    tmp = os.path.join(root, "asset.bin")
                    gh.download(asset["url"], tmp)
                    rel_key = f"metadata/release-assets/{rel['id']}/{asset['id']}-{safe_name(asset['name'])}"
                    result["files"][rel_key] = {"size": os.path.getsize(tmp), "sha256": sha256_file(tmp)}
                    for dest in repo["destinations"]:
                        s3.put_file(tmp, f"{dest}/{rel_key}")
                    os.remove(tmp)
                    n_assets += 1
            result["counts"]["release_assets"] = n_assets
    except Exception as e:  # noqa: BLE001 - one repo must never stop the shard
        result["errors"].append(str(e)[-500:])
        result["status"] = "failed"
    finally:
        shutil.rmtree(root, ignore_errors=True)
    result["duration_s"] = round(time.time() - started, 1)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--shard", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    plan = load_json(args.plan)
    s3 = S3(env("BACKUP_S3_BUCKET"))
    gh = GitHub(auth_from_env(plan["org"]))
    repos = shard_repos(plan, args.shard)
    log(f"Shard {args.shard}: exporting metadata for {len(repos)} repositories.")
    results = {}

    def save() -> None:
        # Rewritten after every repo so a timed-out or crashed job keeps the
        # repos it finished (the upload step runs on always()).
        write_json({"kind": "metadata", "shard": args.shard, "finished_at": iso(utcnow()), "repos": results},
                   args.out)

    save()
    for i, repo in enumerate(repos, 1):
        log(f"[{i}/{len(repos)}] {repo['full_name']} ...")
        r = export_repo(gh, s3, repo)
        results[repo["node_id"]] = r
        save()
        level = gha_error if r["status"] == "failed" else log
        level(f"  {repo['name']}: {r['status']} {r['counts']} in {r['duration_s']}s"
              + (f" — {'; '.join(r['errors'])}" if r["errors"] else ""))


if __name__ == "__main__":
    main()

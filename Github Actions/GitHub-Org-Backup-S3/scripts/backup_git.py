#!/usr/bin/env python3
"""Back up the git data for one shard of the plan.

Per repository:
  1. `git clone --mirror` (all branches, tags, notes and GitHub's refs/pull/*)
  2. Git LFS objects (`git lfs fetch --all`)
  3. The wiki (`<repo>.wiki.git`) when the wiki is enabled and exists
  4. `git bundle create --all` + `git bundle verify` for repo and wiki
  5. Upload to every destination in the plan (weekly snapshot and/or the
     permanent archived-final copy), then delete the local copy

Uploaded under <destination>/git/:
  repo.bundle, wiki.bundle, lfs-objects.tar, refs.txt.gz, git-info.json

BACKUP_LFS:
  always (default)  run `git lfs fetch --all` on every repo. On a repo without
                    LFS this only scans history locally; nothing is downloaded.
  auto              only when some branch/tag/PR tip has `filter=lfs` in any
                    .gitattributes (faster, but misses LFS rules that exist only
                    in older commits)
  never             skip LFS
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import subprocess
import tarfile
import time

from common import (SERVER_URL, S3, TokenFile, auth_from_env, env, gha_error, gha_warning, git_auth_env, iso,
                    load_json, log, sha256_file, shard_repos, utcnow, work_root, write_json)

GIT_TIMEOUT_S = int(env("BACKUP_GIT_TIMEOUT_MIN", "120")) * 60
LFS_MODE = (env("BACKUP_LFS", "always") or "always").lower()
if LFS_MODE not in ("always", "auto", "never"):
    raise SystemExit(f"BACKUP_LFS must be always, auto or never (got {LFS_MODE!r})")


class StepError(Exception):
    pass


def git(args: list[str], cwd: str | None, tokens: TokenFile | None, timeout: int = GIT_TIMEOUT_S,
        check: bool = True, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(["git", *args], cwd=cwd, env=git_auth_env(tokens), capture_output=True,
                          timeout=timeout, input=input_bytes)
    if check and proc.returncode != 0:
        raise StepError(f"git {args[0]} failed: {proc.stderr.decode(errors='replace').strip()[-400:]}")
    return proc


def ref_listing(repo_dir: str) -> tuple[int, str, bytes]:
    out = git(["for-each-ref", "--format=%(objectname) %(refname)"], repo_dir, None).stdout
    lines = sorted(l for l in out.splitlines() if l.strip())
    blob = b"\n".join(lines) + (b"\n" if lines else b"")
    return len(lines), hashlib.sha256(blob).hexdigest(), blob


def uses_lfs(repo_dir: str) -> bool:
    if LFS_MODE == "always":
        return True
    if LFS_MODE == "never":
        return False
    # auto: any .gitattributes (root or nested) at any ref tip, incl. refs/pull/*
    tips = git(["for-each-ref", "--format=%(objectname)"], repo_dir, None).stdout.split()
    tips = sorted(set(t.decode() for t in tips))
    for i in range(0, len(tips), 500):  # keep argv small on repos with thousands of PR refs
        proc = git(["grep", "-l", "-I", "-e", "filter=lfs", *tips[i:i + 500], "--",
                    ".gitattributes", "*/.gitattributes"], repo_dir, None, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return True
    return False


LFS_MISSING_MARKERS = ("does not exist", "object not found", "404")
LFS_HARD_ERROR_MARKERS = ("401", "403", "unauthorized", "forbidden", "authentication", "rate limit",
                          "500", "502", "503", "504", "timeout", "timed out", "no space left",
                          "connection reset", "could not resolve")


def classify_lfs_fetch(proc: subprocess.CompletedProcess) -> tuple[str, str]:
    """Return ("ok" | "partial" | "failed", detail) for a `git lfs fetch --all`."""
    if proc.returncode == 0:
        return "ok", ""
    err = proc.stderr.decode(errors="replace")
    lower = err.lower()
    missing = [l for l in err.splitlines() if any(m in l.lower() for m in LFS_MISSING_MARKERS)]
    if missing and not any(m in lower for m in LFS_HARD_ERROR_MARKERS):
        return "partial", (f"{len(missing)} LFS object(s) referenced in history are missing on the server, "
                           f"e.g. {missing[0].strip()[:200]}")
    return "failed", f"git lfs fetch failed: {err.strip()[-400:]}"


def bundle(repo_dir: str, dest: str) -> None:
    git(["bundle", "create", dest, "--all"], repo_dir, None)
    git(["bundle", "verify", "--quiet", dest], repo_dir, None)


def tar_and_remove(src_dir: str, dest_tar: str, arc_root: str) -> int:
    """Tar src_dir, deleting each file once it's in the archive, so peak disk
    use is ~1x the LFS size instead of 2x. Returns the number of files."""
    count = 0
    with tarfile.open(dest_tar, "w") as tar:
        for dirpath, _, files in os.walk(src_dir):
            for name in sorted(files):
                path = os.path.join(dirpath, name)
                tar.add(path, arcname=os.path.join(arc_root, os.path.relpath(path, src_dir)))
                os.remove(path)
                count += 1
    return count


def backup_repo(repo: dict, tokens: TokenFile, s3: S3) -> dict:
    started = time.time()
    result = {"node_id": repo["node_id"], "name": repo["name"], "status": "ok", "errors": [], "warnings": [],
              "destinations": repo["destinations"], "files": {}, "lfs": "none", "wiki": "none"}
    root = os.path.join(work_root(), "git", repo["node_id"].replace("/", "_"))
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    mirror = os.path.join(root, "repo.git")
    out_dir = os.path.join(root, "out")
    os.makedirs(out_dir)
    url = f"{SERVER_URL}/{repo['full_name']}.git"
    try:
        # 1. mirror clone ------------------------------------------------------
        git(["clone", "--mirror", "--quiet", url, mirror], None, tokens)
        count, refs_hash, refs_blob = ref_listing(mirror)
        result.update(ref_count=count, refs_sha256=refs_hash)
        with gzip.open(os.path.join(out_dir, "refs.txt.gz"), "wb") as f:
            f.write(refs_blob)
        if count == 0:
            result["status"] = "empty"
        else:
            head = git(["rev-parse", "--verify", "--quiet", "HEAD"], mirror, None, check=False)
            result["head"] = head.stdout.decode().strip() or None
            # 4a. bundle the repository --------------------------------------
            bundle(mirror, os.path.join(out_dir, "repo.bundle"))

            # 2. LFS -----------------------------------------------------------
            if uses_lfs(mirror):
                proc = git(["lfs", "fetch", "--all", "origin"], mirror, tokens, check=False)
                outcome, detail = classify_lfs_fetch(proc)
                lfs_dir = os.path.join(mirror, "lfs", "objects")
                n = 0
                if os.path.isdir(lfs_dir) and any(files for _, _, files in os.walk(lfs_dir)):
                    n = tar_and_remove(lfs_dir, os.path.join(out_dir, "lfs-objects.tar"), "lfs/objects")
                if outcome == "failed":
                    result["lfs"] = "failed"
                    result["errors"].append(f"lfs: {detail}")
                elif outcome == "partial":
                    # Objects referenced somewhere in history (often a fork's PR)
                    # that GitHub's LFS store doesn't have. Nothing more to fetch,
                    # so don't fail the repo every week over it.
                    result.update(lfs="partial", lfs_objects=n)
                    result["warnings"].append(f"lfs: {detail}")
                else:
                    result.update(lfs="ok" if n else "none-found", lfs_objects=n)
            shutil.rmtree(mirror, ignore_errors=True)  # free disk before the wiki

        # 3. wiki ---------------------------------------------------------------
        if repo.get("has_wiki"):
            wiki = os.path.join(root, "wiki.git")
            wiki_url = f"{SERVER_URL}/{repo['full_name']}.wiki.git"
            proc = None
            for attempt in range(2):  # one retry so a transient error isn't mistaken for "no wiki"
                shutil.rmtree(wiki, ignore_errors=True)
                proc = git(["clone", "--mirror", "--quiet", wiki_url, wiki], None, tokens, check=False)
                if proc.returncode == 0:
                    break
                time.sleep(5)
            err = proc.stderr.decode(errors="replace")
            if proc.returncode == 0:
                wcount, whash, _ = ref_listing(wiki)
                if wcount:
                    bundle(wiki, os.path.join(out_dir, "wiki.bundle"))
                    result.update(wiki="ok", wiki_ref_count=wcount, wiki_refs_sha256=whash)
                else:
                    result["wiki"] = "empty"
            elif "not found" in err.lower() or "not exist" in err.lower():
                # GitHub answers "Repository not found" both for a wiki that is
                # enabled but has no pages and for an access problem.
                if repo.get("visibility") == "PUBLIC":
                    # Public wikis can be checked without a token.
                    probe = git(["ls-remote", wiki_url], None, None, check=False, timeout=120)
                    if probe.returncode == 0:
                        result["wiki"] = "failed"
                        result["errors"].append("wiki: exists (readable anonymously) but the App token "
                                                "was refused")
                    else:
                        result["wiki"] = "none"  # confirmed: no pages
                else:
                    # Can't confirm for private/internal repos; finalize checks
                    # whether the run proved the token can read private wikis.
                    result["wiki"] = "not-found-unverified"
                    result["warnings"].append("wiki enabled but not found (no pages, or not readable "
                                              "with the App token)")
            else:
                result["wiki"] = "failed"
                result["errors"].append(f"wiki: {err.strip()[-300:]}")
        else:
            result["wiki"] = "disabled"

        # 5. upload ---------------------------------------------------------------
        for name in sorted(os.listdir(out_dir)):
            path = os.path.join(out_dir, name)
            result["files"][name] = {"size": os.path.getsize(path), "sha256": sha256_file(path)}
        info = {k: v for k, v in result.items() if k not in ("errors", "destinations")}
        info.update(full_name=repo["full_name"], backed_up_at=iso(utcnow()), git_version=_git_version())
        write_json(info, os.path.join(out_dir, "git-info.json"))
        for dest in repo["destinations"]:
            for name in sorted(os.listdir(out_dir)):
                s3.put_file(os.path.join(out_dir, name), f"{dest}/git/{name}")
    except subprocess.TimeoutExpired:
        result["errors"].append(f"git timed out after {GIT_TIMEOUT_S // 60} min")
    except Exception as e:  # noqa: BLE001 - one repo must never stop the shard
        result["errors"].append(str(e)[-500:])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if result["errors"]:
        result["status"] = "failed"
    result["duration_s"] = round(time.time() - started, 1)
    return result


_GIT_VERSION = None


def _git_version() -> str:
    global _GIT_VERSION
    if _GIT_VERSION is None:
        _GIT_VERSION = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.strip()
    return _GIT_VERSION


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--shard", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    plan = load_json(args.plan)
    s3 = S3(env("BACKUP_S3_BUCKET"))
    auth = auth_from_env(plan["org"])
    tokens = TokenFile(auth)  # mints the first token now: fails fast on bad App credentials
    subprocess.run(["git", "lfs", "install", "--skip-repo"], capture_output=True)

    repos = shard_repos(plan, args.shard)
    log(f"Shard {args.shard}: {len(repos)} repositories (LFS mode: {LFS_MODE}).")
    results = {}

    def save() -> None:
        # Rewritten after every repo, so if the job times out or crashes the
        # repos that already finished still count (the upload step runs on always()).
        write_json({"kind": "git", "shard": args.shard, "finished_at": iso(utcnow()), "repos": results}, args.out)

    save()
    try:
        for i, repo in enumerate(repos, 1):
            free_gb = shutil.disk_usage(work_root()).free / 1e9
            need_gb = (repo.get("diskUsage") or 0) / 1e6 * 2.5  # mirror + bundle + headroom
            if need_gb > free_gb:
                gha_warning(f"{repo['name']}: git data alone needs ~{need_gb:.1f} GB but only {free_gb:.1f} GB "
                            "is free (LFS objects not included in the estimate); consider a larger runner "
                            "(BACKUP_RUNNER).")
            log(f"[{i}/{len(repos)}] {repo['full_name']} ({repo['action']}) ...")
            r = backup_repo(repo, tokens, s3)
            results[repo["node_id"]] = r
            save()
            level = gha_error if r["status"] == "failed" else log
            level(f"  {repo['name']}: {r['status']} in {r['duration_s']}s"
                  + (f" — {'; '.join(r['errors'])}" if r["errors"] else ""))
            for w in r["warnings"]:
                gha_warning(f"{repo['name']}: {w}")
    finally:
        tokens.close()

    save()
    failed = sum(1 for r in results.values() if r["status"] == "failed")
    log(f"Shard {args.shard} done: {len(results) - failed} ok, {failed} failed.")


if __name__ == "__main__":
    main()

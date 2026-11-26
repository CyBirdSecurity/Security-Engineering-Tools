"""Shared helpers for the GitHub org -> S3 backup scripts.

Standard library only (plus the `git`, `git-lfs`, `openssl` and `aws` CLIs that
are preinstalled on GitHub-hosted Ubuntu runners), so the scripts can be copied
into any repo without a requirements file.

Contents:
  * GitHub App authentication that re-mints installation tokens before their
    1-hour expiry (long shards outlive a single token).
  * REST + GraphQL clients with pagination and primary/secondary rate-limit
    handling.
  * A thin S3 wrapper around the AWS CLI (or a local directory for testing).
  * Small utilities: logging, hashing, gzip JSON, results files.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
GRAPHQL_URL = os.environ.get("GITHUB_GRAPHQL_URL", API_URL + "/graphql")
SERVER_URL = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
USER_AGENT = "github-org-backup-s3"


# --------------------------------------------------------------------------
# Logging / small utilities
# --------------------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def gha_warning(msg: str) -> None:
    """Emit a GitHub Actions warning annotation (plain log line elsewhere)."""
    print(f"::warning::{_escape_annotation(msg)}", flush=True)


def gha_error(msg: str) -> None:
    print(f"::error::{_escape_annotation(msg)}", flush=True)


def _escape_annotation(msg: str) -> str:
    return msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def mask(value: str) -> None:
    """Ask the Actions runner to redact a value from all subsequent logs."""
    if value and os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{value}", flush=True)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def compact_ts(value: str) -> str:
    """'2026-11-26T03:17:00Z' -> '20261126T031700Z' (safe for S3 keys)."""
    return re.sub(r"[^0-9TZ]", "", value)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json_gz(obj, path: str) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)


def write_json(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=True)


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(name, "")
    if value == "":
        if required:
            raise SystemExit(f"Missing required configuration: {name}")
        return default
    return value


def safe_name(value: str) -> str:
    """Make a string safe to use as one S3 key / file name segment."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:200] or "_"


def gha_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")
    else:
        log(f"[output] {name}={value}")


def gha_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(markdown + "\n")
    else:
        log(markdown)


def work_root() -> str:
    root = os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "org-backup")
    os.makedirs(root, exist_ok=True)
    return root


# --------------------------------------------------------------------------
# GitHub authentication
# --------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class GitHubError(Exception):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status} for {url}: {message}")
        self.status = status
        self.message = message
        self.url = url


def _raw_json_request(method: str, url: str, headers: dict, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", USER_AGENT)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        raise GitHubError(e.code, e.read().decode(errors="replace")[:500], url) from None


class AppAuth:
    """GitHub App installation token that refreshes itself.

    The JWT is signed with the `openssl` CLI so no third-party crypto library
    is needed. Installation tokens last 60 minutes; we re-mint when fewer than
    10 minutes remain.
    """

    REFRESH_MARGIN_S = 600

    def __init__(self, app_id: str, private_key_pem: str, org: str):
        self.app_id = app_id
        self.org = org
        self._installation_id: int | None = None
        self._token: str | None = None
        self._expires_at = 0.0
        fd, self._key_path = tempfile.mkstemp(prefix="app-key-", suffix=".pem", dir=work_root())
        with os.fdopen(fd, "w") as f:
            f.write(private_key_pem.replace("\\n", "\n").strip() + "\n")
        os.chmod(self._key_path, 0o600)

    def __del__(self):
        try:
            os.remove(self._key_path)
        except Exception:
            pass

    def _jwt(self) -> str:
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(self.app_id)}).encode())
        signing_input = f"{header}.{payload}".encode()
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self._key_path],
            input=signing_input, capture_output=True, check=False,
        )
        if proc.returncode != 0:
            raise SystemExit("Could not sign GitHub App JWT - is BACKUP_APP_PRIVATE_KEY a valid PEM private key?")
        return f"{header}.{payload}.{_b64url(proc.stdout)}"

    def token(self, force: bool = False) -> str:
        if not force and self._token and self._expires_at - time.time() > self.REFRESH_MARGIN_S:
            return self._token
        jwt = self._jwt()
        auth = {"Authorization": f"Bearer {jwt}"}
        if self._installation_id is None:
            inst = _raw_json_request("GET", f"{API_URL}/orgs/{self.org}/installation", auth)
            self._installation_id = inst["id"]
        data = _raw_json_request("POST", f"{API_URL}/app/installations/{self._installation_id}/access_tokens", auth, {})
        self._token = data["token"]
        mask(self._token)
        expires = parse_iso(data.get("expires_at"))
        self._expires_at = expires.timestamp() if expires else time.time() + 3600
        log(f"Minted GitHub App installation token (expires {data.get('expires_at')})")
        return self._token


class StaticAuth:
    """A fixed token (e.g. GITHUB_TOKEN for issue reporting, or a PAT for local testing)."""

    def __init__(self, token: str | None):
        self._token = token or ""
        mask(self._token)

    def token(self, force: bool = False) -> str:
        return self._token


def auth_from_env(org: str):
    app_id = env("BACKUP_APP_ID")
    key = env("BACKUP_APP_PRIVATE_KEY")
    if app_id and key:
        return AppAuth(app_id, key, org)
    token = env("BACKUP_GH_TOKEN")
    if token:
        log("Using BACKUP_GH_TOKEN instead of a GitHub App (intended for local testing).")
        return StaticAuth(token)
    if env("BACKUP_ANONYMOUS") == "1":
        log("BACKUP_ANONYMOUS=1: making unauthenticated requests (public repos only, local testing).")
        return StaticAuth("")
    raise SystemExit("Set BACKUP_APP_ID and BACKUP_APP_PRIVATE_KEY (GitHub App credentials).")


# --------------------------------------------------------------------------
# GitHub REST / GraphQL client
# --------------------------------------------------------------------------

class GitHub:
    MAX_ATTEMPTS = 8

    def __init__(self, auth):
        self.auth = auth

    # ---- low level -------------------------------------------------------
    def _headers(self, accept: str) -> dict:
        h = {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        tok = self.auth.token()
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        return h

    def _sleep_for_rate_limit(self, status: int, headers, body: str, attempt: int) -> bool:
        """Return True if the response was a rate limit and we slept."""
        remaining = headers.get("x-ratelimit-remaining")
        retry_after = headers.get("retry-after")
        if status in (403, 429) and remaining == "0":
            reset = int(headers.get("x-ratelimit-reset", time.time() + 60))
            wait = max(5, reset - int(time.time()) + 5)
            log(f"Primary rate limit exhausted; sleeping {wait}s until reset.")
            time.sleep(wait)
            return True
        if status in (403, 429) and (retry_after or "secondary rate limit" in body.lower()):
            wait = int(retry_after) if retry_after and retry_after.isdigit() else min(60 * (attempt + 1), 600)
            log(f"Secondary rate limit; sleeping {wait}s.")
            time.sleep(wait)
            return True
        return False

    def request(self, method: str, path: str, params: dict | None = None, body=None,
                accept: str = "application/vnd.github+json", ok_missing: bool = False):
        """Return (status, json_or_None, headers). Raises GitHubError on failure.

        With ok_missing=True a 404 returns (404, None, headers) instead of raising.
        """
        url = path if path.startswith("http") else f"{API_URL}{path}"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        # A POST that timed out or got a 5xx may already have been applied
        # (e.g. an issue created), so only retry calls that are safe to repeat.
        # GraphQL queries are POSTs but read-only. Rate-limited calls are
        # always retried: GitHub rejected them before doing anything.
        retry_errors = method in ("GET", "HEAD", "PUT", "PATCH", "DELETE") or url == GRAPHQL_URL
        refreshed = False
        for attempt in range(self.MAX_ATTEMPTS):
            req = urllib.request.Request(url, data=data, method=method)
            for k, v in self._headers(accept).items():
                req.add_header(k, v)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    raw = resp.read()
                    return resp.status, (json.loads(raw) if raw else None), resp.headers
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                if e.code == 404 and ok_missing:
                    return 404, None, e.headers
                if e.code == 401 and not refreshed:
                    refreshed = True
                    self.auth.token(force=True)
                    continue
                if self._sleep_for_rate_limit(e.code, e.headers, text, attempt):
                    continue
                if e.code >= 500 and retry_errors:
                    time.sleep(min(2 ** attempt + random.random(), 120))
                    continue
                raise GitHubError(e.code, text[:500], url) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if not retry_errors:
                    raise GitHubError(0, f"network error, not retried for {method}: {e}", url) from None
                log(f"Network error on {method} {url}: {e}; retrying.")
                time.sleep(min(2 ** attempt + random.random(), 120))
        raise GitHubError(0, "gave up after repeated errors", url)

    # ---- REST helpers ----------------------------------------------------
    def get(self, path: str, params: dict | None = None, ok_missing: bool = False):
        return self.request("GET", path, params=params, ok_missing=ok_missing)[1]

    def paginate(self, path: str, params: dict | None = None, item_key: str | None = None) -> list:
        """Follow Link: rel="next". item_key is for endpoints that wrap the list
        in an object (e.g. {"total_count": n, "secrets": [...]})."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        url = f"{API_URL}{path}?{urllib.parse.urlencode(params)}"
        items: list = []
        while url:
            _, data, headers = self.request("GET", url)
            if item_key:
                items.extend((data or {}).get(item_key, []))
            else:
                items.extend(data or [])
            url = _next_link(headers.get("link", ""))
        return items

    # ---- GraphQL -----------------------------------------------------------
    def graphql(self, query: str, variables: dict | None = None) -> dict:
        for attempt in range(self.MAX_ATTEMPTS):
            _, data, headers = self.request("POST", GRAPHQL_URL, body={"query": query, "variables": variables or {}})
            errors = (data or {}).get("errors")
            if not errors:
                return data["data"]
            if any(err.get("type") == "RATE_LIMITED" for err in errors):
                reset = int(headers.get("x-ratelimit-reset", time.time() + 60))
                wait = max(5, reset - int(time.time()) + 5)
                log(f"GraphQL rate limited; sleeping {wait}s.")
                time.sleep(wait)
                continue
            # Transient "Something went wrong" / timeouts: back off and retry.
            if any("timeout" in (err.get("message") or "").lower() or err.get("type") == "INTERNAL"
                   for err in errors):
                time.sleep(min(2 ** attempt + random.random(), 120))
                continue
            raise GitHubError(200, json.dumps(errors)[:500], GRAPHQL_URL)
        raise GitHubError(0, "GraphQL gave up after repeated errors", GRAPHQL_URL)

    # ---- binary download ---------------------------------------------------
    def download(self, url: str, dest: str, accept: str = "application/octet-stream") -> None:
        for attempt in range(5):
            req = urllib.request.Request(url, method="GET")
            req.add_header("Accept", accept)
            req.add_header("User-Agent", USER_AGENT)
            tok = self.auth.token()
            if tok:
                # Not forwarded to the pre-signed redirect target.
                req.add_unredirected_header("Authorization", f"Bearer {tok}")
            try:
                with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as out:
                    shutil.copyfileobj(resp, out, 1024 * 1024)
                return
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                if self._sleep_for_rate_limit(e.code, e.headers, text, attempt):
                    continue  # rate limited: retry after the advised wait
                if e.code < 500:
                    # permission / not found: retrying won't help
                    raise GitHubError(e.code, text[:300], url) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                log(f"Download error for {url}: {e}")
            time.sleep(min(2 ** attempt * 5, 120))
        raise GitHubError(0, "download failed repeatedly", url)


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        m = re.match(r'\s*<([^>]+)>;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------
# S3 (via AWS CLI) - or a local directory when BACKUP_LOCAL_DIR is set
# --------------------------------------------------------------------------

class S3:
    def __init__(self, bucket: str | None):
        self.local_dir = env("BACKUP_LOCAL_DIR")
        self.bucket = bucket
        if not self.local_dir and not bucket:
            raise SystemExit("Missing required configuration: BACKUP_S3_BUCKET")
        if not self.local_dir and not shutil.which("aws"):
            raise SystemExit("The AWS CLI is required (preinstalled on GitHub-hosted runners).")

    def _run(self, args: list[str], input_bytes: bytes | None = None, attempts: int = 4):
        last = None
        for attempt in range(attempts):
            proc = subprocess.run(["aws", *args], input=input_bytes, capture_output=True)
            if proc.returncode == 0:
                return proc
            last = proc
            err = proc.stderr.decode(errors="replace")
            if any(s in err for s in ("(404)", "NoSuchKey", "Not Found", "(403)", "AccessDenied")):
                break  # not transient
            time.sleep(2 ** attempt * 3)
        return last

    def put_file(self, local_path: str, key: str) -> None:
        if self.local_dir:
            dest = os.path.join(self.local_dir, key)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(local_path, dest)
            return
        # Object Lock buckets require an integrity checksum on every PUT;
        # --checksum-algorithm also makes S3 verify the upload end to end.
        proc = self._run([
            "s3", "cp", local_path, f"s3://{self.bucket}/{key}",
            "--checksum-algorithm", "SHA256", "--only-show-errors", "--no-progress",
        ])
        if proc.returncode != 0:
            raise RuntimeError(f"S3 upload failed for {key}: {proc.stderr.decode(errors='replace')[-500:]}")

    def put_json(self, obj, key: str) -> None:
        fd, tmp = tempfile.mkstemp(suffix=".json", dir=work_root())
        os.close(fd)
        try:
            write_json(obj, tmp)
            self.put_file(tmp, key)
        finally:
            os.remove(tmp)

    def get_json(self, key: str):
        """Return parsed JSON, or None if the object does not exist."""
        if self.local_dir:
            path = os.path.join(self.local_dir, key)
            return load_json(path) if os.path.exists(path) else None
        proc = self._run(["s3", "cp", f"s3://{self.bucket}/{key}", "-", "--only-show-errors"])
        if proc.returncode == 0:
            return json.loads(proc.stdout or b"null")
        err = proc.stderr.decode(errors="replace")
        if "(404)" in err or "NoSuchKey" in err or "Not Found" in err:
            return None
        if ("(403)" in err or "AccessDenied" in err or "Forbidden" in err) and not self._exists(key):
            # S3 answers 403 instead of 404 for a missing key unless the caller
            # has unconditional ListBucket; the roles only get prefix-scoped
            # listing, so confirm with an explicit list.
            return None
        raise RuntimeError(f"Could not read s3://{self.bucket}/{key}: {err[-500:]}")

    def _exists(self, key: str) -> bool:
        proc = self._run(["s3api", "list-objects-v2", "--bucket", self.bucket, "--prefix", key,
                          "--max-items", "1", "--output", "json"])
        if proc.returncode != 0:
            raise RuntimeError(f"Could not list s3://{self.bucket}/{key}: "
                               f"{proc.stderr.decode(errors='replace')[-500:]}")
        data = json.loads(proc.stdout or b"{}")
        return any(o.get("Key") == key for o in data.get("Contents", []))

    def get_file(self, key: str, dest: str) -> None:
        if self.local_dir:
            shutil.copyfile(os.path.join(self.local_dir, key), dest)
            return
        proc = self._run(["s3", "cp", f"s3://{self.bucket}/{key}", dest, "--only-show-errors", "--no-progress"])
        if proc.returncode != 0:
            raise RuntimeError(f"S3 download failed for {key}: {proc.stderr.decode(errors='replace')[-500:]}")

    def list_prefixes(self, prefix: str) -> list[str]:
        """Immediate 'sub-directories' under prefix (which should end in '/')."""
        if self.local_dir:
            path = os.path.join(self.local_dir, prefix)
            if not os.path.isdir(path):
                return []
            return sorted(prefix + d + "/" for d in os.listdir(path) if os.path.isdir(os.path.join(path, d)))
        out: list[str] = []
        token = None
        while True:
            args = ["s3api", "list-objects-v2", "--bucket", self.bucket, "--prefix", prefix,
                    "--delimiter", "/", "--output", "json", "--max-items", "1000"]
            if token:
                args += ["--starting-token", token]
            proc = self._run(args)
            if proc.returncode != 0:
                raise RuntimeError(f"S3 list failed for {prefix}: {proc.stderr.decode(errors='replace')[-500:]}")
            data = json.loads(proc.stdout or b"{}")
            out += [p["Prefix"] for p in data.get("CommonPrefixes", [])]
            token = data.get("NextToken")
            if not token:
                return sorted(out)


# --------------------------------------------------------------------------
# Backup layout (one place, so every script agrees on key names)
# --------------------------------------------------------------------------

class Layout:
    """
    <prefix>/snapshots/<org>/<snapshot_id>/repos/<repo>/...      weekly snapshots
    <prefix>/snapshots/<org>/<snapshot_id>/manifest.json         written last
    <prefix>/archived-final/<org>/<repo_node_id>/<archived_at>/<snapshot_id>/  permanent final copies
    <prefix>/state/<org>/archive-tracker.json                    archive bookkeeping
    <prefix>/state/<org>/last-run.json | last-success.json       run markers
    """

    def __init__(self, prefix: str, org: str):
        self.prefix = prefix.strip("/")
        self.org = org

    def snapshot_root(self, snapshot_id: str) -> str:
        return f"{self.prefix}/snapshots/{self.org}/{snapshot_id}"

    def snapshot_repo(self, snapshot_id: str, repo_name: str) -> str:
        return f"{self.snapshot_root(snapshot_id)}/repos/{safe_name(repo_name)}"

    def final_copy(self, node_id: str, archived_at: str, snapshot_id: str) -> str:
        # One sub-folder per run: a later run that fails halfway can never mix
        # its files into a final copy that an earlier, successful run wrote.
        return (f"{self.prefix}/archived-final/{self.org}/{safe_name(node_id)}/{compact_ts(archived_at)}/"
                f"{safe_name(snapshot_id)}")

    def state(self, name: str) -> str:
        return f"{self.prefix}/state/{self.org}/{name}"


def layout_from_env() -> Layout:
    return Layout(env("BACKUP_S3_PREFIX", "github-backup"), env("BACKUP_ORG", required=True))


# --------------------------------------------------------------------------
# Plan / results helpers
# --------------------------------------------------------------------------

def shard_repos(plan: dict, shard: int) -> list[dict]:
    return [r for r in plan["repos"] if r.get("shard") == shard and r["action"] != "skip"]


def run_url() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    return f"{SERVER_URL}/{repo}/actions/runs/{run_id}" if repo and run_id else "(local run)"


class TokenFile:
    """Keeps a current installation token in a 0600 file, refreshed by a
    background thread, for git's credential helper to read.

    A static header would expire mid-command: installation tokens live 60
    minutes, while one `git lfs fetch --all` can run longer. git-lfs asks the
    credential helper again after a 401, so it picks up the refreshed token.
    """

    REFRESH_EVERY_S = 300

    def __init__(self, auth):
        import threading
        self.auth = auth
        fd, self.path = tempfile.mkstemp(prefix="gh-token-", dir=work_root())
        os.close(fd)
        os.chmod(self.path, 0o600)
        self._write()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _write(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.auth.token())
        os.replace(tmp, self.path)  # atomic: the helper never reads a half-written file

    def _loop(self) -> None:
        while not self._stop.wait(self.REFRESH_EVERY_S):
            try:
                self._write()
            except Exception as e:  # noqa: BLE001 - keep the last good token
                log(f"Token refresh failed (will retry): {e}")

    def has_token(self) -> bool:
        return bool(self.auth.token())

    def close(self) -> None:
        self._stop.set()
        try:
            os.remove(self.path)
        except OSError:
            pass


def git_auth_env(token_file: TokenFile | None) -> dict:
    """Environment that makes git and git-lfs authenticate to github.com via a
    credential helper reading the always-current token file. The token never
    appears in a URL, a config file or argv."""
    e = dict(os.environ)
    e["GIT_TERMINAL_PROMPT"] = "0"
    e["GIT_LFS_SKIP_SMUDGE"] = "1"
    if token_file and token_file.has_token():
        helper = ("!f() { test \"$1\" = get || exit 0; echo username=x-access-token; "
                  f"printf 'password=%s\\n' \"$(cat '{token_file.path}')\"; }}; f")
        scope = f"credential.{SERVER_URL}"
        pairs = [(f"{scope}.helper", ""),        # drop any inherited helpers for github.com
                 (f"{scope}.helper", helper)]
        e["GIT_CONFIG_COUNT"] = str(len(pairs))
        for i, (k, v) in enumerate(pairs):
            e[f"GIT_CONFIG_KEY_{i}"] = k
            e[f"GIT_CONFIG_VALUE_{i}"] = v
    return e


# --------------------------------------------------------------------------
# Failure issues (shared by finalize and the restore drill)
# --------------------------------------------------------------------------

def report_issue(failed: bool, label: str, title: str, body: str) -> None:
    """Open/comment on a single tracking issue when failed; close it when a
    later run succeeds. Uses the workflow's GITHUB_TOKEN (issues: write)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not repo or not token:
        log("GITHUB_REPOSITORY/GITHUB_TOKEN not set; skipping issue reporting.")
        return
    gh = GitHub(StaticAuth(token))
    open_issues = gh.get(f"/repos/{repo}/issues", {"labels": label, "state": "open", "per_page": 10}) or []
    open_issues = [i for i in open_issues if "pull_request" not in i]
    if failed:
        if gh.request("GET", f"/repos/{repo}/labels/{urllib.parse.quote(label)}", ok_missing=True)[0] == 404:
            gh.request("POST", f"/repos/{repo}/labels",
                       body={"name": label, "color": "b60205", "description": "Automated backup failure"})
        if open_issues:
            num = open_issues[0]["number"]
            gh.request("POST", f"/repos/{repo}/issues/{num}/comments", body={"body": body})
            log(f"Commented on existing issue #{num}.")
        else:
            created = gh.request("POST", f"/repos/{repo}/issues",
                                 body={"title": title, "body": body, "labels": [label]})[1]
            log(f"Opened issue #{created['number']}.")
    else:
        for issue in open_issues:
            num = issue["number"]
            gh.request("POST", f"/repos/{repo}/issues/{num}/comments",
                       body={"body": f"Resolved: a later run succeeded.\n\n{run_url()}"})
            gh.request("PATCH", f"/repos/{repo}/issues/{num}", body={"state": "closed", "state_reason": "completed"})
            log(f"Closed issue #{num}.")

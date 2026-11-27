# GitHub Org Backup to S3

A GitHub Actions workflow that takes **weekly, immutable backups of every
repository in a GitHub organization** into an S3 bucket protected by Object
Lock. It's built to be copied: nothing in the workflow is org-specific — all
settings come from repository variables, one environment secret, and a
Terraform example (or the manual AWS steps below).

> **Status:** template. Read the security model and test with a filtered run
> before relying on it. Terraform and the workflows have not been applied
> against a live org/account by the authors of this template — validate with
> `terraform plan` and `actionlint` in your own environment.

## Contents
- [What gets backed up](#what-gets-backed-up)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Setup](#setup)
  1. [Create the backup repository](#1-create-the-backup-repository)
  2. [AWS: bucket, key and roles](#2-aws-bucket-key-and-roles) (Terraform **or** manual)
  3. [Create the GitHub App](#3-create-the-github-app)
  4. [Environments, secret and variables](#4-environments-secret-and-variables)
  5. [First runs](#5-first-runs)
- [The archived-repo filter](#the-archived-repo-filter)
- [Failure alerts](#failure-alerts)
- [Sizing and tuning (≈400 repos)](#sizing-and-tuning-400-repos)
- [Cost estimate](#cost-estimate)
- [Limitations](#limitations)
- [Maintenance](#maintenance)
- [Restoring](#restoring) → see [`RESTORE.md`](RESTORE.md)

## What gets backed up

| Data | How | Where (per repo) |
|---|---|---|
| Git history — all branches, tags, notes and GitHub's `refs/pull/*` | `git clone --mirror` → `git bundle create --all` → `git bundle verify` | `git/repo.bundle`, `git/refs.txt.gz` |
| Git LFS objects | `git lfs fetch --all` on every repo (repos without LFS download nothing) | `git/lfs-objects.tar` |
| Wiki | mirror of `<repo>.wiki.git` | `git/wiki.bundle` |
| Issues + comments | GraphQL | `metadata/issues.json.gz` |
| Pull requests + comments, reviews, review threads/comments | GraphQL | `metadata/pulls.json.gz` |
| Labels, milestones, releases | REST | `metadata/*.json.gz` |
| Release asset binaries | REST (optional, on by default) | `metadata/release-assets/…` |
| Repo config — settings, rulesets, branch protection, webhooks, teams, collaborators, deploy keys, autolinks, environments, custom properties, Actions permissions, Actions secret **names**, Actions variables | REST | `config/*.json` |

Every file's size and SHA-256 are recorded in the snapshot's `manifest.json`,
and every upload is checksummed by S3 (`--checksum-algorithm SHA256`).

The goal is recovering repositories — code, history and their surrounding
data — if they're deleted and can't be recovered from GitHub. **Org-level
settings** (teams, membership, org rulesets, org webhooks and policies) are
intentionally out of scope.

**Not included:** org-level settings (above), secret *values* (GitHub never returns them), issue/PR
timeline events (label changes, assignments, cross-references), files
attached inside issue/PR comment bodies, Discussions, Projects, Packages,
Actions logs/artifacts, Codespaces, and Dependabot/code-scanning alerts.

## How it works

```
weekly cron / manual run
        │
        ▼
 discover ─── lists all repos (GraphQL), applies the archived-repo filter,
        │     size-balances them into N shards, uploads plan.json
        ├──► backup-git        (matrix, N shards)   mirror → LFS → wiki → bundle → verify → S3
        ├──► backup-metadata   (matrix, N shards)   issues/PRs/releases + repo config → S3
        ▼
 finalize (always runs) ─ manifest.json (written last = "snapshot complete"),
                          archive tracker, last-run/last-success markers,
                          open / comment / close the `backup-failure` issue
```

S3 layout (prefix defaults to `github-backup`):

```
github-backup/snapshots/<org>/<snapshot_id>/repos/<repo>/{git,metadata,config}/…
github-backup/snapshots/<org>/<snapshot_id>/manifest.json
github-backup/archived-final/<org>/<repo_node_id>/<archived_at>/<snapshot_id>/{git,metadata,config}/…
github-backup/state/<org>/{archive-tracker.json,last-run.json,last-success.json}
```

`snapshot_id` is the UTC start time, e.g. `2026-11-29T031712Z`. Final copies
are keyed by the repo's immutable node ID, so renames don't break them. Each
run writes into its own `<snapshot_id>` folder, so a later run that fails
can't mix files into a good copy. The archive tracker records which folder
holds the last complete one.

## Security model

| Control | What it protects against |
|---|---|
| **Read-only GitHub App** with short-lived tokens, re-minted per job and before expiry | No long-lived PAT, no person's account; the App can't change anything in your org |
| **GitHub OIDC → IAM role**, trusted only for `repo:<owner>/<backup-repo>:environment:backup` | No stored AWS keys; other repos/branches can't assume the role |
| Backup role can **only `PutObject`** — deletes, retention changes, governance bypass and bucket changes are explicitly denied | A compromised workflow can add junk but can't destroy backups |
| **S3 Object Lock (GOVERNANCE, 90 days)** + versioning | Ransomware / mistaken deletes; overwrites create new versions, old ones stay locked |
| Bucket policy denies `BypassGovernanceRetention` to everyone except named break-glass principals; TLS-only | An AWS admin can't casually purge locked data |
| **SSE-KMS** customer-managed key (rotation on, `prevent_destroy`) | Encryption at rest with auditable key use |
| Separate **read-only restore role** for drills/restores | Restores never need write credentials |
| Git token sent as an HTTP header via `GIT_CONFIG_*` env vars, never in URLs/argv; `::add-mask::` on every token | Token leakage into logs or process listings |
| All actions **pinned to commit SHAs**; `permissions: {}` by default, per-job least privilege | Supply-chain and token-scope risk |

Recommended: put the bucket in a **dedicated backup AWS account**, and make
the backup repo private with a protected default branch so nobody can alter
the workflow without review.

> **COMPLIANCE vs GOVERNANCE:** this template defaults to GOVERNANCE so you
> can clean up test data. Once you trust it, consider `object_lock_mode =
> "COMPLIANCE"`: then nobody — including the AWS root user — can delete a
> version before its retention ends. That applies to new objects only and is
> irreversible per object.

## Setup

### 1. Create the backup repository

Create a **private** repository (for example `org-backup`) in the org and copy
the files in this layout:

```
.github/workflows/github-org-backup.yml                ← GitHub-Org-Backup-S3.yml
.github/workflows/github-org-backup-restore-drill.yml  ← GitHub-Org-Backup-S3-Restore-Drill.yml
.github/org-backup/scripts/*.py                        ← scripts/
```

(The Terraform and tests can live anywhere — they aren't used by the workflow.)
If you want a different scripts path, change the `SCRIPTS` env value at the
top of both workflows.

Protect the default branch (require PR review) — the IAM role trusts any job
in the `backup` environment, and step 4 limits that environment to the
default branch.

### 2. AWS: bucket, key and roles

Pick **one** of the two options. Both produce the same resources.

#### Option A — Terraform (recommended)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in the four required values
terraform init
terraform plan
terraform apply
terraform output github_variables               # values for step 4
```

Set `create_oidc_provider = false` if the account already has the
`token.actions.githubusercontent.com` OIDC provider. Set
`enable_freshness_alarm = true` + `alarm_email` for the optional "no
successful backup in 8 days" email (see [Failure alerts](#failure-alerts)).

The bucket and KMS key have `prevent_destroy`; `terraform destroy` will refuse
by design.

#### Option B — Manual (console or AWS CLI)

Replace `BUCKET`, `REGION`, `ACCOUNT_ID`, `OWNER` (case-sensitive owner of the
backup repo), `REPO` (backup repo name) and `PREFIX` (default
`github-backup`) below.

**B1. KMS key** — KMS → *Create key* → symmetric, encrypt/decrypt, alias
`github-org-backup`, enable automatic rotation. Keep the default key policy
(account root can delegate via IAM). Note the key ARN as `KEY_ARN`.

**B2. Bucket with Object Lock** (Object Lock must be chosen at creation):

```bash
aws s3api create-bucket --bucket BUCKET --region REGION \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=REGION   # omit this line for us-east-1

aws s3api put-object-lock-configuration --bucket BUCKET --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":90}}}'

aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-ownership-controls --bucket BUCKET \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'

aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"KEY_ARN"},"BucketKeyEnabled":true}]}'
```

(Enabling Object Lock at creation turns versioning on automatically.)

**B3. Lifecycle rules** — save as `lifecycle.json` and apply with
`aws s3api put-bucket-lifecycle-configuration --bucket BUCKET --lifecycle-configuration file://lifecycle.json`:

```json
{
  "Rules": [
    {
      "ID": "snapshots", "Status": "Enabled", "Filter": {"Prefix": "PREFIX/snapshots/"},
      "Transitions": [{"Days": 30, "StorageClass": "GLACIER_IR"}, {"Days": 120, "StorageClass": "DEEP_ARCHIVE"}],
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 365},
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    },
    {
      "ID": "archived-final", "Status": "Enabled", "Filter": {"Prefix": "PREFIX/archived-final/"},
      "Transitions": [{"Days": 30, "StorageClass": "DEEP_ARCHIVE"}],
      "NoncurrentVersionTransitions": [{"NoncurrentDays": 30, "StorageClass": "DEEP_ARCHIVE"}],
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    },
    {
      "ID": "state", "Status": "Enabled", "Filter": {"Prefix": "PREFIX/state/"},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 120}
    },
    {
      "ID": "expired-delete-markers", "Status": "Enabled", "Filter": {"Prefix": "PREFIX/"},
      "Expiration": {"ExpiredObjectDeleteMarker": true}
    }
  ]
}
```

Lifecycle rules never remove a version that is still under Object Lock; they
act once retention has passed. Nothing under `archived-final/` ever expires,
including overwritten (non-current) versions. Overwritten snapshot versions
are kept as long as current ones (365 days). So even someone holding the
backup role can't get a backup deleted early by overwriting it.

**B4. Bucket policy** — `aws s3api put-bucket-policy --bucket BUCKET --policy file://bucket-policy.json`.
Put any break-glass role ARNs in the `ArnNotLike` list (or leave the
placeholder, which matches nobody):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
      "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "DenyGovernanceBypass", "Effect": "Deny", "Principal": "*",
      "Action": "s3:BypassGovernanceRetention", "Resource": "arn:aws:s3:::BUCKET/*",
      "Condition": {"ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::ACCOUNT_ID:role/no-break-glass-configured"]}}
    }
  ]
}
```

**B5. GitHub OIDC provider** (skip if it exists) — IAM → *Identity providers*
→ *Add provider* → OpenID Connect, URL `https://token.actions.githubusercontent.com`,
audience `sts.amazonaws.com`.

**B6. Backup role** — IAM → *Roles* → *Create role* → *Web identity* →
provider above, audience `sts.amazonaws.com`. Name it
`github-org-backup-writer` and set **maximum session duration to 6 hours**
(shard jobs request 6-hour sessions). Replace its trust policy with:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:environment:backup"
    }}
  }]
}
```

Add this inline permissions policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "WriteBackups", "Effect": "Allow", "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
     "Resource": ["arn:aws:s3:::BUCKET/PREFIX/snapshots/*", "arn:aws:s3:::BUCKET/PREFIX/archived-final/*",
                  "arn:aws:s3:::BUCKET/PREFIX/state/*"]},
    {"Sid": "ReadOwnState", "Effect": "Allow", "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::BUCKET/PREFIX/state/*"},
    {"Sid": "ListStatePrefix", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::BUCKET",
     "Condition": {"StringLike": {"s3:prefix": ["PREFIX/state/*"]}}},
    {"Sid": "UseBackupKey", "Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "KEY_ARN"},
    {"Sid": "NeverDeleteOrWeaken", "Effect": "Deny",
     "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging",
                "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:PutBucket*",
                "s3:DeleteBucket*", "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration",
                "s3:PutReplicationConfiguration"],
     "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"]},
    {"Sid": "NeverTouchKey", "Effect": "Deny",
     "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy", "kms:CreateGrant"], "Resource": "KEY_ARN"}
  ]
}
```

**B7. Restore role** — same as B6 but named `github-org-backup-reader`, trust
`sub` = `repo:OWNER/REPO:environment:restore`, and this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "ReadBackups", "Effect": "Allow",
     "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:RestoreObject"], "Resource": "arn:aws:s3:::BUCKET/PREFIX/*"},
    {"Sid": "ListBackups", "Effect": "Allow", "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
     "Resource": "arn:aws:s3:::BUCKET", "Condition": {"StringLike": {"s3:prefix": ["PREFIX/*"]}}},
    {"Sid": "DecryptBackups", "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "KEY_ARN"}
  ]
}
```

> If your org has customised its [OIDC subject claim template](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#customizing-the-subject-claims-for-an-organization-or-repository),
> the `sub` values above won't match — adjust them to your template.

**Verify the role is write-only** (from a job in the `backup` environment, or
with an equivalent session): uploading a test object to
`PREFIX/snapshots/test/x` should succeed; `aws s3api delete-object` on it must
fail with `AccessDenied`.

### 3. Create the GitHub App

Org **Settings → Developer settings → GitHub Apps → New GitHub App**:

- Name: e.g. `<org>-backup`. Homepage URL: the backup repo's URL.
- **Webhook: uncheck *Active*** (the App never receives events).
- Where can it be installed: **Only on this account**.
- Permissions — all **read-only**:

| Permission | Level | Needed for |
|---|---|---|
| Repository → **Contents** | Read | git clone, LFS, wikis, branches, releases + assets |
| Repository → **Metadata** | Read (mandatory) | repo listing, settings, rulesets, collaborators, custom property values |
| Repository → **Issues** | Read | issues, comments, labels, milestones |
| Repository → **Pull requests** | Read | PRs, reviews, review comments |
| Repository → **Administration** | Read | branch protection, teams, deploy keys, autolinks, Actions permissions |
| Repository → **Webhooks** | Read | repo webhooks |
| Repository → **Actions** | Read | environments |
| Repository → **Variables** | Read | Actions variables |
| Repository → **Secrets** | Read | Actions secret **names** (values are never exposed) |

No organization permissions are needed. The first four rows are the core;
the rest only feed the repo config export, and anything you leave out is
recorded as a warning (not a failure) in the manifest. Drop **Secrets** if
you'd rather not expose secret names.

Then:
1. **Create** the App, note the **App ID** (or Client ID).
2. **Generate a private key** (downloads a `.pem`).
3. **Install App → your org → All repositories.** (Repos the App isn't
   installed on are invisible to the backup.)

### 4. Environments, secret and variables

In the backup repo, **Settings → Environments**:

| Environment | Deployment branches | Secrets |
|---|---|---|
| `backup` | Selected branches → your default branch only | `BACKUP_APP_PRIVATE_KEY` = full contents of the `.pem` |
| `restore` | Selected branches → your default branch only | none |

Don't add *required reviewers* — scheduled runs would wait for approval
forever.

**Settings → Secrets and variables → Actions → Variables** (repository level):

| Variable | Required | Value |
|---|---|---|
| `BACKUP_S3_BUCKET` | ✅ | bucket name |
| `BACKUP_AWS_REGION` | ✅ | e.g. `us-east-1` |
| `BACKUP_AWS_ROLE_ARN` | ✅ | backup (writer) role ARN |
| `BACKUP_AWS_RESTORE_ROLE_ARN` | for drills | restore (reader) role ARN |
| `BACKUP_APP_ID` | ✅ | GitHub App ID or Client ID |
| `BACKUP_ORG` | | org to back up (default: owner of the backup repo) |
| `BACKUP_S3_PREFIX` | | default `github-backup` (must match Terraform `s3_prefix`) |
| `ARCHIVED_GRACE_DAYS` | | default `14`; `-1` disables the archived-repo filter |
| `BACKUP_SHARD_COUNT` | | default `8` |
| `BACKUP_MAX_PARALLEL` | | concurrent git shards, default `4` |
| `BACKUP_METADATA_MAX_PARALLEL` | | concurrent metadata shards, default `2` |
| `BACKUP_RUNNER` | | runner label for git shards (e.g. a larger runner) |
| `BACKUP_RELEASE_ASSETS` | | `false` to skip release binaries |
| `BACKUP_LFS` | | `always` (default); `auto` only fetches when a ref tip has an LFS rule in any `.gitattributes` (faster, but can miss LFS used only in old commits); `never` |
| `DRILL_MAX_AGE_DAYS` | | the restore drill fails if the newest successful snapshot is older than this (default `15`) |

### 5. First runs

1. **Smoke test** — *Actions → GitHub Org Backup to S3 → Run workflow* with
   `repo_filter` = a regex matching 3–5 small repos (e.g. `^(docs|infra-tools)$`).
   Check the run summary, then the snapshot's `manifest.json` in S3.
2. **Restore test** — run *GitHub Org Backup — Restore Drill* with `repo` = one
   of those repos, and do one manual restore following [`RESTORE.md`](RESTORE.md).
3. **Archived filter test** — archive a throwaway repo and run with
   `repo_filter` = its name and `archived_grace_days` = `0`. Expect status
   `final-copy-created` and files under `archived-final/`. Run again: expect
   `skipped-archived`.
4. **Write-only check** — confirm the backup role can't delete (step 2).
   Also include, in the smoke test, one **private repo whose wiki has pages**
   and confirm its manifest entry shows `"wiki": "ok"`. That proves the App
   token can read private wikis. GitHub answers "not found" both for a wiki
   with no pages and for one the token can't read. For public repos the
   script checks anonymously; for private ones it can only warn.
5. **Full run** — run with no inputs. Watch duration per shard, API rate-limit
   sleeps in the logs, and disk warnings; tune using the next section.
6. **Failure path** — optionally break something on purpose (e.g. temporarily
   set `BACKUP_S3_BUCKET` to a wrong name) and confirm a `backup-failure` issue
   opens, then fix it and confirm the next run closes it.

Filtered runs never write `last-success.json` and never close an open failure
issue, so tests can't mask a real problem.

## The archived-repo filter

On by default. Each repo's archive date comes from GraphQL `archivedAt`; for
repos archived before GitHub recorded that field, the first time this tool
saw the repo archived is used instead (kept in `state/<org>/archive-tracker.json`).

| Situation | Action | Manifest status |
|---|---|---|
| Not archived | weekly snapshot | `backed-up` |
| Archived ≤ 14 days ago | weekly snapshot **and** permanent final copy | `backed-up` |
| Archived > 14 days ago, final copy already stored | skipped | `skipped-archived` |
| Archived > 14 days ago, no final copy yet | one-time final copy only | `final-copy-created` |
| Unarchived later | back in the weekly snapshots | `backed-up` |
| Re-archived (new `archivedAt`) | new final copy under the new date | `final-copy-created` |

The first full run creates final copies for every repo that was archived long
ago, so expect it to take longer than later runs. Final copies live under
`archived-final/`, move to Deep Archive after 30 days and **never expire**;
they're still Object Locked for the first 90 days.

Set `ARCHIVED_GRACE_DAYS=-1` (or the `archived_grace_days` run input) to back
up archived repos every week like any other repo.

## Failure alerts

`finalize` always runs. If any repo, job or export failed — including a crash
or timeout that left no results — it:
- opens an issue labelled **`backup-failure`** in the backup repo (or comments
  on the one already open, so you get one issue rather than one per week),
- lists failed repos and errors (also in the run summary and `manifest.json`),
- fails the run.

The next clean full run comments and closes the issue. The restore drill does
the same with a **`restore-drill-failure`** label. It only drills the newest
snapshot whose run succeeded, and it also fails when:
- there is no successful snapshot,
- that snapshot has no restorable repos,
- that snapshot is older than `DRILL_MAX_AGE_DAYS` (15 by default).

That last check gives the monthly drill some coverage of backups that have
stopped running.

Turn on the label's notifications (or watch the repo) for whoever owns
backups.

**Gap: a workflow that never runs files no issue.** GitHub can disable a
scheduled workflow, a cron can be edited out, or the App key can be revoked
before anything runs. If you want coverage for that, enable the Terraform
freshness alarm (`enable_freshness_alarm`), which emails via SNS when
`last-success.json` is older than 8 days. It's an AWS email, not a webhook.

Deleted, renamed or transferred repos are listed once, in the first full run
that notices them, under `repos_newly_missing_from_org` in the manifest and
in the run summary. This is informational, and the tracker keeps the
`missing_since` date.
Their past snapshots remain until the snapshot lifecycle expires them (365
days by default) — restore from there if a deletion was a mistake.

## Sizing and tuning (≈400 repos)

- **Shards.** Repos are split into `BACKUP_SHARD_COUNT` (default 8) shards
  balanced by size, so ~50 repos per shard. Git and metadata shards run in
  parallel, each capped by its own `*_MAX_PARALLEL`.
- **Job time limit.** GitHub-hosted jobs stop at 6 hours (`timeout-minutes:
  355`). If a shard gets close, raise `BACKUP_SHARD_COUNT`.
- **Disk.** Standard runners have roughly 14 GB free. A repo needs about 2.5×
  its size while being bundled; the job warns when that won't fit. Point
  `BACKUP_RUNNER` at a larger or self-hosted runner for very large repos.
- **API rate limits.** All shards share one installation-wide limit
  (5,000 requests/hour, rising with the number of repos the App is installed
  on, typically up to 12,500/hour). The scripts sleep on primary and
  secondary limits; if the metadata jobs spend a lot of time sleeping, lower
  `BACKUP_METADATA_MAX_PARALLEL` instead of raising it. The first run is the
  heaviest.
- **Tokens.** Installation tokens last an hour; the scripts re-mint them
  automatically, so long shards are fine.

## Cost estimate

Rough S3 storage for **100 GB of org data** backed up weekly, at us-east-1
list prices (check current pricing):

| Tier | Snapshots held | Approx. per month |
|---|---|---|
| Standard (0–30 days) | ~4 | ~$10 |
| Glacier Instant Retrieval (30–120 days) | ~13 | ~$5 |
| Deep Archive (120–365 days) | ~35 | ~$3.50 |
| **Total** | | **~$19/month per 100 GB**, plus ~$1 KMS key and small request/transition fees |

Snapshots are full copies each week, so cost scales with total org size ×
retention. Lower `snapshot_expiration_days` or the tiering days to trade
history for cost. Final copies of archived repos cost about $1/TB/month in
Deep Archive. GitHub Actions minutes are free for public repos; private repos
use your plan's minutes (shards × run time per week).

## Limitations

- Everything listed under *Not included* above.
- Snapshots are point-in-time and weekly, so changes made since the last run
  aren't in a backup.
- Metadata is a faithful **export**, not something GitHub can re-import; git
  data restores completely. See [`RESTORE.md`](RESTORE.md).
- `refs/pull/*` refs are read-only on GitHub; a restore keeps them in the
  mirror but can't push them back (see `RESTORE.md`).
- The org must be on GitHub.com. GHES needs `GITHUB_API_URL`/`GITHUB_SERVER_URL`
  set on the runner (they normally are) and has not been tested.

## Maintenance

- **App private key:** rotate yearly (generate a new key, update the
  environment secret, delete the old key in the App settings).
- **Pinned actions:** when upgrading, re-pin to the new release's full commit
  SHA; don't switch to a tag.
- **Schedule:** GitHub can disable scheduled workflows in repos with no
  activity for 60 days (public repos). Keep the backup repo private, and
  re-enable the workflow if a disable notice arrives.
- **Tests:** `python3 -m unittest discover -s tests` covers the archived-repo
  decisions and sharding.
- **Local runs:** the scripts accept `BACKUP_LOCAL_DIR=/path` (write to a
  folder instead of S3) and `BACKUP_GH_TOKEN` (a token instead of the App),
  useful for debugging.

## Restoring

See [`RESTORE.md`](RESTORE.md) for restoring a repository's git history, wiki,
LFS objects and metadata, including from Deep Archive.

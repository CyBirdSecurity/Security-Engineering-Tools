# Restoring from the GitHub Org Backup

Use the **read-only restore role** (`BACKUP_AWS_RESTORE_ROLE_ARN`), never the
backup role. Examples use the AWS CLI with `BUCKET`, `PREFIX`
(default `github-backup`) and `ORG` filled in.

## 1. Find the backup

```bash
# Snapshots, newest last
aws s3 ls s3://BUCKET/PREFIX/snapshots/ORG/

# What's in a snapshot (status per repo, file checksums, problems)
aws s3 cp s3://BUCKET/PREFIX/snapshots/ORG/<snapshot_id>/manifest.json - | jq '.repos[] | select(.name=="REPO")'
```

- Use a snapshot whose manifest has `"success": true` and `"partial": false`
  if you can. A manifest with problems still holds every repo whose status is
  `backed-up`.
- **Archived repos** that are skipped weekly have a permanent final copy.
  The archive tracker gives its location:
  `aws s3 cp s3://BUCKET/PREFIX/state/ORG/archive-tracker.json - | jq '.repos[] | select(.name=="REPO") | .final_copy.prefix'`
- **Deleted repos** remain in older snapshots until those expire (365 days by
  default). Search back through earlier manifests.

Set `SRC` to the repo's folder, for example
`s3://BUCKET/PREFIX/snapshots/ORG/<snapshot_id>/repos/REPO`, or the final-copy
prefix.

## 2. Thaw it if it's in Deep Archive

Snapshots move to Deep Archive after 120 days, and final copies after 30.
Objects in Glacier Instant Retrieval read normally. A Deep Archive object
returns `InvalidObjectState` until you restore it:

```bash
aws s3api restore-object --bucket BUCKET --key PREFIX/.../git/repo.bundle \
  --restore-request '{"Days":7,"GlacierJobParameters":{"Tier":"Standard"}}'   # ~12h; "Bulk" ~48h, cheaper
aws s3api head-object --bucket BUCKET --key PREFIX/.../git/repo.bundle --query Restore   # poll
```

Repeat for every file you need (`aws s3 ls --recursive` lists them).

## 3. Download and verify

```bash
mkdir restore && cd restore
aws s3 cp --recursive "$SRC/" .
sha256sum git/repo.bundle        # compare with manifest .git.files["repo.bundle"].sha256
```

## 4. Restore the git history

```bash
git clone --mirror git/repo.bundle REPO.git
cd REPO.git
git bundle verify ../git/repo.bundle
git for-each-ref | wc -l          # equals manifest .git.ref_count
```

`REPO.git` now holds every branch, tag and note, plus `refs/pull/*` (the
history of every PR head, including PRs from forks).

**Push to a new, empty repository**

GitHub rejects pushes to `refs/pull/*`, so push only branches and tags. A
mirror clone's `origin` remote refuses refspecs, so add a separate remote:

```bash
git remote add restore https://github.com/ORG/NEW-REPO.git
git push restore 'refs/heads/*:refs/heads/*' 'refs/tags/*:refs/tags/*'
git push restore 'refs/notes/*:refs/notes/*'     # if the repo used git notes
```

If you need commits that only existed on a PR (for example, an unmerged PR
whose branch was deleted), push that PR's head to a branch:

```bash
git push restore refs/pull/123/head:refs/heads/restored/pr-123
```

Then set the default branch on GitHub. It's recorded as `default_branch` in
the repo's manifest entry and in `config/repository.json`.

**LFS objects**

```bash
cd REPO.git
tar -xf ../git/lfs-objects.tar      # recreates lfs/objects/ inside the mirror
git lfs push --all restore          # the remote added above
```

**Wiki**

```bash
git clone --mirror git/wiki.bundle REPO.wiki.git
cd REPO.wiki.git
git push --mirror https://github.com/ORG/NEW-REPO.wiki.git
```

GitHub only creates a wiki's git repo after its first page has been saved in
the UI. Create a placeholder page first, then force-push the mirror.

## 5. Metadata and configuration

`metadata/*.json.gz` and `config/*.json` are exports of the API data, not an
import format. GitHub has no API to recreate issues or PRs with their
original authors and timestamps. Typical uses:

- **Reference / audit:** read it directly with
  `zcat metadata/issues.json.gz | jq '.[] | {number, title, state}'`.
- **Recreate open issues:** script `POST /repos/{owner}/{repo}/issues` from
  `issues.json.gz`, quoting the original author and date in the body.
- **Settings:** reapply them from `config/repository.json`,
  `config/rulesets.json`, `config/branch-protection.json`,
  `config/teams.json`, `config/hooks.json` and the rest, through the REST API
  or Terraform's GitHub provider. Webhook secrets and Actions secret values
  are never backed up, so set those again by hand.
- **Releases:** recreate them from `metadata/releases.json.gz` and upload the
  binaries from `metadata/release-assets/<release_id>/`.

## 6. Emergency: removing locked data

In GOVERNANCE mode only a principal listed in `break_glass_principal_arns`
can delete a version before its retention ends. It must pass the bypass
header:

```bash
aws s3api delete-object --bucket BUCKET --key KEY --version-id VERSION --bypass-governance-retention
```

In COMPLIANCE mode nobody can, the AWS root user included. Wait until the
retention date passes.

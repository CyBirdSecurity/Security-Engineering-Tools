"""Unit tests for the archived-repo filter and sharding.

Run:  python3 -m unittest discover -s tests   (from the GitHub-Org-Backup-S3 folder)
"""

import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from discover_repos import assign_shards, decide  # noqa: E402

NOW = dt.datetime(2026, 11, 29, 3, 17, tzinfo=dt.timezone.utc)


def days_ago(n: float) -> str:
    return (NOW - dt.timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%SZ")


class DecideTests(unittest.TestCase):
    def test_active_repo_is_backed_up(self):
        d = decide({"isArchived": False}, None, 14, NOW)
        self.assertEqual(d["action"], "backup")
        self.assertFalse(d["write_final"])

    def test_recently_archived_is_backed_up_and_final_copy_written(self):
        d = decide({"isArchived": True, "archivedAt": days_ago(3)}, None, 14, NOW)
        self.assertEqual((d["action"], d["write_final"]), ("backup", True))

    def test_boundary_exactly_grace_days_is_still_backed_up(self):
        d = decide({"isArchived": True, "archivedAt": days_ago(14)}, None, 14, NOW)
        self.assertEqual(d["action"], "backup")

    def test_long_archived_without_final_copy_gets_one(self):
        d = decide({"isArchived": True, "archivedAt": days_ago(400)}, None, 14, NOW)
        self.assertEqual((d["action"], d["write_final"]), ("final-only", True))

    def test_long_archived_with_final_copy_is_skipped(self):
        at = days_ago(400)
        entry = {"final_copy": {"archived_at": at}}
        d = decide({"isArchived": True, "archivedAt": at}, entry, 14, NOW)
        self.assertEqual(d["action"], "skip")

    def test_rearchived_repo_gets_new_final_copy(self):
        entry = {"final_copy": {"archived_at": days_ago(400)}}
        d = decide({"isArchived": True, "archivedAt": days_ago(30)}, entry, 14, NOW)
        self.assertEqual(d["action"], "final-only")

    def test_filter_disabled_backs_up_everything(self):
        d = decide({"isArchived": True, "archivedAt": days_ago(999)}, None, -1, NOW)
        self.assertEqual((d["action"], d["write_final"]), ("backup", True))

    def test_grace_zero_skips_anything_archived_before_now(self):
        at = days_ago(1)
        d = decide({"isArchived": True, "archivedAt": at}, {"final_copy": {"archived_at": at}}, 0, NOW)
        self.assertEqual(d["action"], "skip")

    def test_missing_archived_at_uses_first_seen(self):
        d = decide({"isArchived": True, "archivedAt": None}, {"first_seen_archived": days_ago(20)}, 14, NOW)
        self.assertEqual((d["archived_at_source"], d["action"]), ("first-seen", "final-only"))

    def test_missing_archived_at_first_time_seen_counts_as_now(self):
        d = decide({"isArchived": True, "archivedAt": None}, None, 14, NOW)
        self.assertEqual((d["archived_at_source"], d["action"]), ("first-seen", "backup"))


class ShardTests(unittest.TestCase):
    def test_skipped_repos_get_no_shard_and_shards_are_balanced(self):
        repos = [{"action": "backup", "diskUsage": s} for s in (900_000, 100, 100, 100, 450_000, 450_000)]
        repos.append({"action": "skip", "diskUsage": 5})
        n = assign_shards(repos, 2)
        self.assertEqual(n, 2)
        self.assertIsNone(repos[-1]["shard"])
        loads = [sum(r["diskUsage"] for r in repos if r["shard"] == i) for i in range(2)]
        self.assertLess(abs(loads[0] - loads[1]), 1000)

    def test_never_more_shards_than_work(self):
        repos = [{"action": "backup", "diskUsage": 1}]
        self.assertEqual(assign_shards(repos, 8), 1)

    def test_no_work_still_yields_one_shard(self):
        self.assertEqual(assign_shards([{"action": "skip"}], 8), 1)


if __name__ == "__main__":
    unittest.main()

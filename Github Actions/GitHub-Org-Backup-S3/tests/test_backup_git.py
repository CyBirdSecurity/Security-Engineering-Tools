"""Unit tests for how `git lfs fetch --all` outcomes are classified.

Run:  python3 -m unittest discover -s tests   (from the GitHub-Org-Backup-S3 folder)
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from backup_git import classify_lfs_fetch  # noqa: E402


def proc(code: int, stderr: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["git", "lfs", "fetch"], code, b"", stderr.encode())


class ClassifyLfsFetchTests(unittest.TestCase):
    def test_success(self):
        self.assertEqual(classify_lfs_fetch(proc(0, ""))[0], "ok")

    def test_objects_missing_on_server_is_partial_not_failure(self):
        err = ("[4d7a2146...] Object does not exist on the server: [404] Object does not exist on the server\n"
               "error: failed to fetch some objects from 'https://github.com/o/r.git/info/lfs'")
        outcome, detail = classify_lfs_fetch(proc(2, err))
        self.assertEqual(outcome, "partial")
        self.assertIn("1 LFS object", detail)

    def test_auth_error_is_failure_even_with_missing_objects(self):
        err = ("[abc] Object does not exist on the server\n"
               "batch response: Authorization error: https://github.com/o/r.git/info/lfs (403)")
        self.assertEqual(classify_lfs_fetch(proc(2, err))[0], "failed")

    def test_server_error_is_failure(self):
        self.assertEqual(classify_lfs_fetch(proc(2, "batch response: Fatal error: Server error 502"))[0], "failed")

    def test_disk_full_is_failure(self):
        self.assertEqual(classify_lfs_fetch(proc(2, "write error: no space left on device"))[0], "failed")


if __name__ == "__main__":
    unittest.main()

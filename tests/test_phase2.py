"""Tests for the write path: uploads, jobs, and the code-review scanner.

Everything here is a security test in the sense that matters for this feature.
The dashboard stopped being read-only, and the two new capabilities - accept a
file from someone, run a tool over it - are the two capabilities that most often
turn a local utility into a foothold. So these assert the refusals, not the
happy path: an archive that escapes its directory, a form submitted from another
origin, a filename that tries to be a path.
"""

import os
import socket
import urllib.error
import sqlite3
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.codereview import (
    ArchiveRejected,
    Finding,
    MAX_MEMBERS,
    parse_gitleaks,
    parse_semgrep,
    run_scanner,
    safe_extract,
)
from ares.dashboard import allowed_origin, make_handler, parse_multipart
from ares.jobs import (
    MAX_UPLOAD_BYTES,
    UploadRejected,
    looks_like_event_log,
    safe_label,
    store_review_upload,
    store_upload,
)
from ares.rendering import (
    CONTENT_SECURITY_POLICY,
    DASHBOARD_CONTENT_SECURITY_POLICY,
)
from ares.store import initialize


EVENT_LINE = b'{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1}\n'


class ArchiveExtractionTests(unittest.TestCase):
    """Zip Slip and its relatives. Each of these writes outside the target."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def _archive(self, entries, name="a.zip"):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for member, content in entries:
                archive.writestr(member, content)
        return path

    def test_extracts_an_ordinary_archive(self):
        archive = self._archive([("pkg/app.py", "x = 1\n"), ("pkg/sub/b.py", "y = 2\n")])
        extracted = safe_extract(archive, self.root / "out")
        self.assertEqual(len(extracted), 2)
        self.assertTrue((self.root / "out" / "pkg" / "app.py").exists())

    def test_refuses_a_member_that_climbs_out_with_dotdot(self):
        archive = self._archive([("../escaped.py", "pwned = True\n")])
        with self.assertRaises(ArchiveRejected):
            safe_extract(archive, self.root / "out")
        self.assertFalse((self.root / "escaped.py").exists())

    def test_refuses_a_deeply_nested_climb(self):
        archive = self._archive([("a/b/../../../escaped.py", "pwned = True\n")])
        with self.assertRaises(ArchiveRejected):
            safe_extract(archive, self.root / "out")
        self.assertFalse((self.root / "escaped.py").exists())

    def test_refuses_an_absolute_path_member(self):
        archive = self._archive([("/etc/ares_test_marker", "x\n")])
        with self.assertRaises(ArchiveRejected):
            safe_extract(archive, self.root / "out")

    def test_refuses_a_symlink_member(self):
        path = self.root / "link.zip"
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("link")
            # 0xA1FF = S_IFLNK | 0777, shifted into the Unix mode half of
            # external_attr, which is how a zip records a symlink.
            info.external_attr = 0xA1FF << 16
            archive.writestr(info, "/etc/passwd")
        with self.assertRaises(ArchiveRejected):
            safe_extract(path, self.root / "out")

    def test_refuses_an_archive_with_too_many_members(self):
        archive = self._archive([(f"f{index}.py", "x\n") for index in range(MAX_MEMBERS + 1)])
        with self.assertRaises(ArchiveRejected):
            safe_extract(archive, self.root / "out")

    def test_refuses_an_archive_that_expands_past_the_limit(self):
        # Highly compressible content: a few KB on disk, 300MB unpacked. The
        # check must read the declared uncompressed size, never the file size.
        path = self.root / "bomb.zip"
        chunk = b"0" * (8 * 1024 * 1024)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            with archive.open("bomb.txt", "w") as member:
                for _ in range(38):
                    member.write(chunk)
        self.assertLess(path.stat().st_size, 1024 * 1024)
        with self.assertRaises(ArchiveRejected):
            safe_extract(path, self.root / "out")


class ScannerInvocationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_arguments_are_never_interpreted_by_a_shell(self):
        """The single most important property of the review feature.

        With shell=True this argument would run `id`. As an argument list it is
        an inert string that echo prints back verbatim.
        """
        completed, error = run_scanner(
            ["echo", "harmless; id"], cwd=self.directory.name
        )
        self.assertIsNone(error)
        self.assertIn("harmless; id", completed.stdout)
        self.assertNotIn("uid=", completed.stdout)

    def test_a_missing_scanner_is_reported_not_raised(self):
        _, error = run_scanner(["ares-no-such-scanner"], cwd=self.directory.name)
        self.assertIn("not installed", error)

    def test_a_hanging_scanner_is_killed(self):
        _, error = run_scanner(["sleep", "5"], cwd=self.directory.name, timeout=1)
        self.assertIn("exceeded", error)

    def test_the_scanner_environment_carries_no_operator_secrets(self):
        os.environ["ARES_TEST_FAKE_TOKEN"] = "super-secret"
        self.addCleanup(os.environ.pop, "ARES_TEST_FAKE_TOKEN", None)
        completed, error = run_scanner(["env"], cwd=self.directory.name)
        self.assertIsNone(error)
        self.assertNotIn("super-secret", completed.stdout)


class FindingParsingTests(unittest.TestCase):
    def test_semgrep_findings_carry_their_cwe_and_tool(self):
        payload = {"results": [{
            "check_id": "ares-subprocess-shell-true",
            "path": "/tmp/tree/app.py",
            "start": {"line": 12},
            "extra": {
                "severity": "ERROR",
                "message": "shell=True",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        }]}
        [finding] = parse_semgrep(payload, "/tmp/tree")
        self.assertEqual(finding.tool, "semgrep")
        self.assertEqual(finding.cwe, "CWE-78: OS Command Injection")
        self.assertEqual(finding.path, "app.py")
        self.assertEqual(finding.line, 12)

    def test_gitleaks_findings_do_not_carry_the_secret_itself(self):
        payload = [{
            "RuleID": "aws-access-token",
            "File": "/tmp/tree/config.py",
            "StartLine": 3,
            "Description": "AWS token",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
        }]
        [finding] = parse_gitleaks(payload, "/tmp/tree")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finding.message)
        self.assertIn("CWE-798", finding.cwe)


class UploadStorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_the_uploaders_filename_never_reaches_the_filesystem(self):
        stored = store_upload(self.root / "up", "../../../etc/ares_owned.json", EVENT_LINE)
        self.assertEqual(stored.parent, self.root / "up")
        self.assertNotIn("ares_owned", stored.name)
        self.assertNotIn("..", str(stored))
        self.assertTrue(stored.name.endswith(".jsonl"))

    def test_rejects_an_empty_upload(self):
        with self.assertRaises(UploadRejected):
            store_upload(self.root / "up", "empty.json", b"")

    def test_rejects_something_that_is_not_an_event_log(self):
        with self.assertRaises(UploadRejected):
            store_upload(self.root / "up", "photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    def test_rejects_an_upload_over_the_size_cap(self):
        with self.assertRaises(UploadRejected):
            store_upload(self.root / "up", "huge.json", b"x" * (MAX_UPLOAD_BYTES + 1))

    def test_rejects_an_archive_that_is_not_a_zip(self):
        with self.assertRaises(UploadRejected):
            store_review_upload(self.root / "ar", b"not a zip at all")

    def test_a_json_array_file_is_not_mistaken_for_json_lines(self):
        self.assertFalse(looks_like_event_log(b'[{"EventID": 1}]'))
        self.assertTrue(looks_like_event_log(EVENT_LINE))

    def test_labels_are_bounded_and_printable(self):
        self.assertEqual(safe_label("a\nb\tc"), "abc")
        self.assertLessEqual(len(safe_label("x" * 500)), 120)
        self.assertEqual(safe_label(""), "uploaded log")


class MultipartTests(unittest.TestCase):
    def test_fields_and_files_are_kept_apart(self):
        boundary = b"XbX"
        body = (
            b"--XbX\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\ntok\r\n"
            b"--XbX\r\nContent-Disposition: form-data; name=\"logfile\"; filename=\"a.json\"\r\n"
            b"Content-Type: application/json\r\n\r\n" + EVENT_LINE + b"\r\n"
            b"--XbX--\r\n"
        )
        fields, files = parse_multipart(body, boundary)
        self.assertEqual(fields["csrf"], "tok")
        self.assertNotIn("logfile", fields)
        self.assertEqual(files["logfile"][0], "a.json")
        self.assertEqual(files["logfile"][1], EVENT_LINE)


class OriginTests(unittest.TestCase):
    def test_a_foreign_origin_is_refused(self):
        self.assertFalse(allowed_origin("https://evil.example", 8420))
        self.assertFalse(allowed_origin("http://127.0.0.1:9999", 8420))

    def test_this_server_is_accepted(self):
        self.assertTrue(allowed_origin("http://127.0.0.1:8420", 8420))
        self.assertTrue(allowed_origin("http://localhost:8420/x", 8420))

    def test_an_absent_origin_is_left_to_the_csrf_token(self):
        self.assertTrue(allowed_origin(None, 8420))


class WritePathTests(unittest.TestCase):
    """The POST routes, exercised over a real socket like a browser would."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.db_path = self.root / "ares.db"
        connection = sqlite3.connect(self.db_path)
        initialize(connection)
        connection.close()
        self.handler = make_handler(self.db_path, self.root / "work", csrf_token="test-token")

    def _request(self, request):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        fake_server = type("Server", (), {"server_port": 8420})()
        thread = threading.Thread(target=self.handler, args=(server, ("127.0.0.1", 0), fake_server))
        thread.start()
        client.sendall(request)
        # A dashboard page is larger than the socketpair buffer, so the handler
        # blocks mid-write until the client drains it. Joining before reading
        # deadlocks the two threads against each other.
        client.settimeout(0.5)
        chunks = []
        try:
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except (TimeoutError, socket.timeout):
            pass
        thread.join(timeout=10)
        return b"".join(chunks).decode("utf-8", "replace")

    def _multipart(self, path, token, extra_headers=b"", filename="log.json", payload=EVENT_LINE):
        body = (
            b"--B\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n"
            + token.encode() + b"\r\n"
            b"--B\r\nContent-Disposition: form-data; name=\"logfile\"; filename=\""
            + filename.encode() + b"\"\r\n\r\n" + payload + b"\r\n--B--\r\n"
        )
        return self._request(
            b"POST " + path + b" HTTP/1.1\r\nHost: localhost:8420\r\nConnection: close\r\n"
            b"Content-Type: multipart/form-data; boundary=B\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            + extra_headers + b"\r\n" + body
        )

    def _job_count(self):
        connection = sqlite3.connect(self.db_path)
        try:
            return connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        finally:
            connection.close()

    def test_a_post_without_the_csrf_token_creates_nothing(self):
        response = self._multipart(b"/analyze", "wrong-token")
        self.assertIn(" 403 ", response.splitlines()[0])
        self.assertEqual(self._job_count(), 0)

    def test_a_post_from_another_origin_is_refused_before_the_body_is_read(self):
        response = self._multipart(
            b"/analyze", "test-token", b"Origin: https://evil.example\r\n"
        )
        self.assertIn(" 403 ", response.splitlines()[0])
        self.assertEqual(self._job_count(), 0)

    def test_a_rejected_file_creates_no_job(self):
        response = self._multipart(b"/analyze", "test-token", payload=b"\x89PNG\r\n\x1a\n")
        self.assertIn(" 400 ", response.splitlines()[0])
        self.assertEqual(self._job_count(), 0)

    def test_the_csrf_token_is_not_echoed_to_an_unauthorised_caller(self):
        # The error page is rendered for a failed POST; it must not hand the
        # attacker the token that would make the next attempt succeed.
        response = self._multipart(b"/analyze", "wrong-token")
        self.assertNotIn("test-token", response)

    def test_a_valid_submission_creates_a_job_and_redirects_to_it(self):
        response = self._multipart(b"/analyze", "test-token")
        self.assertIn(" 303 ", response.splitlines()[0])
        self.assertIn("Location: /job/", response)
        self.assertEqual(self._job_count(), 1)

    def test_the_upload_lands_in_a_directory_that_states_its_dataset_mode(self):
        # The pipeline re-derives the mode from the path and aborts on a
        # mismatch; this asserts the upload directory keeps that check honest.
        self._multipart(b"/analyze", "test-token")
        self.assertTrue((self.root / "work" / "uploads" / "demo").is_dir())


class PolicyTests(unittest.TestCase):
    def test_the_dashboard_may_post_to_itself_and_nowhere_else(self):
        self.assertIn("form-action 'self'", DASHBOARD_CONTENT_SECURITY_POLICY)
        self.assertNotIn("form-action 'none'", DASHBOARD_CONTENT_SECURITY_POLICY)

    def test_exported_reports_keep_the_stricter_policy(self):
        self.assertIn("form-action 'none'", CONTENT_SECURITY_POLICY)

    def test_neither_policy_permits_script(self):
        for policy in (CONTENT_SECURITY_POLICY, DASHBOARD_CONTENT_SECURITY_POLICY):
            self.assertIn("default-src 'none'", policy)
            self.assertNotIn("script-src", policy)

    def test_the_two_policies_differ_by_exactly_one_directive(self):
        strict = set(CONTENT_SECURITY_POLICY.split("; "))
        relaxed = set(DASHBOARD_CONTENT_SECURITY_POLICY.split("; "))
        self.assertEqual(strict - relaxed, {"form-action 'none'"})
        self.assertEqual(relaxed - strict, {"form-action 'self'"})


if __name__ == "__main__":
    unittest.main()


class LocalModelChooserTests(unittest.TestCase):
    """The chooser lists what Ollama has, and says so plainly when it has nothing."""

    def _status(self, payload=None, fail=None):
        import json as _json
        from unittest import mock

        import ares.local_models as local_models

        if fail is not None:
            with mock.patch.object(local_models.urllib.request, "urlopen", side_effect=fail):
                return local_models.local_status()

        class _Response:
            def read(self):
                return _json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        with mock.patch.object(local_models.urllib.request, "urlopen", return_value=_Response()):
            return local_models.local_status()

    def test_the_measured_model_is_offered_first(self):
        status = self._status({"models": [
            {"name": "granite4:3b"},
            {"name": "qwen2.5:7b-instruct"},
            {"name": "aardvark:1b"},
        ]})
        self.assertEqual(status["models"][0], "qwen2.5:7b-instruct")
        self.assertEqual(status["default"], "qwen2.5:7b-instruct")
        self.assertTrue(status["preferred_present"])

    def test_embedding_models_are_not_offered_as_selectors(self):
        status = self._status({"models": [
            {"name": "nomic-embed-text:latest"},
            {"name": "granite4:3b"},
        ]})
        self.assertEqual(status["models"], ["granite4:3b"])

    def test_a_daemon_that_is_down_is_reported_not_raised(self):
        status = self._status(fail=urllib.error.URLError("connection refused"))
        self.assertFalse(status["reachable"])
        self.assertIn("not reachable", status["error"])
        self.assertEqual(status["models"], [])

    def test_running_with_nothing_pulled_is_distinguished_from_being_down(self):
        # A fresh container hits this: the daemon is up, nothing is pulled. The
        # remedy is `ollama pull`, not `ollama serve`, so the two states must not
        # collapse into one "unavailable".
        running_but_empty = self._status({"models": []})
        self.assertTrue(running_but_empty["reachable"])
        self.assertFalse(running_but_empty["has_models"])
        self.assertIsNone(running_but_empty["error"])

        down = self._status(fail=urllib.error.URLError("connection refused"))
        self.assertFalse(down["reachable"])
        self.assertFalse(down["has_models"])


class ModelChoiceTests(WritePathTests):
    """A submitted model name is a request, validated against reality."""

    def _submit_model(self, arm, model):
        from unittest import mock

        body = (
            b"--B\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\ntest-token\r\n"
            b"--B\r\nContent-Disposition: form-data; name=\"arm\"\r\n\r\n" + arm.encode() + b"\r\n"
            b"--B\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n" + model.encode() + b"\r\n"
            b"--B\r\nContent-Disposition: form-data; name=\"logfile\"; filename=\"a.json\"\r\n\r\n"
            + EVENT_LINE + b"\r\n--B--\r\n"
        )
        with mock.patch("ares.dashboard.local_status", return_value={
            "reachable": True, "models": ["qwen2.5:7b-instruct"],
            "error": None, "default": "qwen2.5:7b-instruct",
            "preferred_present": True, "preferred": "qwen2.5:7b-instruct",
        }):
            self._request(
                b"POST /analyze HTTP/1.1\r\nHost: localhost:8420\r\n"
                b"Content-Type: multipart/form-data; boundary=B\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
        connection = sqlite3.connect(self.db_path)
        try:
            return connection.execute("SELECT arm, model FROM jobs").fetchone()
        finally:
            connection.close()

    def test_an_installed_model_is_recorded_on_the_job(self):
        self.assertEqual(self._submit_model("local", "qwen2.5:7b-instruct"),
                         ("local", "qwen2.5:7b-instruct"))

    def test_a_model_ollama_does_not_have_is_discarded(self):
        # Otherwise the run fails inside the model call, minutes later, with an
        # error that looks like a bug rather than a bad choice.
        self.assertEqual(self._submit_model("local", "not-installed:70b"),
                         ("local", None))

    def test_the_frontier_arm_ignores_the_local_model_choice(self):
        self.assertEqual(self._submit_model("frontier", "qwen2.5:7b-instruct"),
                         ("frontier", None))

"""Static review of an uploaded code archive. Read and scanned, never executed.

This is the second thing ARES does, and it is the more dangerous one. An event
log is data we parse; an uploaded archive is somebody else's source tree, and the
two obvious ways to get value out of it - unpack it, then run something over it -
are also the two classic ways to be compromised by it.

So both are constrained here rather than in the caller:

* **Extraction** (`safe_extract`) treats every archive member as hostile. Zip Slip
  (`../../.ssh/authorized_keys`), absolute paths, symlink members and zip bombs
  are each refused explicitly, and the refusal is a rejection of the whole
  archive rather than a skipped member - a partial extraction of an archive that
  tried to escape is not a safe outcome, it is a successful attack with one arm.

* **Scanning** (`run_scanner`) shells out to nothing. Every scanner is invoked as
  an argument list with `shell=False`, a wall-clock timeout, a scrubbed
  environment and the extraction directory as its working directory.

**Nothing in the uploaded tree is ever executed.** No install step, no build, no
test run, no import. The scanners read files. That guarantee is the reason this
feature can exist at all, and it is asserted in the test suite rather than only
promised in this docstring.
"""

import json
import os
import subprocess
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path


# A hackathon submission is a source tree, not a disk image. These bounds exist
# so a malicious archive cannot exhaust the disk or the file table before any
# scanner runs.
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 5000
SCANNER_TIMEOUT_SECONDS = 120

RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "ares-review.yaml"

# gitleaks reports secrets; the weakness class is the same for every hit, so the
# mapping is a constant rather than something read out of the tool's output.
GITLEAKS_CWE = "CWE-798: Use of Hard-coded Credentials"
OSV_CWE = "CWE-1395: Dependency on Vulnerable Third-Party Component"


class ArchiveRejected(Exception):
    """The archive tried something an archive should never need to do."""


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    cwe: str
    severity: str
    path: str
    line: int
    message: str


def _member_is_symlink(info):
    # The high 16 bits of external_attr carry the Unix mode; 0xA000 is S_IFLNK.
    # A symlink member is how an archive gets a later member written through it
    # to a path outside the extraction root, so it is refused outright.
    return (info.external_attr >> 16) & 0xF000 == 0xA000


def safe_extract(archive_path, destination):
    """Extract a zip into `destination`, refusing anything that tries to escape it.

    Returns the list of extracted paths. Raises `ArchiveRejected` on the first
    hostile member, before writing it.
    """
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if Path(archive_path).stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveRejected(
            f"Archive is larger than the {MAX_ARCHIVE_BYTES // (1024 * 1024)}MB limit."
        )
    extracted = []
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise ArchiveRejected(
                f"Archive contains {len(members)} entries; the limit is {MAX_MEMBERS}."
            )
        total = sum(info.file_size for info in members)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ArchiveRejected(
                "Archive expands to "
                f"{total // (1024 * 1024)}MB, over the "
                f"{MAX_UNCOMPRESSED_BYTES // (1024 * 1024)}MB limit."
            )
        for info in members:
            name = info.filename
            if _member_is_symlink(info):
                raise ArchiveRejected(f"Archive contains a symlink: {name!r}")
            if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
                raise ArchiveRejected(f"Archive contains an absolute path: {name!r}")
            # Resolve against the destination and confirm the result is still
            # inside it. This catches `..`, nested `..`, and the encodings of
            # them that a string check on the raw name would miss.
            target = (destination / name).resolve()
            if target != destination and destination not in target.parents:
                raise ArchiveRejected(f"Archive member escapes the extraction root: {name!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as sink:
                sink.write(source.read())
            extracted.append(target)
    return extracted


def run_scanner(argv, cwd, timeout=SCANNER_TIMEOUT_SECONDS):
    """Invoke a scanner as an argument list, never through a shell.

    `shell=False` is the default and is passed explicitly because this is the
    property that matters most in this file: with a shell, any filename in the
    uploaded tree that contained `;` would be a command. The environment is
    reduced to PATH and HOME so a scanner cannot pick up credentials from the
    operator's session and mail them somewhere.
    """
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
    }
    try:
        completed = subprocess.run(  # noqa: S603 - argument list, shell=False, see docstring
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=environment,
            check=False,
        )
    except FileNotFoundError:
        return None, f"{argv[0]} is not installed"
    except subprocess.TimeoutExpired:
        return None, f"{argv[0]} exceeded {timeout}s and was terminated"
    return completed, None


def _relative(path, root):
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except (ValueError, OSError):
        return str(path)


def parse_semgrep(payload, root):
    findings = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        findings.append(Finding(
            tool="semgrep",
            rule_id=str(result.get("check_id", "")),
            cwe=str(cwe or "unmapped"),
            severity=str(extra.get("severity", "INFO")),
            path=_relative(result.get("path", ""), root),
            line=int((result.get("start") or {}).get("line", 0)),
            message=str(extra.get("message", "")).strip(),
        ))
    return findings


def parse_gitleaks(payload, root):
    findings = []
    for result in payload or []:
        findings.append(Finding(
            tool="gitleaks",
            rule_id=str(result.get("RuleID", "")),
            cwe=GITLEAKS_CWE,
            severity="ERROR",
            path=_relative(result.get("File", ""), root),
            line=int(result.get("StartLine", 0)),
            # The secret itself is deliberately NOT carried into the finding.
            # A report that quotes the credential it found is a second copy of
            # the credential, in a file people forward around.
            message=f"{result.get('Description', 'Secret detected')} (value withheld)",
        ))
    return findings


def parse_osv(payload, root):
    findings = []
    for scanned in (payload or {}).get("results", []):
        for package in scanned.get("packages", []):
            name = (package.get("package") or {}).get("name", "?")
            version = (package.get("package") or {}).get("version", "?")
            for vulnerability in package.get("vulnerabilities", []):
                findings.append(Finding(
                    tool="osv-scanner",
                    rule_id=str(vulnerability.get("id", "")),
                    cwe=OSV_CWE,
                    severity="ERROR",
                    path=_relative(scanned.get("source", {}).get("path", ""), root),
                    line=0,
                    message=f"{name} {version}: {str(vulnerability.get('summary', '')).strip()}",
                ))
    return findings


def scan_directory(root):
    """Run every available scanner over an already-extracted tree.

    A missing scanner is reported as a skipped tool, never silently dropped: a
    review that quietly ran two of three tools and said nothing would let a clean
    result mean either "no secrets" or "no secret scanner", which is precisely
    the ambiguity this project exists to remove.
    """
    findings = []
    skipped = []

    completed, error = run_scanner(
        ["semgrep", "--config", str(RULES_PATH), "--json", "--quiet",
         "--metrics", "off", "--no-git-ignore", "."],
        cwd=root,
    )
    if error:
        skipped.append(f"semgrep: {error}")
    elif completed.stdout.strip():
        try:
            findings.extend(parse_semgrep(json.loads(completed.stdout), root))
        except json.JSONDecodeError:
            skipped.append("semgrep: output was not valid JSON")

    completed, error = run_scanner(
        ["gitleaks", "detect", "--source", ".", "--no-git", "--report-format", "json",
         "--report-path", "/dev/stdout", "--redact", "--exit-code", "0"],
        cwd=root,
    )
    if error:
        skipped.append(f"gitleaks: {error}")
    elif completed.stdout.strip():
        try:
            findings.extend(parse_gitleaks(json.loads(completed.stdout), root))
        except json.JSONDecodeError:
            skipped.append("gitleaks: output was not valid JSON")

    completed, error = run_scanner(
        ["osv-scanner", "--format", "json", "--recursive", "."], cwd=root,
    )
    if error:
        skipped.append(f"osv-scanner: {error}")
    elif completed.stdout.strip():
        try:
            findings.extend(parse_osv(json.loads(completed.stdout), root))
        except json.JSONDecodeError:
            skipped.append("osv-scanner: output was not valid JSON")

    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    findings.sort(key=lambda item: (order.get(item.severity, 3), item.path, item.line))
    return findings, skipped


def review_archive(archive_path, workdir):
    """Extract and scan one archive. Returns (findings, skipped_tools)."""
    root = Path(workdir) / "tree"
    safe_extract(archive_path, root)
    return scan_directory(root)


def findings_as_dicts(findings):
    return [asdict(finding) for finding in findings]

"""Nothing tracked in this repository may identify a real person or tenant.

This repository is intended to go public, and publishing is not reversible: a
private repository made public exposes every commit that was ever made to it.
These tests are the standing check that the state stays publishable, so the
question is answered on every push rather than once by hand on the day.

They deliberately look at what is tracked by git rather than at the working
tree, because that is exactly the set of files that would be published.
"""

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.m13

ROOT = Path(__file__).parents[1]

# Reserved by RFC 2606 and RFC 6761 for documentation and testing. None of
# these can be registered, so none can ever reach a real person.
SAFE_EMAIL_DOMAINS = (
    "example.com", "example.org", "example.net", "example.invalid",
    "tenant.example", "contoso.com", "nowhere.example", "iamai.invalid",
)
# The address used to attribute commits, and the one this project's assistant
# signs with. Both are non routing by design.
SAFE_EMAIL_EXACT = (
    "noreply@anthropic.com",
    "263729753+zephyrpretendstoknowtech@users.noreply.github.com",
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TENANT = re.compile(r"[A-Za-z0-9\-]+\.onmicrosoft\.com", re.IGNORECASE)

# Schema and namespace markers that are not addresses despite the @ sign.
_NOT_AN_ADDRESS = re.compile(r"@odata|@microsoft|@type\b")


def tracked_text_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\n")
    for name in out:
        name = name.strip()
        if not name:
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            yield name, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable, nothing to read for identity


def test_no_tracked_file_carries_a_routable_email_address():
    found = []
    for name, text in tracked_text_files():
        for match in _EMAIL.finditer(text):
            address = match.group(0)
            if _NOT_AN_ADDRESS.search(address):
                continue
            lowered = address.lower()
            if lowered in SAFE_EMAIL_EXACT:
                continue
            if any(lowered.endswith(d) for d in SAFE_EMAIL_DOMAINS):
                continue
            found.append(f"{name}: {address}")
    assert not found, "routable addresses in tracked files:\n" + "\n".join(found)


def test_no_tracked_file_names_a_real_tenant():
    """A tenant's onmicrosoft.com name identifies the organization as surely as
    its domain does, and it is the thing a stranger would search for."""
    found = []
    for name, text in tracked_text_files():
        for match in _TENANT.finditer(text):
            if match.group(0).lower().startswith("contoso."):
                continue  # Microsoft's own documentation placeholder
            found.append(f"{name}: {match.group(0)}")
    assert not found, "real tenant names in tracked files:\n" + "\n".join(found)


def test_the_files_that_hold_secrets_are_ignored():
    """These are the paths that hold a certificate, a tenant id, or collected
    tenant data. An entry disappearing from .gitignore is how the next leak
    happens, so the list is asserted rather than trusted."""
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").split("\n")
    entries = {line.strip() for line in ignored if line.strip()}
    for required in ("data/", "certs/", "config.yaml"):
        assert required in entries, f".gitignore no longer excludes {required}"


def test_no_secret_bearing_path_is_tracked():
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.lower()
    for pattern in ("config.yaml", "certs/", "data/", ".pem", ".pfx", "answers.json"):
        assert pattern not in tracked, f"a path matching {pattern} is tracked by git"


def test_the_license_is_present_and_is_apache_2():
    """Section 8 of the specification makes the licence the liability position,
    so a missing or truncated one is a real problem rather than paperwork."""
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in text
    assert "Version 2.0, January 2004" in text
    assert "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND" in text
    assert "[name of copyright owner]" not in text, "the copyright holder is unset"

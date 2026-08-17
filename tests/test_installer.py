"""The installers must fail honestly and need no developer tooling.

A clean-Windows first run (2026-08-17, operator report) found install.ps1
printing success after pipx had failed twice: it never checked an exit code,
and its success message was unconditional. It also required git, which stock
Windows does not have. These tests pin the fixes so neither can quietly
return:

1. No git anywhere: the install source is a plain archive or wheel URL.
2. Every external command's exit code is checked.
3. The success message is unreachable except through the verification step.
4. The script parses under Windows PowerShell 5.1, the actual baseline.

They are static and parse-level on purpose: an end-to-end installer run needs
a clean machine, which is the operator's clean-VM test, not CI's.
"""

import pathlib
import re
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.m15

ROOT = pathlib.Path(__file__).parents[1]
PS1 = ROOT / "scripts" / "install.ps1"
SH = ROOT / "scripts" / "install.sh"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


# --- No developer toolchain required ------------------------------------------


def test_no_installer_requires_git():
    """Stock Windows has no git, so a git+https install source fails for
    essentially every new user. Archives and wheels install with pip alone."""
    for path in (PS1, SH):
        code_lines = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if not line.strip().startswith("#")  # comments may name the rule
        ]
        assert "git+" not in "\n".join(code_lines), path.name


def test_both_installers_prefer_a_pinned_release():
    """Master is the development fallback, not the default install source."""
    for path in (PS1, SH):
        text = path.read_text(encoding="utf-8")
        assert "releases/latest" in text, path.name
        assert "archive/refs/heads/master.zip" in text, path.name


# --- Honest failure -----------------------------------------------------------


def test_ps1_checks_exit_codes_after_external_commands():
    text = PS1.read_text(encoding="utf-8")
    # winget, pip-install-pipx, ensurepath, pipx install, and the final
    # verification each get their own check; the count keeps a refactor from
    # quietly dropping one.
    assert text.count("$LASTEXITCODE") >= 6, "exit-code checks were removed"
    assert "Fail " in text or "Fail(" in text


def test_ps1_success_message_is_behind_the_verification():
    """The failure the operator hit: pipx failed twice and the script printed
    'IAMAI is installed.' anyway. Success text must be unreachable except
    through the step that ran the installed command and got an answer."""
    text = PS1.read_text(encoding="utf-8")
    verify = text.index("verifying the install")
    for match in re.finditer(r"IAMAI is installed", text):
        # The one in the header comment block describes the script; every
        # occurrence in code must come after verification.
        preceding = text[: match.start()]
        if "#>" in preceding:  # past the comment header
            assert match.start() > verify, "success text before verification"


def test_ps1_verifies_the_command_answers_not_just_exists():
    text = PS1.read_text(encoding="utf-8")
    assert "iamai --version" in text
    assert "iamai --help" in text  # releases before 1.3.0 have no --version


def test_sh_verifies_before_claiming_success():
    text = SH.read_text(encoding="utf-8")
    assert "fail()" in text
    verify = text.index("--version")
    claimed = text.index("installed and verified")
    assert verify < claimed


# --- The specific first-run papercuts -----------------------------------------


def test_ps1_sets_utf8_for_captured_output():
    """Captured pipx output fell back to cp1252 and crashed on pipx's emoji
    with 'charmap codec can't encode character'."""
    text = PS1.read_text(encoding="utf-8")
    assert "PYTHONUTF8" in text
    assert "PYTHONIOENCODING" in text
    assert "OutputEncoding" in text


def test_ps1_winget_cannot_prompt():
    """A piped one-liner has no TTY; an msstore agreement prompt would hang
    forever. The source is pinned and interactivity disabled."""
    text = PS1.read_text(encoding="utf-8")
    assert "--source winget" in text
    assert "--disable-interactivity" in text
    assert "--accept-source-agreements" in text
    assert "--accept-package-agreements" in text


def test_ps1_has_a_preflight():
    text = PS1.read_text(encoding="utf-8")
    for probe in ("PSVersion", "PROCESSOR_ARCHITECTURE", "github.com", "pypi.org",
                  "This installer will:"):
        assert probe in text, probe


def test_ps1_filters_the_pipx_setuptools_noise():
    text = PS1.read_text(encoding="utf-8")
    assert "Skipping (setuptools|wheel) as it is not installed" in text


# --- The baseline shell is Windows PowerShell 5.1 ------------------------------


@pytest.mark.skipif(shutil.which("powershell.exe") is None,
                    reason="Windows PowerShell 5.1 not on this machine")
def test_ps1_parses_under_windows_powershell_51():
    check = (
        "$e = $null; $t = $null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{PS1}', [ref]$t, [ref]$e) | Out-Null; "
        "if ($e.Count -gt 0) { $e | ForEach-Object { Write-Output $_.Message }; exit 1 }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", check],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on this machine")
def test_sh_passes_a_bash_syntax_check():
    result = subprocess.run(
        ["bash", "-n", str(SH)], capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr


# --- Release wheels ------------------------------------------------------------


def test_release_workflow_builds_a_reproducible_wheel():
    """The installer prefers the pinned release wheel; this workflow is what
    puts one on each release, pinned to the release commit's timestamp so the
    build is reproducible, with the hash recorded in the notes."""
    assert RELEASE_WORKFLOW.exists()
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "SOURCE_DATE_EPOCH" in text
    assert "sha256sum" in text
    assert "release upload" in text

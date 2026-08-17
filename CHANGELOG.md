# Changelog

All notable changes to IAMAI are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **Cross-tenant trust is now read and questioned.** A new collector reads the
  cross-tenant access policy (default plus partner overrides) with the
  permissions the app already holds, so no re-consent is needed. When the
  tenant accepts another organisation's multifactor claims, the questionnaire
  asks whether that was decided on purpose, and the assessment records the
  decision (control `xtenant-001`).
- **The device code exception is judged on its shape** (control
  `devicecode-001`). A policy blocking the device code flow may excuse
  specific accounts or a device group; excusing an application instead
  reopens the flow for every user, and the report now says so.

### Changed

- **The standard pack's placeholder citations are gone.** Sixteen controls
  carry the researched CISA SCuBA and Microsoft citations from the basics
  pack; the four controls no published source supports carry none. Importing
  a pack with placeholder citations is now rejected, and the compliance
  crosswalk skips placeholders in older assessments.
- The Email one-time code control's explanation now states that the separate
  switch for guests' email codes is unaffected, so turning the method off
  does not lock guests out.

## [1.1.0] - 2026-08-17

### Added

- **One-command install.** Paste one line (`install.sh` on macOS and Linux,
  `install.ps1` on Windows) and it checks Python, creates a virtual
  environment, installs the tool, and puts `iamai` on the PATH. The script is
  hardened against partial downloads.
- A full HTML **user guide** (`docs/guide.html`) covering every command and
  feature in plain English, with a complete command reference.
- A **use-cases page** (`docs/use-cases.html`) showing who the tool is for and
  where it fits.
- A published **sample report** (`docs/example-report.html`) rendered from
  sanitized data, linked from the demo site.
- The **`iamai-review` Claude Code skill** for reading collector output, with a
  catalog of every raw dataset.
- **`ARTIFACTS.md`** and JSON **schemas** (`schemas/`) documenting the assessment
  and plan output for downstream readers.
- **`SECURITY.md`** and **`CONTRIBUTING.md`**.
- **Back and forward navigation** in the questionnaire, with previous answers
  pre-filled on return.
- **Live per-collector progress** during `collect`.
- The trusted-locations question now flags a dominant sign-in address as a likely
  **office or VPN** and invites entering an office IP address or range.

### Changed

- **Data, config and certificates now live in a per-user application
  directory** (platform standard locations) instead of the working directory,
  so the tool behaves the same no matter where it is run from. Set
  `IAMAI_HOME` to override the location; an existing working-directory layout
  can be pointed at with `IAMAI_HOME=.`.
- The report renders **each control as an expandable card** with a one-line
  summary, so a full assessment scans in one screen.
- The report **timezone** is now a validated dropdown of IANA zones instead of
  free text.
- `setup` offers an **Azure CLI fast path** for the one-time helper-app
  registration, alongside the manual portal steps.
- The break-glass and trusted-locations questions now name their "none" and
  "fully remote" cases in the prompt.
- `setup` requests a narrower Graph write scope (`Application.ReadWrite.OwnedBy`),
  and the certificate now expires after 180 days.
- One shared design across the report, plan, wizard and docs pages, with WCAG AA
  contrast, responsive tables, and visible keyboard focus.
- Group transitive-member counts are fetched concurrently, and `collect` no
  longer looks stalled during the long network phase.

### Fixed

- **The standard pack ships inside the package**, so `iamai baseline import`
  works from an installed copy, not only from a source checkout.
- **`sanitize` no longer crashes** on snapshots with more than 508 distinct IPv4
  addresses, which a real 30-day sign-in feed passes easily. Pseudonyms now
  overflow into a non-routable range while staying distinct.
- **Report timezones were silently UTC on Windows.** Added `tzdata` as a
  dependency so `zoneinfo` can resolve zones; timezone answers now take effect.
- Hardened the on-disk key permissions and reduced privilege following two
  security audits.

## [1.0.0]

- Initial release: read a Microsoft Entra tenant, grade its identity security
  against a standard, run a questionnaire, and generate a remediation plan. Read
  only, local, no telemetry.

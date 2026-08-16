# Changelog

All notable changes to IAMAI are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[semantic versioning](https://semver.org/).

## [Unreleased]

Changes staged for the next release.

### Added

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

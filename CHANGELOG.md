# Changelog

All notable changes to IAMAI are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **`iamai --version` (and `-V`)**, the natural way to confirm an install
  worked. The installer now runs it as its own final verification.
- **`iamai doctor`**: one command that checks the install, Python, the config
  file, the sign-in certificate and its expiry, which standard is active,
  whether Microsoft is reachable, and per tenant whether every read
  permission has been consented, each row with the exact next command to run
  when something is wrong. `--offline` skips the network checks.
- A **release workflow** builds a reproducible wheel for every release
  (pinned to the release commit's timestamp) and records its SHA256 in the
  release notes.

### Changed

- **There is no golden tenant.** The standard ships with the tool, fixed and
  versioned, the same for every tenant, which is what makes grades comparable
  across tenants, across time, and between organisations. Setup no longer
  asks for a "golden tenant ID"; `baseline build` (the reference-tenant
  capture) is removed; the overview, guide, and report now all describe the
  standard identically; and every assessment and report states which standard
  and version graded it. Tailoring to one tenant happens in the plan, never
  in the grade.
- **Setup signs you in instead of asking for a Directory ID.** The browser
  opens Microsoft's own sign-in page (device code fallback for machines with
  no browser), the tenant is read from the sign-in and echoed back for
  confirmation, and a suggested short name is offered. The exact scope of the
  one-time sign-in is printed before the browser opens, the Collector's
  read-only permission list is printed before anything is created, and a
  mechanical assertion (plus tests) refuses any permission that is not a
  read. `--tenant-id` pins the tenant for scripted use, the one-time sign-in
  app is remembered so certificate renewal never re-asks for it, and setup
  ends with a summary of exactly what was configured and what to run next.

### Fixed

- **The Windows installer no longer claims success after a failure.** It
  checks every external command's exit code, stops at the first failure with
  what failed and what to try, and prints its success message only after the
  installed `iamai` command has been run and answered. Found on a clean
  Windows first run where pipx failed twice and the installer said "IAMAI is
  installed" anyway.
- **Installing no longer requires git.** Both installers install from a
  plain archive or wheel download: the pinned release wheel when one exists,
  else the release source archive, else the master archive. Stock Windows
  has no git, so the old `git+https` install failed for exactly the audience
  the tool is for.
- The Windows installer now forces UTF-8 on captured output (pipx's emoji
  crashed the cp1252 capture path), pins winget to its own source with
  interactivity disabled so a piped install can never hang on a store
  agreement prompt, filters pipx's own setuptools housekeeping warning, and
  opens with a preflight that reports the machine's state and exactly what
  the installer is about to do.

## [1.2.0] - 2026-08-17

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
- **The Claude skill now walks a new user through setup.** The bundled
  `iamai-review` skill gained a step-by-step setup walkthrough (install,
  app registration, consent, verify, collect, assess, wizard, plan), with
  tests that keep every command it names real and in the right order.

### Changed

- **The standard pack's placeholder citations are gone.** Sixteen controls
  carry the researched CISA SCuBA and Microsoft citations from the basics
  pack; the four controls no published source supports carry none. Importing
  a pack with placeholder citations is now rejected, and the compliance
  crosswalk skips placeholders in older assessments.
- The Email one-time code control's explanation now states that the separate
  switch for guests' email codes is unaffected, so turning the method off
  does not lock guests out.
- **The standard pack no longer grades four method controls no source
  supports.** Certificate-based authentication, software OATH tokens and
  verified credentials are no longer required to be off (a tenant using
  certificate sign-in was getting a false finding for a method Microsoft
  lists as phishing-resistant), and QR code sign-in is now judged on its
  scoping rather than banned outright, matching the basics pack.

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

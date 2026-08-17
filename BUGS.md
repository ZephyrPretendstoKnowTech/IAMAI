# BUGS

Findings from the bug hunt of 2026-08-14, run across the engine, the data
layer, and the output layer after PUB-M0 was accepted. Every finding below was
reproduced against the real code. Fixed items are marked and dated; the rest
are open and ordered by severity within each section.

Severity means: **critical** could harm a real tenant if a person follows the
output, **high** produces a wrong grade or leaks data, **medium** produces
misleading output, **low** is latent or needs an unusual input.

## Critical: the plan can make a tenant less secure

Items 1, 2 and 3 were FIXED 2026-08-14 (commit follows this file's update).
Every finding in this document is now fixed or addressed; the per-section
status lines record the dates. Nothing here is open.

1. **No plan ever generates an enforcement step.** plan.py:1428 gates
   `_cap_enable_step` on `requiredState == "enabled"`, but canon.py:534 only
   produces that when the golden policy was captured enforced. Every
   conditional access control in packs/standard-v1.json, baseline-v1.json and
   baseline-v2.json is `enabledOrReportOnly`, so the branch is dead in every
   shipped artifact. Phase 4 "Enforce" renders "No steps in this phase" while
   checkpoint G4 and the phase text both claim enforcement happened. The MFA
   cohort split, registered-count scoping and legacy-inventory precondition
   are all dead code behind it. test_m4_plan.py:66-75 only reaches the path by
   hand-patching requiredState, which is why the suite stayed green.

2. **An already-enforced policy is switched to report-only and never switched
   back.** plan.py:679 appends "Set Enable policy to Report-only." on the
   branch that edits an *existing* policy. A tenant whose admin MFA policy is
   live but grades PARTIAL is told to align it "in report-only mode". With
   item 1, nothing turns it back on. Following the plan literally removes
   admin MFA from a tenant that already had it. Even with item 1 fixed, this
   strips a live protection for the watch window with nothing in `watchFor`.

3. **Every trusted-network entry gets /32 appended, including IPv6 and free
   text.** plan.py:1037. The trusted-locations options come from raw
   `ipAddress` values in the sign-in feed, which routinely include IPv6, and
   both renderers offer a free-text box with no validation. Answering with
   `2001:db8::1` produces the instruction to add `2001:db8::1/32` as a trusted
   location, which is roughly 2^96 addresses. `the Sydney office/32` is
   accepted just as happily.

## High: the engine grades up when the data does not prove protection

Conservative grading is absolute in CLAUDE.md, so each of these is a contract
violation, not a preference.

Items 4 to 11 were all FIXED 2026-08-14.

4. **Required session controls are silently dropped on every require and block
   control.** grade.py:318 only checks `_session_cover` when the control's
   category is `session`, but canon.py:262 sets the category from the grant,
   so any control with both a grant and a session control loses its session
   requirement. The shipped `cap-002` carries `signInFrequency 14 days`; a
   tenant with 90 days, or none at all, grades FUNCTIONAL with no gaps. This
   blocks SPEC-PUBLIC section 7 items 3, 4 and 5, which are all session
   controls.

5. **No backstop for canonical keys stage 2 does not know about.** grade.py
   compares apps, clientAppTypes, platforms, locations, risk and population.
   `canonical["devices"]` is compared nowhere, and `authFlows` only inside the
   block branch. A policy scoped to compliant devices only, or to device code
   sign-ins only, grades FUNCTIONAL with no gaps against a standard of strong
   MFA for everyone. This is the finding that compounds worst: every new axis
   added to `canonical_cap` is coverage-neutral by default, which means it
   defaults to grading up. It needs an unknown-key guard, not six more
   comparisons.

6. **Population coverage and application coverage are computed
   independently.** grade.py:364-401. An application counts as covered if any
   contributor reaches it, even if that contributor reaches a different
   population. Reproduced: standard requires strong MFA for two admin roles
   over two applications; a tenant with one policy per role, each covering a
   different application, grades FUNCTIONAL with no gaps while Global
   Administrators have no MFA requirement on Exchange. The same defect exists
   on the carve axis at grade.py:390. Introduced by PUB-M0.

7. **Disabled policies are graded as report-only evidence.** grade.py:346.
   Nothing filters `state == "disabled"` from the candidate list, so a
   disabled policy lands in `downgraded_state`, turns MISSING into PARTIAL,
   and emits "Policy is report-only where the standard enforces." The tenant
   has zero protection and the gap text is factually wrong, so the plan tells
   the reader to flip a report-only policy that does not exist.

8. **Candidates covering none of the required population still change the
   outcome, and the surplus duality returns.** grade.py:339-349 adds to
   `unsanctioned_all` and `contributors` before it is known whether the
   candidate covers anything, and the residual-carve loop at 390 iterates
   `contributors` rather than `contributing`. A policy unrelated to the
   control can inject an unsanctioned-exclusion finding while also appearing
   in surplus, which SPEC-PUBLIC section 4 rule 5 forbids.

9. **The conditionalAccess surface does not declare the datasets its
   canonicalization depends on.** grade.py:59. `canonical_cap` resolves grants
   through `auth_strengths` and locations through `named_locations`, but
   neither is listed, so a skipped dataset changes the canonical form instead
   of grading UNKNOWN. With `auth_strengths` skipped a matching policy grades
   PARTIAL "weaker than the standard"; with `named_locations` skipped it
   grades MISSING *and* appears in surplus, reproducing checkpoint finding 2
   that PUB-M0 was meant to close.

10. **A real population gap is swallowed by the weaker-requirement message.**
    grade.py:416. `weaker_reach` absorbs the `All` token however little of it
    the weak policy reaches, so a tenant with one weak policy scoped to a
    single group is told only that the requirement is weak, never that the
    rest of the tenant has no policy at all. Introduced by PUB-M0.

11. **knownOptionalDeviations defeats the reaches-nothing guard.**
    grade.py:325 subtracts deviations from `app_gap` but compares against the
    un-subtracted required set, so a policy scoped to a completely unrelated
    application is accepted as a contributor. Introduced by PUB-M0.

## High: the sanitizer leaks tenant data

The sanitized snapshot exists to be shareable, so each of these defeats its
only purpose.

Items 12 to 18 were all handled 2026-08-14. Items 12 to 17 were fixed and
verified against the live snapshot; item 18 is addressed by pinning rather
than by a behaviour change, for the reason recorded on it.

12. **The displayName branch returns the value with no sanitization at all.**
    sanitize.py:265-272. The intent was to keep policy and role names
    readable; the effect is that the email, GUID, IP and verified-domain
    passes are all skipped for that value. A policy named after a real domain,
    owner UPN and office IP survives byte for byte. Confirmed on live data:
    `deviceDetail.displayName` in the sign-in feeds keeps real workstation
    hostnames.

13. **Dict keys are never sanitized.** sanitize.py:246. `transitiveMemberCounts`
    is keyed by real group object ids. Confirmed on live data: the keys are
    raw while `groups[].id` in the same file is pseudonymized, which is both a
    leak and a referential-integrity break, since the counts no longer join to
    the group list.

14. **A missing domains.json silently disables all domain masking.**
    sanitize.py:301. `_load_verified_domains` returns an empty list and
    nothing checks the manifest, so one failed domains pull means every real
    domain name survives while the command still prints success.

15. **The organization's identity block survives verbatim.** Confirmed on live
    data: `organization[0].displayName` (the real company name), street, city,
    state, postal code and business phones are identical in raw and sanitized.
    CLAUDE.md says never print tenant display names.

16. **Embedded emails and IPs are not handled.** sanitize.py:210. Note 20
    added embedded-GUID handling only. A string containing a UPN and an IP
    keeps the UPN local part and the whole IP. This reaches the sanitized
    manifest through `DatasetRecord.errors`, which carries raw Graph text.

17. **Overlapping verified domains break distinctness.** sanitize.py:222.
    Substring replacement means `payroll.contoso.com` becomes
    `payroll.tenant.example`, leaking the subdomain label, and the longer
    domains never get their own token.

18. ADDRESSED 2026-08-14. **The universal-GUID preserve set is global rather than key-scoped.**
    sanitize.py:277. A GUID seen once under a universal key is preserved
    everywhere, so adding one entry to `UNIVERSAL_KEYS` is a one-line path to
    a leak. Latent today.

## High: collection can report success on incomplete data

Items 19 to 22 were FIXED 2026-08-14.

19. **Retry exhaustion raises a private type no collector catches.**
    graphclient.py:57 re-raises `_RetryableStatusError`, but roles.py:30 and
    groups.py:72 catch only `GraphError`. A persistent 503 on one sub-call
    discards the entire dataset, including data already fetched, and the
    designed graceful-degradation path never runs. Throttling is the expected
    failure mode on a large tenant, so this degrades worst exactly when it
    matters most.

20. **A truncated sign-in feed is consumed as a complete one.**
    signins.py:65. A mid-collection failure leaves a valid gzip containing a
    few events. `grade._legacy_auth_usage` reads it straight off disk with no
    manifest lookup, reports zero legacy events, and the questionnaire and
    plan then drop the legacy authentication work entirely. The snapshot is
    marked partial, but the derived conclusion is presented as fact.

21. **Retry-After crashes on the HTTP-date form and is otherwise uncapped.**
    graphclient.py:163 calls `float()` on the header, which raises on the
    RFC-permitted date form and kills the dataset; line 74 applies the 60
    second cap only to the exponential branch, so `Retry-After: 3600` sleeps
    for an hour silently.

22. **get_paged has no loop guard.** graphclient.py:207 follows nextLink with
    no seen-URL set and no page cap. A self-referential nextLink loops
    forever, and inside the sign-in streamer it writes unbounded data to disk.

## Medium: output that misleads

37. FIXED 2026-08-14. **A weaker session requirement reports as no policy at all.** Found while
    authoring the PUB-M2 session controls. The weaker-overlap diagnostic
    added for grants has no session equivalent, so a policy that covers the
    right people with too long an interval is simply rejected and the control
    grades MISSING with "No target policy contributes coverage of this
    intent." On the lab tenant, session-002 wants administrators
    reauthenticating every 4 hours and the tenant reauthenticates them every
    7 days, which reads as having nothing rather than having something set
    too loosely. Factually wrong in the same way the disabled-policy gap text
    was, and much less actionable: "change 7 days to 4 hours" is a different
    job from "build this from scratch".


Items 23 to 29 were all FIXED 2026-08-14.

23. **A break glass account confirmed on the exclusion question is invisible
    to the plan.** plan.py:330. `_break_glass_answer` reads only the
    `break-glass` answer while `slot_bindings` also honours a `chosenSlot`
    answer of `breakGlassAccounts`, so the grade lifts but the plan tells the
    operator to create a new Global Administrator, marks the day-1
    precondition failed, and leaves the real account off the exclusion list.

24. **A service-account answer stores the option label instead of the
    account.** plan.py:1255. The same trap `_onboarding_groups` documents and
    avoids. The watch list reads "A service account used by software, not a
    person" instead of naming it, so the cross-check the step exists to enable
    is impossible.

25. **Comms promise an enforcement date the plan does not deliver.**
    plan.py:1475 renders the announcement and reminder unconditionally, so a
    two-step report-only plan still tells staff that the second step becomes
    required on a specific date. `uses_tap` has the mirror problem.

26. **The legacy inventory precondition is hardcoded to pass.** plan.py:954
    asserts "Sign in logs were collected for the analysis window" with
    `result="pass"` regardless, and the report renders it as "checked now:
    pass". A fabricated factual claim in a tool whose contract is that it
    never guesses.

27. FIXED 2026-08-14. **The location step contradicts the questionnaire when a named location
    was selected.** plan.py:1062. Ticking an existing named location binds the
    slot but leaves `trustedNetworks` empty, so the step reports that no
    trusted networks were confirmed when they were.

28. **Set answers are accepted, persisted, then never bound.**
    questions.py:490. The required check applies only to freeText, and any
    typed entry that is not a GUID is stored and then dropped by
    `slot_bindings` with no feedback. Typing a UPN on the break-glass question
    persists it and lifts nothing. Same class as the "Mountain Time." timezone
    case: accepted, stored, ignored, never re-asked.

29. **Answers are written non-atomically.** questions.py:530 truncates in
    place, and the docstring one line above claims an interrupted run keeps
    progress. A truncated file raises out of every wizard route, `iamai
    questions` and `iamai plan`, losing every prior answer.

## Medium: snapshot stability

Items 30, 31 and 32 were all FIXED 2026-08-14.

30. FIXED 2026-08-14 (at the repository level). **write_text translates newlines on Windows.** store.py:75, sanitize.py:331,
    config.py:92. Every snapshot, manifest and fixture is CRLF on Windows and
    LF elsewhere, with no .gitattributes, so identical content hashes
    differently depending on where it was produced.

31. FIXED 2026-08-14. **gzip embeds the current time in its header.** signins.py:67,
    sanitize.py:336. Two collects of an unchanged tenant can never produce
    identical bytes. Fix is `mtime=0`.

32. FIXED 2026-08-14. **Six object-array families are left in server order.** store.py:45.
    `assignedPlans`, `servicePlans`, `provisionedPlans`, `verifiedDomains`,
    `rolePermissions` and `certificateUserBindings` match neither sort rule,
    so a server reorder produces a large spurious diff.

## Low

33. FIXED 2026-08-14. **A pack that passes validate_pack can crash the assessment.**
    grade.py:490 indexes `canonical["combos"]` unguarded and validate_pack
    never checks canonical shape, so an authored pack using the Graph field
    name raises KeyError out of `assess_snapshot`.

34. FIXED 2026-08-14. **pseudo_map.json grows unbounded with sign-in event ids.**
    sanitize.py:141. One 30-day lab snapshot produced 10,207 entries. Sign-in
    ids need no cross-snapshot stability.

35. FIXED 2026-08-14. **"P2 not detected" is asserted when licence data is unknown.**
    risky_users.py:20. If the licences pull failed, the skip marker records a
    positive claim about the tenant's licensing that was never verified.

36. FIXED 2026-08-14. **A missing context block aborts the whole report.**
    assessment.html.j2:296 chains attribute access on a Jinja Undefined, so
    `render_assessment({})` raises. Not reachable from the current pipeline;
    it bites on a hand-edited or older-schema assessment read back from disk.

## Checked and clean

No token, Authorization header or private key reaches a log, exception
message or written file. No unescaped assessment or tenant-derived string
reaches HTML: autoescape is on for both the report and the wizard templates.
The wizard binds 127.0.0.1 only. Display names never take part in matching or
grading. No em dashes or brand names in any copy-generating path. The long
list rule is correctly applied everywhere it should be.

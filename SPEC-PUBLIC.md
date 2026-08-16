# SPEC PUBLIC

The contract for the public release. Drafted 2026-08-14 and accepted; it
supersedes the earlier internal specifications, which are no longer part of
this repository. Every rule in CLAUDE.md carries forward except where this
document amends it explicitly.

This document exists because a live checkpoint on the lab tenant found that
the engine graded configuration shape rather than security effect. Three
defects were proven against real tenant data:

1. Overlapping Conditional Access policies are treated as weakening each
   other, when Entra evaluates them additively and requires all of them to
   be satisfied.
2. A policy that achieves the standard's intent through different scoping is
   not counted as a contributor at all, so the same policy can appear as a
   missing control and as an unrecognized extra on one page.
3. Group and user identifiers print as raw GUIDs in output even though their
   names are already present in the snapshot.

Operator decisions recorded at draft time (2026-08-14):

1. Grade on effective outcome across every applicable policy, not on the
   best single matching policy. Accepted.
2. Helping a tenant organize and standardize its policies remains a goal of
   the roadmap even when the tenant is already secure. It is secondary to
   security, and it must never reduce a security grade. Accepted.
3. Draft this spec before further engine work. Accepted.
4. Approved sign in locations are removed from the default basics and
   become optional hardening. Reason in section 7.3. Accepted 2026-08-14.
5. Per user MFA legacy state, application consent settings, standing
   privileged access, and authentication methods policy migration are added
   to the default basics. Accepted 2026-08-14.
6. The operator asked for their own basics list to be reviewed and
   corrected before it was encoded. The corrections are applied in section
   7 and the two load bearing ones were verified against Microsoft Learn at
   draft time. Accepted 2026-08-14.

## 1. What this version is

V1 proved the engine. V2 removed the golden tenant requirement and made the
output human. This version makes the tool safe to hand to a stranger.

The audience is an administrator or managed service provider with little or
no identity expertise, running the tool against their own tenant, with no
help from us. That audience changes three things:

1. The tool must be honest about a tenant that is secure but untidy. A
   tenant with ten sensibly built policies must not be told it is
   non-compliant because its policies are shaped differently from the
   reference.
2. The tool must never change anything. This version is read only, with no
   write scopes, no remediation actions, and no automation. Management
   capability is out of scope and stays out of scope.
3. The tool must be an enablement tool, not a replacement for identity
   experience. It explains, recommends, and teaches. The person decides and
   acts.

## 2. The two axes

This is the central change. Every control is now assessed on two
independent axes, and they are never mixed.

**Security effect.** Is the control's intent actually achieved in this
tenant, by any means, however the configuration is shaped? This produces the
grade. It is the only axis that affects the score.

**Structural conformance.** Does the configuration that achieves it match
the standard's shape, naming, and organization? This produces advisory notes
and roadmap items. It never changes the grade.

A tenant that blocks legacy authentication using three overlapping policies
with unhelpful names is fully secure on axis one and untidy on axis two. It
scores as secure, and its roadmap contains a tidy up item explaining why
consolidating those three policies is worth doing. A tenant that has tidy,
well named policies that do not actually block anything scores as insecure,
and no amount of tidiness offsets that.

Rules:

1. Structural findings are never expressed as gaps and never appear in the
   grade counts.
2. Structural findings appear in their own section of the report and in a
   dedicated later phase of the plan, after every security item.
3. Where a structural finding exists, the report states what the tenant does
   today, what the standard's shape is, and why the difference matters. If
   the only reason is consistency, it says so plainly rather than implying
   risk.

## 3. Effective control evaluation

Conditional Access is additive. When several policies apply to the same
sign in, all of their grant controls must be satisfied. The engine must
model this.

1. For a given control and a given population, the effective requirement is
   the union of the grant controls of every enabled or report only policy
   that applies to that population.
2. A policy whose requirement is broader than the standard's does not weaken
   a policy whose requirement is narrower. The presence of an additional
   overlapping policy can only ever make the effective requirement equal or
   stronger, never weaker.
3. The message "the sign in requirement is weaker than the standard" may
   only be produced when the union across all applicable policies is weaker,
   not when any single policy is weaker.
4. Coverage is evaluated against the effective union too. A population is
   covered when every member of it is reached by at least one policy
   achieving the intent, even when that coverage is split across several
   policies.
5. Conservative grading is unchanged and still absolute. The union is
   computed only from data the collector proved. Where the data cannot
   establish the effective requirement for a population, the control grades
   down and the reason is stated.

Report only policies continue to count toward the required state where the
control's requiredState allows it, as in V2. A policy in report only mode is
labelled as such in evidence so the reader knows it is not yet enforcing.

## 4. Intent level matching

A candidate policy is identified as a contributor to a control when it
achieves the control's intent, not when it matches the control's shape.

1. Matching is on canonical forms only, never on display names. This rule
   from CLAUDE.md is unchanged and is reaffirmed here.
2. Axis differences that do not change the security outcome do not
   disqualify a candidate. Application scope, client app type breadth,
   device filter phrasing, and policy decomposition are the common cases.
3. Where a candidate achieves the intent for part of the required scope,
   it contributes that part. Contributions combine across policies as in
   section 3.
4. Where a candidate achieves the intent through a narrower or broader
   scope than the standard, the difference is recorded as a structural
   finding under section 2, not as a coverage gap.
5. A policy may never appear simultaneously as an uncovered control and as
   a surplus item. Surplus means the engine found no control the policy
   serves. If a policy contributed to any control, it is not surplus.

## 5. Identity resolution in output

The collector already captures display names for groups, users, roles, and
policies. The reporting layer must use them.

1. Every group, user, role, application, and policy identifier that appears
   in a report, plan, questionnaire, or console output is rendered with its
   display name, with the identifier available as secondary detail.
2. Where a name cannot be resolved from the snapshot, the identifier is
   shown alone and the report says the object could not be resolved, which
   is itself a finding worth surfacing.
3. Names are used for display and for questionnaire suggestions only. Names
   never participate in matching or grading. This preserves the CLAUDE.md
   engine rule.
4. The questionnaire uses resolved names to propose likely answers. Where an
   excluded group's name indicates a break glass or bootstrapping purpose,
   the question is presented with that suggestion pre-filled and the
   evidence shown. The person still confirms. A name is a hint to a human,
   never an automatic sanction.
5. Tenant display names remain excluded. The CLAUDE.md rule that tenants are
   referenced by alias only is unchanged.

## 6. Licensing aware grading and best effort

A tenant cannot be graded against controls its licensing cannot support.

1. Every control carries its licenseRequirement, as in the V2 pack schema.
2. The collector determines the tenant's effective identity licensing from
   subscribed SKUs and service plans.
3. Controls the tenant cannot license are excluded from the score, listed
   separately as out of reach, and each states which license would enable
   it and what it would protect against.
4. The tool then produces a best effort target: the strongest posture
   achievable with the licensing the tenant already owns. This is the
   default plan. A tenant with no premium licensing still gets a real,
   useful, achievable roadmap.
5. Where a licensed alternative achieves part of an out of reach control's
   intent, that alternative is offered in the best effort target and the
   residual risk is stated.
6. The report never implies a tenant is insecure for lacking a license it
   was never told it needed. It states the gap, the cost of closing it, and
   the mitigation available without it.

## 7. The default basics pack

When the person says they have no specific framework requirement, the tool
proposes this set. It is a graduated pack in the V2-M2 schema, so every item
is machine checkable and every item can be individually declined.

Every Microsoft specific in this section is verified against current
Microsoft Learn documentation and recorded in ASSUMPTIONS.md before it is
coded, never after. This is the existing CLAUDE.md rule and it applies with
extra force here, because this pack becomes security advice followed by
people who cannot check it themselves.

### 7.1 Enable, enroll, enforce

Three things are routinely conflated and they fail in different ways:

1. Enabling a method in the Authentication methods policy.
2. Enrolling users on that method, driven by the registration campaign and
   Temporary Access Pass.
3. Enforcing its use, through an authentication strength in a Conditional
   Access policy.

Enforcing before enrolling locks people out. Every pack item that depends on
a method states which of the three stages it belongs to, and the generated
plan always sequences them in this order.

### 7.2 Default items

Carried over from the existing pack: legacy authentication blocked,
authentication transfer blocked, device code flow blocked, emergency access
account identification, the authentication methods posture, and the
registration campaign.

1. **Passkey availability and enrollment.** Passkey (FIDO2) enabled in the
   Authentication methods policy, users enrolled through the registration
   campaign, and usage enforced only once enrollment is established. Graded
   as three separate checks per section 7.1.

2. **Emergency access accounts.** Two cloud only accounts on the
   .onmicrosoft.com domain, each registered with a phishing resistant
   method, either a passkey or certificate based authentication, and
   deliberately using a different method from the one normal administrator
   accounts use. They are excluded from Conditional Access policies that
   could block sign in.

   They are not exempt from multifactor authentication, and the pack must
   not suggest they are. Mandatory multifactor authentication for the Azure,
   Entra, and Intune portals is enforced by the client application, not by
   Conditional Access, so excluding an account from every Conditional Access
   policy does not remove that prompt. A password only emergency account
   cannot reach the Entra portal during the emergency it exists for. The
   report states this explicitly wherever it discusses emergency access.

3. **Reauthentication cadence for non administrative users.** Sign in
   frequency of at most 14 days. The report explains that this forces
   reauthentication rather than a visible prompt, and that on a compliant
   device much of it is satisfied silently.

4. **Reauthentication cadence for privileged roles.** Sign in frequency of
   at most 4 hours, targeted at directory roles. Where the tenant uses
   Privileged Identity Management, the report notes that role activation
   already forces fresh authentication and that the two overlap.

5. **Persistent browser sessions for non administrative users.** The
   persistent browser session control requires the policy to target all
   cloud applications and cannot be scoped to a subset, so this is
   necessarily its own policy with administrators excluded. The pack also
   checks whether the legacy remember multifactor authentication on trusted
   devices setting is still enabled, because combining it with sign in
   frequency produces prompts at unexpected times.

   This is a graded control, not a convenience note. Operator ruling,
   2026-08-14: prompt fatigue is a security risk in its own right, because
   people who are asked constantly stop reading what they are approving, and
   that is exactly what a push bombing attack relies on. A tenant that
   prompts more than it needs to has degraded the control it is prompting
   with. The builder proposed reporting this as a structural finding on the
   grounds that it was a usability matter; the operator corrected that, and
   the correction is why it is graded.

   The wider version of this idea, finding unnecessary prompts across a
   tenant and reducing them, is a later version's problem and is explicitly
   out of scope here.

6. **Silent single sign on for compliant devices.** The goal is that people
   on managed devices are not repeatedly prompted. The mechanism is not a
   Windows Hello setting. Windows Hello for Business is inherently
   multifactor, so signing in with it issues a Primary Refresh Token
   carrying the multifactor claim, and that token provides silent single
   sign on for its lifetime. The configuration is therefore to require a
   compliant or Entra joined device and to avoid applying an aggressive sign
   in frequency to that population.

   The pack records that Windows Hello for Business already satisfies the
   phishing resistant authentication strength, so requiring phishing
   resistant methods and using Windows Hello are the same requirement rather
   than competing ones.

7. **Passkeys in Microsoft Authenticator.** Enabled through the Passkey
   (FIDO2) method for tenants not using hardware security keys. Where the
   tenant restricts allowed authenticators by AAGUID, which is otherwise
   good practice, the Microsoft Authenticator AAGUIDs must be present or
   Authenticator passkeys are silently blocked while security keys continue
   to work. iOS and Android have different values. The pack checks for this
   specific misconfiguration because it fails quietly.

8. **Passkey bootstrap and recovery.** Temporary Access Pass configured for
   onboarding new users and for users who have lost their passkey, with its
   state, lifetime bounds, length and single use setting checked.

   Corrected 2026-08-14 after verification: who may issue a Temporary Access
   Pass has no representation in the policy at all. Its includeTargets is who
   may sign in with one. Issuance is a role assignment, so that half of this
   item is a separate check against directory roles and is not claimed by the
   Temporary Access Pass control.

   A Temporary Access Pass does not satisfy the phishing resistant strength,
   so a tenant that requires phishing resistant methods cannot bootstrap with
   one alone. This is a real gap rather than a misconfiguration, and the pack
   must not pretend otherwise. The recommended paths, in order: an identity
   check through Verified ID paired with a Temporary Access Pass, which is
   Microsoft's stated best practice for phishing resistant onboarding; or
   handing the person a security key that is already registered, so the first
   credential never needs bootstrapping.

   Excluding a group from the phishing resistant requirement while people
   enroll is the common workaround and the pack recognizes it, because
   pretending it does not exist helps nobody. It is classified in the
   questionnaire, it sanctions the exclusion so the grade reflects the
   purpose, and the plan watches it for removal and names the two paths above
   as the way to stop needing it. It is never presented as the recommended
   design.

9. **Guest access configuration.** Four separate checks rather than one:
   external collaboration settings governing who may invite guests, cross
   tenant access settings including whether multifactor claims from a
   partner tenant are trusted, guest directory permission restrictions, and
   a Conditional Access policy applying an authentication strength to
   guests. Trusting a partner tenant's multifactor claim is a risk decision
   and gets its own question rather than a default.

10. **Device code flow carve out for conferencing hardware.** Where meeting
    room devices require device code flow, the exclusion is scoped to the
    specific resource accounts or device group. A blanket application
    exclusion reopens the flow for every user and the pack grades it as
    such.

    Deferred to PUB-M2b, 2026-08-14. The conditional machinery in 7.2b reads
    predicates against one configuration object, which suits the
    authentication methods policy and Security Defaults. This check is about
    a set of policies rather than a single object: it has to find the policies
    that block device code flow and then judge how their exclusions are
    scoped. That needs predicates that can quantify over a collection, which
    is a larger addition than the item is worth on its own, and the same
    machinery will serve several PUB-M2b items, so it is built once there
    rather than bent into shape here.

11. **Security Defaults detection.** A tenant running Security Defaults with
    no Conditional Access is the true floor, is common in small tenants, and
    is recognized and explained rather than reported as a pile of missing
    policies.

12. **Risk based policies.** Sign in risk and user risk policies, included
    only where the tenant's licensing supports them, per section 6.

13. **Per user multifactor authentication legacy state.** Accounts still
    carrying the legacy per user enabled or enforced state conflict with
    Conditional Access and produce behavior that is hard to explain. Common
    in tenants that grew organically, cheap to detect, and reported with the
    affected accounts named.

14. **Application consent settings.** User consent restricted to verified
    publishers and low impact permissions, with the administrator consent
    workflow enabled. Illicit consent grants are among the most common real
    identity attacks and this is rarely configured.

15. **Standing privileged access.** The count of accounts holding permanent
    privileged roles. Where licensing supports Privileged Identity
    Management, eligible assignment is recommended over permanent. Where it
    does not, the count and the roles are still surfaced, because most
    tenants answer the question "how many permanent Global Administrators
    do you have" badly.

    Corrected 2026-08-14 after verification, and this moves the item to
    PUB-M2b. The roleAssignments endpoint the collector reads today carries
    no type or time field, so it cannot tell a permanent assignment from a
    Privileged Identity Management activation that happens to be in flight.
    Counting from it would report inflated numbers to exactly the tenants
    using PIM properly, which inverts the advice. The correct source is
    roleAssignmentSchedules filtered to assignmentType Assigned, with
    permanence read from scheduleInfo, and that is a collector this version
    does not have yet.

16. **Authentication methods policy migration.** Tenants still carrying
    legacy separate multifactor and self service password reset method
    configuration rather than the converged Authentication methods policy.
    The exact current state of this migration is verified against Microsoft
    Learn before this item is encoded.

### 7.2b Conditional checks

Raised while authoring 2026-08-14 and resolved the same day: the operator
chose to add conditional controls to the pack schema.

Several items in this list are not conformance checks. They are traps that
only exist when a tenant has configured something a particular way, and the
pack schema cannot express them, because a control says "the canonical form
must equal this" and these say "if X, then Y".

The clearest is the Authenticator AAGUID trap in item 7. Restricting which
authenticators may be registered is good practice. The danger is only that a
tenant which restricts by AAGUID and omits Microsoft Authenticator's two
values silently blocks Authenticator passkeys while security keys keep
working. A control demanding no restriction would be wrong, and a control
demanding the Authenticator values be present would be wrong for every tenant
that deliberately allows only hardware keys. The lab tenant has the
restriction disabled, so nothing to check today.

The Teams carve out in item 10 has the same shape: it only applies if a
carve out exists, and what matters is how narrowly it is scoped.

Neither fits the existing axes. A grade would be wrong because there is no
failure until the condition holds, and a structural finding would be wrong
because SPEC-PUBLIC section 2 defines that axis as explicitly not about
security, while a silently blocked enrollment path is a security outcome. The
options are to add conditional controls to the pack schema, to add a third
output for misconfiguration warnings, or to drop these checks. This needs an
operator decision before the affected items are built.

### 7.3 Optional hardening, not a default

**Approved sign in locations** are deliberately excluded from the default
basics and offered as optional hardening instead.

Location is a weak signal that virtual private networks, travel, and mobile
carriers routinely defeat, and of everything considered for this pack it is
the most likely to cause an outage for someone who follows the advice
without understanding their own environment. For a tool handed to strangers
that is the wrong default.

When selected, it is presented with an explicit warning, a report only
rollout step before enforcement, and a recommendation to restrict the scope
to administrative scenarios where the population is known and the blast
radius is small.

### 7.4 New data and its consent cost

- Active user counts, registered authentication methods, and the most recent
  use of each method per active account all come from data the collector
  already gathers, so they need no new consent.
- Per user multifactor state, consent settings, and privileged role
  assignments are read through permissions the collector already holds.
- Device compliance and join state, needed for item 6, requires an
  additional Graph permission. Every added permission increases the
  friction of the consent step, which is one of this version's main
  promises. Item 6 is therefore graded from Conditional Access device
  filters alone, without the additional permission, and the report states
  that limitation plainly. This is the operator's decision, recorded at
  draft time, and it favors the simplest possible consent.

## 8. Distribution

1. The repository is public on GitHub under the Apache License 2.0. The
   license's warranty disclaimer is the liability position, and it is
   restated in plain language in the README and in generated plan output:
   the tool is read only, it makes no changes, and every recommendation is a
   starting point that must be judged against the specific tenant.
2. A landing page carries a short demo of a real run, the setup steps, and
   an email capture. The capture is in front of the download path, not in
   front of the repository, because a public repository cannot be gated and
   friction would defeat the purpose.
3. Setup must assume no technical knowledge. The documented path is
   measured by whether a competent administrator with no Python experience
   can reach a finished report without help.
4. No telemetry, no analytics, no outbound traffic beyond Graph and login,
   unchanged from V1.

## 9. The collector and the skill

The tool ships as two parts that are useful separately and better together.

1. **The collector.** The existing command line tool. Deterministic, read
   only, local. It collects, grades, and writes artifacts. It contains no
   language model and makes no external calls beyond Graph.
2. **The skill.** A Claude skill the person installs into their own Claude.
   It reads the collector's artifacts, walks the person through setup and
   through their results, and answers questions about their posture.

Rules:

1. The engine remains the only source of truth for grading. The skill reads
   numbers the engine computed and options the pack defines. It never
   invents a control, never restates what a control does in its own terms,
   and never grades.
2. Inference cost sits with the person running it, inside their own Claude
   subscription. The project hosts nothing and pays for no inference.
3. The collector must remain fully usable without the skill. The skill is a
   better front door, not a dependency.
4. This satisfies the V2 rule that no language model ships inside the tool.
   The conversational layer lives outside the deterministic boundary.

## 10. Out of scope, explicitly

1. Any write operation against a tenant, including remediation, policy
   creation, and policy editing. This version is read only. Permanently, for
   this version.
2. Any automatic action taken on the person's behalf.
3. Hosting, multi tenant service, or any component that costs the project
   money per run.
4. Telemetry of any kind.

## 11. Milestones

Build in order, as always. Markers continue from m9.

**PUB-M0, engine correctness (m10).** Sections 2 through 5. Additive
Conditional Access semantics, effect based grading, the structural
conformance axis, the surplus and gap exclusivity rule, and identity
resolution throughout the output. Definition of done: the three proven
defects no longer reproduce, mutation suite extended to cover overlapping
policy combinations and scope variation, pytest across all markers green.
Live acceptance: rerun the checkpoint on the lab tenant and confirm the
grades reflect the tenant's actual security, with structural differences
reported separately and named readably.

**PUB-M1, licensing aware grading (m11).** Section 6, including the best
effort target and the out of reach list.

**PUB-M2, the basics pack (m12).** Section 7, split in two on the operator's
ruling of 2026-08-14 because the milestone as written is several times the
size of PUB-M0 and PUB-M1 and would run a long way with nothing verifiable in
between.

PUB-M2 covers every pack item buildable from the datasets the collector
already gathers, plus the graduated tiers, plus the strict profile. The
strict profile is in rather than deferred: the lab tenant now carries Entra
ID P2, so those controls can be proven live, and PUB-M1's licensing aware
grading means a tenant without P2 sees them as out of reach rather than
failing them. The blocker that caused the original deferral is gone.

PUB-M2b covers what needs data the collector does not yet pull, plus the
authored mitigations from section 6, plus the real citation mapping. The
crosswalk keeps its placeholder citations until then and must not be shipped
publicly with them: naming CIS, SCuBA and Microsoft as sources the tool has
not actually mapped is a credibility claim it cannot support. Either the
mapping lands before the repository goes public or the crosswalk is hidden
until it does.

**PUB-M3, public packaging (m13).** Section 8. License, README rewrite for a
non technical reader, demo, landing page, and a CI workflow running the test
suite. This milestone may be pulled ahead of PUB-M1 and PUB-M2 if the
operator wants the repository public sooner; the tool is publishable once
PUB-M0 lands.

**PUB-M4, the skill (m14).** Section 9.

## 12. What this does to V2-M2

V2-M2's capability is proven. The pack imported cleanly on a live tenant and
became the active baseline with no golden collect, which was the milestone's
purpose. Its live acceptance is superseded rather than failed: the
remaining acceptance criterion, grading the lab tenant to a clean result,
depended on a definition of correctness that this document replaces. It
folds into PUB-M0's live acceptance.

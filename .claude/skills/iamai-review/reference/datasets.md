# Raw dataset catalog

Every file the collector writes under `data/<alias>/<timestamp>/raw/`. These are
raw Microsoft Graph objects, trimmed to the fields IAMAI selected (`$select`), not
the engine's conclusions. For the graded view, read `assessment.json` instead
(contract in `ARTIFACTS.md`). For grading logic, the standard pack ships in
`src/iamai/packs/`.

All of this is real, unsanitised identity data. Read the two hard rules in
`SKILL.md` before querying it: quote sparingly, never transmit it off the machine.

Read `manifest.json` first. Its `datasets` array records, per dataset, the
`endpoint`, `apiVersion`, `count`, `durationSeconds`, `complete` flag, whether it
was `skipped`, and any `errors`. If `complete` is false for a dataset, any answer
drawn from it is partial, so say so.

## The datasets

Shapes below use `[]` for a JSON array of objects and `{}` for a single object.

| File | Shape | What it holds | Key fields |
|---|---|---|---|
| `conditional_access_policies.json` | `[]` | Every CA policy in the tenant. | `id`, `displayName`, `state` (enabled / disabled / enabledForReportingButNotEnforced), `conditions` (users, applications, clientAppTypes, locations, ...), `grantControls` (built-in controls, authenticationStrength, operator), `sessionControls`. |
| `named_locations.json` | `[]` | Named locations CA can key on. | Per location: `id`, `displayName`, and either `ipRanges` (with `cidrAddress`) or country settings. Often empty. |
| `auth_strengths.json` | `[]` | Authentication strength policies. | `id`, `displayName`, `policyType` (builtIn / custom), `allowedCombinations`, `requirementsSatisfied`. |
| `auth_methods_policy.json` | `{}` | Tenant-wide authentication methods policy. | `authenticationMethodConfigurations[]` (each with `id` = method, `state`, `includeTargets`/`excludeTargets` group ids), and `registrationEnforcement.authenticationMethodsRegistrationCampaign`. |
| `security_defaults.json` | `{}` | The security defaults toggle. | `isEnabled`. When true, most CA is unavailable; the engine accounts for this. |
| `authorization_policy.json` | `{}` | Tenant authorization policy. | `allowInvitesFrom`, `allowedToSignUpEmailBasedSubscriptions`, `guestUserRoleId`, `defaultUserRolePermissions` (`allowedToCreateApps`, `allowedToCreateSecurityGroups`, `allowedToCreateTenants`, `allowedToReadOtherUsers`, `permissionGrantPoliciesAssigned`), `blockMsolPowerShell`. |
| `admin_consent_request_policy.json` | `{}` | Admin consent workflow (whether a user asking for an app has somewhere to ask). Graph singleton; `null` here means it could not be read, not that it is unconfigured. | `isEnabled`, `notifyReviewers`, `remindersEnabled`, `requestDurationInDays`, `reviewers[]`. |
| `users.json` | `[]` | Users, selected fields only. | `id`, `userPrincipalName`, `displayName`, `accountEnabled`, `userType` (Member / Guest), `onPremisesSyncEnabled`, `signInActivity` (last sign-in timestamps; needs P1/P2 and AuditLog.Read.All). |
| `registration_details.json` | `[]` | Per-user authentication method registration. | `userPrincipalName`, `isAdmin`, `isMfaCapable`, `isMfaRegistered`, `isPasswordlessCapable`, `isSsprRegistered`, `methodsRegistered[]`, `userPreferredMethodForSecondaryAuthentication`. |
| `roles.json` | `{}` | Directory roles and assignments. | `roleDefinitions[]` (144+ built-in roles: `id`, `displayName`, `isBuiltIn`, `rolePermissions`), `roleAssignments[]` (`principalId`, `roleDefinitionId`, `directoryScopeId`), and `roleEligibilitySchedules` (PIM eligible roles; null without P2). Resolve `principalId` against `users.json`/`groups.json`/`service_principals.json`. |
| `groups.json` | `{}` | Groups plus counts for policy-referenced groups. | `groups[]` (`id`, `displayName`, `groupTypes`, `securityEnabled`, `onPremisesSyncEnabled`, `membershipRule` for dynamic groups); `transitiveMemberCounts` (`{groupId: count}`) only for groups named by a policy. |
| `service_principals.json` | `[]` | Service principals (enterprise apps). | `id`, `appId`, `displayName`, `accountEnabled`. Large in most tenants (100s). |
| `org_licenses.json` | `{}` | Organisation and subscriptions. | `organization[]` (tenant profile, `assignedPlans`), `subscribedSkus[]` (`skuPartNumber`, `consumedUnits`, `prepaidUnits`, `servicePlans[]`). Used to tell P1 from P2. |
| `domains.json` | `[]` | Verified domains. | `id` (domain name), `isDefault`, `isInitial`, `isVerified`, `authenticationType` (Managed / Federated), `supportedServices`. |
| `risky_users.json` | `{}` or `[]` | Identity Protection risky users. | When present: risky user records. Often `{skipped: true, reason: ...}` because it needs Entra ID P2; a skip is not a finding. |
| `signins_interactive.jsonl.gz` | JSONL.gz | Interactive sign-in log, one event per line, gzipped. | Per event: `userPrincipalName`, `userId`, `appDisplayName`, `ipAddress`, `location`, `clientAppUsed`, `conditionalAccessStatus`, `appliedConditionalAccessPolicies[]`, `status`, `riskLevelDuringSignIn`, `riskState`, `createdDateTime`. |
| `signins_noninteractive.jsonl.gz` | JSONL.gz | Non-interactive (service/token) sign-ins, same event shape. | As above. Usually far larger than the interactive feed. |

## Reading tips

- **Sign-ins**: gzipped JSON Lines. Stream a line at a time; do not decompress
  the whole feed into a reply. Python: `import gzip, json; [json.loads(l) for l
  in gzip.open(path, "rt", encoding="utf-8")]`. The feed is a bounded window
  (default 30 days from collect), so a missing event does not prove absence.
- **Joins**: identifiers are GUIDs. Resolve `principalId`, group ids, and
  `appId`/`id` across `users.json`, `groups.json`, and `service_principals.json`.
  The assessment's `names` map already resolves the ones it used.
- **Size**: `service_principals.json`, `users.json`, and `roles.json` are the
  large JSON files. Filter with `jq` or a targeted Python read.
- **Completeness before conclusions**: a dataset marked incomplete in
  `manifest.json`, or a `skipped` collector (commonly `risky_users` without P2),
  bounds what any raw answer can claim. State the limit rather than reading past
  it.

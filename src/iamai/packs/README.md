# Standard packs

A pack is a tenant-free baseline artifact (schemaVersion 2) authored from
published guidance; the tool grades against the bundled one by default.
Import one to override it:

```
iamai baseline import packs/standard-v1.json
```

Import validates the pack (schema, one citation per control, a known profile,
no tenant object ids outside parameter slots) and freezes it into `baselines/`
as the active baseline.

## standard-v1.json

- 20 controls, all `baseline` profile (Entra ID P1). The canonical shapes are
  the proven V1 forms; they grade the sanitized lab fixtures 20/20 FULL.
- Parameter slots (breakGlassAccounts, trustedLocations, serviceAccounts,
  pilotGroups) are declared but unbound. They bind on the target side from the
  questionnaire answers, so the pack carries no tenant data.
- Citations are structural placeholders for now. The real CIS Microsoft 365
  Foundations / CISA SCuBA AAD / Microsoft Conditional Access template mapping
  is a later pass. The report's compliance crosswalk renders whatever
  citations are present and never asserts anything beyond the grades.
- `strict` profile controls (P2: risk policies, PIM) are not yet authored;
  they wait until the lab tenant has Entra ID P2. See ASSUMPTIONS.md note 23.

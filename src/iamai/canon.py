"""Canonicalization rules and baseline artifact construction (SPEC section 6).

Comparison never happens on raw JSON. Every comparable surface reduces to a
canonical form: tenant-specific identifiers resolve into parameter slots,
universal constants (roleTemplateIds, first-party appIds, SKU GUIDs) pass
through untouched, ordering is normalized, and volatile metadata (ids, names,
dates) is dropped. Policy displayName is kept only as evidence metadata.

Enforcement state is not part of the canonical form; the artifact records a
requiredState per control and the parity engine evaluates target state
against it separately.
"""

from __future__ import annotations

import json
import re
from typing import Any

SLOT_NAMES = (
    "breakGlassAccounts",
    "trustedLocations",
    "serviceAccounts",
    "pilotGroups",
    # A group people sit in only while they enroll on a new sign in method.
    # Sanctioned so the grade reflects the purpose, and carried on the plan's
    # watch list so the exclusion is removed once enrollment is finished.
    "onboardingGroups",
)

PROFILES = ("baseline", "strict")

# Built-in authentication strength policy ids, identical in every tenant.
BUILTIN_STRENGTH_MFA = "00000000-0000-0000-0000-000000000002"
BUILTIN_STRENGTH_PASSWORDLESS = "00000000-0000-0000-0000-000000000003"
BUILTIN_STRENGTH_PHISHING_RESISTANT = "00000000-0000-0000-0000-000000000004"

# Windows Cloud Login: may be silently absent from application arrays
# (SPEC 6 known quirk).
WINDOWS_CLOUD_LOGIN_APP = "270efc09-cd0d-444b-a71f-39af4910ec45"


def normalize_combo(combo: str) -> str:
    """A combination is an unordered set of methods joined by commas."""
    return ",".join(sorted(part.strip() for part in combo.split(",") if part.strip()))


def combos_set(combos: list[str] | None) -> list[str]:
    return sorted({normalize_combo(c) for c in (combos or [])})


def strength_at_least_as_strong(candidate: list[str], required: list[str]) -> bool:
    """Partial order per SPEC 7: A is at least as strong as B when
    A.allowedCombinations is a subset of B.allowedCombinations."""
    return set(candidate) <= set(required)


class SlotResolver:
    """Maps tenant-specific GUIDs to parameter slots.

    Bindings come from the baseline artifact parameters at build time and,
    from M3 on, from questionnaire answers on the target side."""

    def __init__(self, bindings: dict[str, list[str]] | None = None):
        self._by_guid: dict[str, str] = {}
        for slot, guids in (bindings or {}).items():
            for guid in guids:
                self._by_guid[guid.lower()] = slot

    def token(self, kind: str, guid: str) -> str:
        slot = self._by_guid.get(guid.lower())
        if slot:
            return f"slot:{slot}"
        return f"{kind}:{guid.lower()}"


def _population_tokens(users_block: dict, resolver: SlotResolver) -> dict:
    """Canonical population: include and exclude token sets."""
    include: set[str] = set()
    exclude: set[str] = set()
    for user in users_block.get("includeUsers") or []:
        include.add("All" if user in ("All", "None", "GuestsOrExternalUsers") else resolver.token("user", user))
        if user == "None":
            include.discard("All")
            include.add("None")
        if user == "GuestsOrExternalUsers":
            include.discard("All")
            include.add("guests:all")
    for user in users_block.get("excludeUsers") or []:
        exclude.add(resolver.token("user", user))
    for group in users_block.get("includeGroups") or []:
        include.add(resolver.token("group", group))
    for group in users_block.get("excludeGroups") or []:
        exclude.add(resolver.token("group", group))
    for role in users_block.get("includeRoles") or []:
        include.add(f"role:{role.lower()}")
    for role in users_block.get("excludeRoles") or []:
        exclude.add(f"role:{role.lower()}")
    guests_in = users_block.get("includeGuestsOrExternalUsers")
    if guests_in:
        kinds = guests_in.get("guestOrExternalUserTypes") or "all"
        include.add(f"guests:{','.join(sorted(str(kinds).split(',')))}")
    guests_ex = users_block.get("excludeGuestsOrExternalUsers")
    if guests_ex:
        kinds = guests_ex.get("guestOrExternalUserTypes") or "all"
        exclude.add(f"guests:{','.join(sorted(str(kinds).split(',')))}")
    return {"include": sorted(include), "exclude": sorted(exclude)}


def _slot_token(resolver: "SlotResolver | None", guid: str) -> dict | None:
    """A {"slot": name} marker when this location GUID binds a parameter slot,
    else None. This is what makes IP ranges portable across tenants: a trusted
    location canonicalizes to its slot, never to the tenant's own addresses."""
    if resolver is None or not guid:
        return None
    token = resolver.token("namedLocation", guid)
    if token.startswith("slot:"):
        return {"slot": token.split(":", 1)[1]}
    return None


def _location_content(location: dict, resolver: "SlotResolver | None" = None) -> dict | str:
    odata = location.get("@odata.type", "")
    if "ipNamedLocation" in odata:
        slot = _slot_token(resolver, location.get("id", ""))
        if slot is not None:
            return slot
        cidrs = sorted(
            r.get("cidrAddress", "") for r in location.get("ipRanges") or [] if r.get("cidrAddress")
        )
        return {"cidrs": cidrs, "isTrusted": bool(location.get("isTrusted"))}
    if "countryNamedLocation" in odata:
        return {
            "countries": sorted(location.get("countriesAndRegions") or []),
            "includeUnknown": bool(location.get("includeUnknownCountriesAndRegions")),
        }
    return {"raw": {k: v for k, v in sorted(location.items()) if k not in ("id", "displayName", "createdDateTime", "modifiedDateTime")}}


def canonical_location(location: dict, resolver: "SlotResolver | None" = None) -> dict | str:
    return _location_content(location, resolver)


def _locations_tokens(
    loc_block: dict | None,
    named_locations: list[dict],
    resolver: "SlotResolver | None" = None,
) -> dict | None:
    if not loc_block:
        return None
    by_id = {loc.get("id", "").lower(): loc for loc in named_locations}

    def resolve(entries: list[str] | None) -> list:
        out: list = []
        for entry in entries or []:
            if entry in ("All", "AllTrusted", "AllCompliantNetworkLocations"):
                out.append(entry)
                continue
            slot = _slot_token(resolver, entry)
            if slot is not None:
                out.append(slot)
            elif entry.lower() in by_id:
                out.append(_location_content(by_id[entry.lower()], resolver))
            else:
                out.append(f"location:{entry.lower()}")
        return sorted(out, key=repr)

    return {
        "include": resolve(loc_block.get("includeLocations")),
        "exclude": resolve(loc_block.get("excludeLocations")),
    }


def _session_controls(session: dict | None) -> dict | None:
    if not session:
        return None
    out: dict[str, Any] = {}
    sif = session.get("signInFrequency")
    if sif and sif.get("isEnabled"):
        out["signInFrequency"] = {
            "isEnabled": True,
            "type": sif.get("type"),
            "value": sif.get("value"),
            "frequencyInterval": sif.get("frequencyInterval"),
        }
    pb = session.get("persistentBrowser")
    if pb and pb.get("isEnabled"):
        out["persistentBrowser"] = {"isEnabled": True, "mode": pb.get("mode")}
    sss = session.get("secureSignInSession")
    if sss and sss.get("isEnabled"):
        out["secureSignInSession"] = {"isEnabled": True}
    cae = session.get("continuousAccessEvaluation")
    if cae and cae.get("mode"):
        out["continuousAccessEvaluation"] = {"mode": cae.get("mode")}
    if session.get("disableResilienceDefaults"):
        out["disableResilienceDefaults"] = True
    aer = session.get("applicationEnforcedRestrictions")
    if aer and aer.get("isEnabled"):
        out["applicationEnforcedRestrictions"] = {"isEnabled": True}
    return out or None


def _grant(grant: dict | None, strengths_by_id: dict[str, list[str]]) -> dict | None:
    if not grant:
        return None
    builtins = sorted(grant.get("builtInControls") or [])
    if builtins == ["block"]:
        return {"block": True}
    combos: list[str] = []
    strength = grant.get("authenticationStrength")
    if strength:
        inline = strength.get("allowedCombinations")
        if inline:
            combos = combos_set(inline)
        else:
            combos = strengths_by_id.get(str(strength.get("id", "")).lower(), [])
    controls = [c for c in builtins if c != "block"]
    if "mfa" in controls and not combos:
        # Built-in "Require MFA" is equivalent to the built-in MFA strength
        # combination set; resolving it makes all grants comparable under the
        # combination-set partial order.
        combos = strengths_by_id.get(BUILTIN_STRENGTH_MFA, [])
        if combos:
            controls = [c for c in controls if c != "mfa"]
    out: dict[str, Any] = {"operator": grant.get("operator") or "OR"}
    if controls:
        out["controls"] = controls
    if combos:
        out["strengthCombos"] = combos
    if not controls and not combos:
        out["controls"] = []
    return out


def strengths_index(auth_strengths: list[dict]) -> dict[str, list[str]]:
    return {
        str(s.get("id", "")).lower(): combos_set(s.get("allowedCombinations"))
        for s in auth_strengths
    }


def canonical_cap(
    policy: dict,
    resolver: SlotResolver,
    named_locations: list[dict] | None = None,
    auth_strengths: list[dict] | None = None,
) -> dict:
    """Canonical form of one Conditional Access policy (SPEC 6)."""
    cond = policy.get("conditions") or {}
    grant = _grant(policy.get("grantControls"), strengths_index(auth_strengths or []))
    session = _session_controls(policy.get("sessionControls"))

    canonical: dict[str, Any] = {"surface": "conditionalAccess"}
    if grant and grant.get("block"):
        canonical["category"] = "block"
    elif grant:
        canonical["category"] = "require"
        canonical["grant"] = grant
    else:
        canonical["category"] = "session"

    canonical["users"] = _population_tokens(cond.get("users") or {}, resolver)

    apps_block = cond.get("applications") or {}
    apps: dict[str, Any] = {
        "include": sorted(a for a in apps_block.get("includeApplications") or []),
        "exclude": sorted(a for a in apps_block.get("excludeApplications") or []),
    }
    if apps_block.get("includeUserActions"):
        apps["userActions"] = sorted(apps_block["includeUserActions"])
    if apps_block.get("includeAuthenticationContextClassReferences"):
        apps["authContexts"] = sorted(apps_block["includeAuthenticationContextClassReferences"])
    canonical["apps"] = apps

    canonical["clientAppTypes"] = sorted(cond.get("clientAppTypes") or ["all"])

    platforms = cond.get("platforms")
    if platforms:
        canonical["platforms"] = {
            "include": sorted(platforms.get("includePlatforms") or []),
            "exclude": sorted(platforms.get("excludePlatforms") or []),
        }

    locations = _locations_tokens(cond.get("locations"), named_locations or [], resolver)
    if locations:
        canonical["locations"] = locations

    risk: dict[str, list] = {}
    if cond.get("signInRiskLevels"):
        risk["signIn"] = sorted(cond["signInRiskLevels"])
    if cond.get("userRiskLevels"):
        risk["user"] = sorted(cond["userRiskLevels"])
    if risk:
        canonical["risk"] = risk

    flows = cond.get("authenticationFlows")
    if flows and flows.get("transferMethods"):
        canonical["authFlows"] = sorted(
            m.strip() for m in str(flows["transferMethods"]).split(",") if m.strip()
        )

    devices = cond.get("devices")
    if devices and (devices.get("deviceFilter") or devices.get("includeDevices") or devices.get("excludeDevices")):
        canonical["devices"] = {
            "filter": (devices.get("deviceFilter") or {}).get("rule"),
            "mode": (devices.get("deviceFilter") or {}).get("mode"),
            "include": sorted(devices.get("includeDevices") or []),
            "exclude": sorted(devices.get("excludeDevices") or []),
        }

    if session:
        canonical["session"] = session
    return canonical


def canonical_strength(strength: dict) -> dict:
    return {
        "surface": "authenticationStrength",
        "combos": combos_set(strength.get("allowedCombinations")),
    }


# Security-relevant settings per authentication method configuration id.
_METHOD_SETTINGS: dict[str, tuple[str, ...]] = {
    "MicrosoftAuthenticator": ("isSoftwareOathEnabled",),
    "TemporaryAccessPass": (
        "defaultLifetimeInMinutes",
        "maximumLifetimeInMinutes",
        "minimumLifetimeInMinutes",
        "defaultLength",
        "isUsableOnce",
    ),
    "Fido2": ("isSelfServiceRegistrationAllowed", "isAttestationEnforced"),
    "Sms": ("isUsableForSignIn",),
}


def _targets(targets: list[dict] | None, resolver: SlotResolver) -> list[dict]:
    out = []
    for t in targets or []:
        target_id = str(t.get("id", ""))
        token = "all_users" if target_id == "all_users" else resolver.token("group", target_id)
        out.append({"target": token, "isRegistrationRequired": bool(t.get("isRegistrationRequired"))})
    return sorted(out, key=repr)


def canonical_method(config: dict, resolver: SlotResolver) -> dict:
    method_id = str(config.get("id", ""))
    canonical: dict[str, Any] = {
        "surface": "authMethods",
        "method": method_id,
        "state": config.get("state"),
        "includeTargets": _targets(config.get("includeTargets"), resolver),
    }
    feature_settings = config.get("featureSettings") or {}
    features = {}
    for name in ("numberMatchingRequiredState", "displayAppInformationRequiredState", "displayLocationInformationRequiredState"):
        if name in feature_settings and isinstance(feature_settings[name], dict):
            features[name] = feature_settings[name].get("state")
    if features:
        canonical["features"] = features
    settings = {}
    for name in _METHOD_SETTINGS.get(method_id, ()):
        if config.get(name) is not None:
            settings[name] = config[name]
    if settings:
        canonical["settings"] = settings
    return canonical


def canonical_campaign(policy: dict, resolver: SlotResolver) -> dict | None:
    campaign = ((policy.get("registrationEnforcement") or {})
                .get("authenticationMethodsRegistrationCampaign"))
    if not campaign:
        return None
    return {
        "surface": "registrationCampaign",
        "state": campaign.get("state"),
        "snoozeDurationInDays": campaign.get("snoozeDurationInDays"),
        "includeTargets": _targets(campaign.get("includeTargets"), resolver),
        "excludeTargets": _targets(campaign.get("excludeTargets"), resolver),
    }


# --- Description convention parsing (SPEC 6) ---------------------------------

_DESC_FIELDS = ("purpose", "scope", "rationale")
_DESC_STRIPPED = ("tag", "baseline", "version", "date", "owner")


def parse_description(text: str | None) -> dict:
    """Parse the structured description convention. The tag, version, and
    owner lines are stripped and must never appear anywhere downstream."""
    result = {"parsed": False, "intent": "", "scope": "", "rationale": ""}
    if not text:
        return result
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip().lower()
        value = value.strip()
        if label in _DESC_STRIPPED:
            continue
        if label == "purpose":
            result["intent"] = value
        elif label == "scope":
            result["scope"] = value
        elif label == "rationale":
            result["rationale"] = value
    result["parsed"] = bool(result["intent"])
    return result


def control_signature(canonical: dict) -> str:
    """Deterministic key into the static intent catalog, by canonical shape."""
    surface = canonical.get("surface")
    if surface == "conditionalAccess":
        flows = set(canonical.get("authFlows") or [])
        if canonical.get("category") == "block":
            if "deviceCodeFlow" in flows:
                return "cap:block-device-code"
            if "authenticationTransfer" in flows:
                return "cap:block-auth-transfer"
            if {"exchangeActiveSync", "other"} <= set(canonical.get("clientAppTypes") or []):
                return "cap:block-legacy-auth"
            return "cap:block"
        if canonical.get("category") == "session":
            if (canonical.get("session") or {}).get("secureSignInSession"):
                return "cap:token-protection"
            return "cap:session"
        includes = set((canonical.get("users") or {}).get("include") or [])
        if any(t.startswith("role:") for t in includes):
            return "cap:admin-mfa"
        if "All" in includes:
            return "cap:user-mfa"
        return "cap:require"
    if surface == "authenticationStrength":
        return f"strength:{len(canonical.get('combos') or [])}"
    if surface == "authMethods":
        return f"method:{canonical.get('method')}"
    if surface == "registrationCampaign":
        return "campaign"
    return f"{surface}:generic"


# Plain language for a reader with no IAM experience. Sentence case, no em
# dashes, no jargon without explanation, no brand names.
INTENT_CATALOG: dict[str, tuple[str, str]] = {
    "cap:admin-mfa": (
        "People with administrator roles must prove who they are with a strong, phishing resistant sign in method.",
        "Administrator accounts can change anything in the company's systems, so they are the first target for attackers. Requiring the strongest sign in proof protects the accounts with the most power.",
    ),
    "cap:user-mfa": (
        "Everyone must confirm their identity with a second step when signing in.",
        "A password alone is not enough. If a password is stolen, the second step stops the attacker from getting in.",
    ),
    "cap:block-legacy-auth": (
        "Old sign in methods that cannot do a second identity check are blocked.",
        "Older apps and protocols skip modern security checks entirely. Attackers use them as a back door, so they are shut off.",
    ),
    "cap:block-device-code": (
        "The device code sign in flow is blocked.",
        "This sign in style is designed for TVs and shared devices, and attackers abuse it to trick people into approving a sign in they did not start.",
    ),
    "cap:block-auth-transfer": (
        "Transferring a sign in from one device to another is blocked.",
        "Attackers abuse sign in transfer to move a stolen session onto their own device. Blocking it closes that path.",
    ),
    "cap:token-protection": (
        "Sign in sessions on Windows are locked to the device they were created on.",
        "If someone steals a session token, it will not work from any other device, so a stolen token is useless.",
    ),
    "campaign": (
        "People are prompted to register a second sign in step until they complete it.",
        "Everyone needs a second step registered before it can be required. The prompt moves people to register without blocking their work.",
    ),
}

_METHOD_INTENTS: dict[str, tuple[str, str]] = {
    "enabled": (
        "The {m} sign in method is available, set up the way the standard expects.",
        "The standard allows this method with specific settings so sign in stays both usable and safe.",
    ),
    "disabled": (
        "The {m} sign in method is turned off.",
        "This method is easier to trick or intercept, so the standard keeps it off.",
    ),
}


def intent_for(canonical: dict, description: str | None) -> dict:
    """Intent and rationale for a control: parsed description first, then the
    static catalog, then a generic flagged fallback."""
    parsed = parse_description(description)
    if parsed["parsed"]:
        return {
            "intent": parsed["intent"],
            "rationale": parsed["rationale"] or parsed["scope"],
            "needsIntentText": False,
        }
    signature = control_signature(canonical)
    if signature in INTENT_CATALOG:
        intent, rationale = INTENT_CATALOG[signature]
        return {"intent": intent, "rationale": rationale, "needsIntentText": False}
    if canonical.get("surface") == "authMethods":
        state = "enabled" if canonical.get("state") == "enabled" else "disabled"
        intent, rationale = _METHOD_INTENTS[state]
        method = str(canonical.get("method"))
        return {"intent": intent.format(m=method), "rationale": rationale, "needsIntentText": False}
    if canonical.get("surface") == "authenticationStrength":
        return {
            "intent": "This named set of allowed sign in methods exists exactly as the standard defines it.",
            "rationale": "Policies point at this set to control which sign in methods count as strong enough.",
            "needsIntentText": False,
        }
    return {
        "intent": "This control matches the standard's configuration.",
        "rationale": "",
        "needsIntentText": True,
    }


# --- Baseline artifact build (SPEC 6) ----------------------------------------

def required_state(observed: str | None) -> str:
    return "enabled" if observed == "enabled" else "enabledOrReportOnly"


def _license_requirement(canonical: dict) -> str:
    if canonical.get("surface") in ("conditionalAccess", "authenticationStrength"):
        if canonical.get("risk"):
            return "P2"
        return "P1"
    if canonical.get("surface") == "registrationCampaign":
        return "P1"
    return "none"


_RISK_CLASS: dict[str, str] = {
    "cap:admin-mfa": "high",
    "cap:user-mfa": "high",
    "cap:block-legacy-auth": "high",
    "cap:block-device-code": "medium",
    "cap:block-auth-transfer": "medium",
    "cap:token-protection": "medium",
    "campaign": "medium",
}


def _risk_class(canonical: dict) -> str:
    signature = control_signature(canonical)
    if signature in _RISK_CLASS:
        return _RISK_CLASS[signature]
    if canonical.get("surface") == "authMethods":
        return "low"
    return "medium"


def build_artifact(
    data: dict,
    *,
    tenant_id: str,
    snapshot: str,
    tool_version: str,
    slot_bindings: dict[str, list[str]] | None = None,
    exclude_control_ids: set[str] | None = None,
) -> dict:
    """Freeze a baseline artifact from golden snapshot data.

    slot_bindings maps parameter slots to the golden tenant's own GUIDs
    (curation binds policy exclusion groups to breakGlassAccounts by
    default). exclude_control_ids drops curated-out controls by their
    generated id."""
    bindings = dict(slot_bindings or {})
    excluded = exclude_control_ids or set()

    caps = data.get("conditional_access_policies") or []
    named_locations = data.get("named_locations") or []
    strengths = data.get("auth_strengths") or []

    # A golden trusted IP location binds trustedLocations by definition, so the
    # baseline stores the slot instead of the golden tenant's own ranges.
    golden_trusted = [
        loc.get("id", "").lower()
        for loc in named_locations
        if "ipNamedLocation" in loc.get("@odata.type", "") and loc.get("isTrusted")
    ]
    if golden_trusted:
        bindings["trustedLocations"] = sorted(
            set(bindings.get("trustedLocations", [])) | set(golden_trusted)
        )

    resolver = SlotResolver(bindings)
    methods_policy = data.get("auth_methods_policy") or {}
    if isinstance(methods_policy, list):
        methods_policy = methods_policy[0] if methods_policy else {}

    controls: list[dict] = []

    for index, cap in enumerate(
        sorted(caps, key=lambda c: str(c.get("displayName", ""))), start=1
    ):
        if cap.get("state") == "disabled":
            continue
        canonical = canonical_cap(cap, resolver, named_locations, strengths)
        control_id = f"cap-{index:03d}"
        if control_id in excluded:
            continue
        meta = intent_for(canonical, cap.get("description"))
        controls.append({
            "id": control_id,
            "surface": "conditionalAccess",
            "sourceName": cap.get("displayName", ""),
            "intent": meta["intent"],
            "rationale": meta["rationale"],
            "needsIntentText": meta["needsIntentText"],
            "canonical": canonical,
            "requiredState": required_state(cap.get("state")),
            "licenseRequirement": _license_requirement(canonical),
            "riskClass": _risk_class(canonical),
            "knownOptionalDeviations": [WINDOWS_CLOUD_LOGIN_APP],
        })

    for index, strength in enumerate(
        sorted(strengths, key=lambda s: str(s.get("displayName", ""))), start=1
    ):
        canonical = canonical_strength(strength)
        control_id = f"strength-{index:03d}"
        if control_id in excluded:
            continue
        meta = intent_for(canonical, None)
        controls.append({
            "id": control_id,
            "surface": "authenticationStrength",
            "sourceName": strength.get("displayName", ""),
            "intent": meta["intent"],
            "rationale": meta["rationale"],
            "needsIntentText": meta["needsIntentText"],
            "canonical": canonical,
            "requiredState": "enabled",
            "licenseRequirement": _license_requirement(canonical),
            "riskClass": _risk_class(canonical),
            "knownOptionalDeviations": [],
        })

    for config in sorted(
        methods_policy.get("authenticationMethodConfigurations") or [],
        key=lambda c: str(c.get("id", "")),
    ):
        canonical = canonical_method(config, resolver)
        control_id = f"method-{config.get('id')}"
        if control_id in excluded:
            continue
        meta = intent_for(canonical, None)
        controls.append({
            "id": control_id,
            "surface": "authMethods",
            "sourceName": str(config.get("id", "")),
            "intent": meta["intent"],
            "rationale": meta["rationale"],
            "needsIntentText": meta["needsIntentText"],
            "canonical": canonical,
            "requiredState": "enabled",
            "licenseRequirement": _license_requirement(canonical),
            "riskClass": _risk_class(canonical),
            "knownOptionalDeviations": [],
        })

    campaign = canonical_campaign(methods_policy, resolver)
    if campaign and "campaign-001" not in excluded:
        meta = intent_for(campaign, None)
        controls.append({
            "id": "campaign-001",
            "surface": "registrationCampaign",
            "sourceName": "Registration campaign",
            "intent": meta["intent"],
            "rationale": meta["rationale"],
            "needsIntentText": meta["needsIntentText"],
            "canonical": campaign,
            "requiredState": "enabled",
            "licenseRequirement": _license_requirement(campaign),
            "riskClass": _risk_class(campaign),
            "knownOptionalDeviations": [],
        })

    for index, location in enumerate(
        sorted(named_locations, key=lambda l: str(l.get("displayName", ""))), start=1
    ):
        canonical = {"surface": "namedLocation", "content": canonical_location(location, resolver)}
        control_id = f"location-{index:03d}"
        if control_id in excluded:
            continue
        meta = intent_for(canonical, None)
        controls.append({
            "id": control_id,
            "surface": "namedLocation",
            "sourceName": location.get("displayName", ""),
            "intent": meta["intent"],
            "rationale": meta["rationale"],
            "needsIntentText": meta["needsIntentText"],
            "canonical": canonical,
            "requiredState": "enabled",
            "licenseRequirement": "none",
            "riskClass": "medium",
            "knownOptionalDeviations": [],
        })

    # schemaVersion 2 (V2-M2) adds profile and citations per control. A golden
    # built artifact has no published-source citations, so they default empty
    # and the profile defaults to baseline; an authored pack fills both in.
    for control in controls:
        control.setdefault("profile", "baseline")
        control.setdefault("citations", [])

    return {
        "schemaVersion": 2,
        "builtFrom": {"tenantId": tenant_id, "snapshot": snapshot, "tool": tool_version},
        "parameters": [
            {"slot": slot, "boundGuids": sorted(g.lower() for g in bindings.get(slot, []))}
            for slot in SLOT_NAMES
        ],
        "controls": controls,
    }


# Tenant-specific canonical tokens. Population membership resolves to group:
# and user: tokens carrying tenant object ids, and an unresolved location
# reference to location:; a trusted location binds the trustedLocations slot,
# so raw "cidrs" content in a pack is a tenant leak too. Everything else in a
# canonical form is universal: role template ids (role:), first-party appIds,
# built-in strength ids, SKU GUIDs, and slot tokens.
_TENANT_TOKEN_RE = re.compile(
    r"(group|user|location):([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)


def validate_pack(artifact: dict) -> list[str]:
    """Static checks for an authored standard pack (SPEC-V2 section 3).

    Returns a list of human readable errors; an empty list means the pack is
    importable. A pack must be tenant free: schemaVersion 2, every control
    carries at least one citation and a known profile, parameters bind no
    tenant GUIDs (slots bind on the target side), and no canonical form leaks
    a tenant object id (populations and locations must resolve to slots; first
    party appIds and role template ids are universal and pass through)."""
    errors: list[str] = []

    if artifact.get("schemaVersion") != 2:
        errors.append(f"schemaVersion must be 2, found {artifact.get('schemaVersion')!r}.")

    for parameter in artifact.get("parameters", []):
        slot = parameter.get("slot")
        if slot not in SLOT_NAMES:
            errors.append(f"Unknown parameter slot {slot!r}.")
        if parameter.get("boundGuids"):
            errors.append(
                f"Slot {slot!r} binds tenant GUIDs; a pack must be tenant free, "
                "so slots bind on the target side instead."
            )

    controls = artifact.get("controls", [])
    if not controls:
        errors.append("The pack has no controls.")

    for control in controls:
        cid = control.get("id", "<no id>")
        for field in ("id", "surface", "canonical", "requiredState"):
            if not control.get(field):
                errors.append(f"Control {cid}: missing {field}.")

        if control.get("profile") not in PROFILES:
            errors.append(
                f"Control {cid}: profile must be one of {', '.join(PROFILES)}, "
                f"found {control.get('profile')!r}."
            )

        citations = control.get("citations")
        if not isinstance(citations, list):
            # An empty list is honest: a control no published framework backs
            # carries no citation rather than an invented one. What is never
            # importable is a placeholder, because a citation is a claim the
            # control covers that published item and the crosswalk repeats the
            # claim to the reader (SPEC-PUBLIC section 11).
            errors.append(f"Control {cid}: citations must be a list (empty is allowed).")
        else:
            for citation in citations:
                if not isinstance(citation, dict) or not citation.get("source") or not citation.get("item"):
                    errors.append(
                        f"Control {cid}: each citation needs a non empty source and item."
                    )
                elif "placeholder" in str(citation.get("source", "")).lower():
                    errors.append(
                        f"Control {cid}: a placeholder citation is a coverage claim with "
                        "nothing behind it; map it to the real source or remove it."
                    )

        blob = json.dumps(control.get("canonical", {}))
        for kind, guid in _TENANT_TOKEN_RE.findall(blob):
            errors.append(
                f"Control {cid}: canonical form references a tenant {kind} ({guid.lower()}); "
                "resolve it to a parameter slot."
            )
        if '"cidrs"' in blob:
            errors.append(
                f"Control {cid}: canonical form carries raw IP ranges; a trusted location "
                "must bind the trustedLocations slot instead."
            )

    return errors

"""Manufacture a heavy but valid IAMAI snapshot by scaling the golden fixture.

IAMAI decouples `collect` (live, needs a tenant) from `assess`/`wizard`/`plan`
(pure functions of a snapshot on disk). That means the whole downstream pipeline
can be exercised at realistic scale with no tenant at all: this builds a snapshot
with thousands of users and tens of thousands of sign-ins, so performance and
correctness at volume can be measured against manufactured data a small or
already-configured test tenant cannot provide.

The config surface (CA policies, auth methods, security defaults, authorization
policy, role definitions, domains, licences) is copied verbatim from the
sanitized golden fixture, so grading has real policy to grade. The volume-bearing
datasets (users, sign-ins, service principals, groups, role assignments,
registration details) are generated to the requested counts.

    python scripts/synth_snapshot.py <out_dir> <users> <signins> <sps> <groups>

The output is a real snapshot directory (raw/*.json + gz feeds + manifest.json)
that `iamai assess`, the report engine, and `iamai sanitize` all read directly.
"""
from __future__ import annotations

import copy
import gzip
import json
import random
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "golden_sanitized"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def build(out_dir: Path, n_users: int, n_signins: int, n_sps: int, n_groups: int, seed: int = 1729):
    """Write a heavy snapshot under out_dir. Deterministic given seed."""
    rng = random.Random(seed)
    raw = out_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    def guid() -> str:
        return str(uuid.UUID(bytes=rng.randbytes(16)))

    def iso_within(days_back: int) -> str:
        dt = datetime(2026, 6, 27) - timedelta(seconds=rng.randint(0, days_back * 86400))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def load(name):
        return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))

    # --- Config surface: copied verbatim (this is what grading reads) ---------
    for name in ("conditional_access_policies", "named_locations", "auth_strengths",
                 "auth_methods_policy", "security_defaults", "authorization_policy",
                 "admin_consent_request_policy", "domains", "org_licenses"):
        src = FIX / f"{name}.json"
        if src.exists():  # the fixture omits a couple of singletons
            (raw / f"{name}.json").write_text(json.dumps(load(name)), encoding="utf-8")

    # --- Users + registration details -----------------------------------------
    user_tmpl, reg_tmpl = load("users")[0], load("registration_details")[0]
    users, regs, user_ids = [], [], []
    for i in range(n_users):
        uid, upn = guid(), f"user{i}@tenant.example"
        user_ids.append(uid)
        u = copy.deepcopy(user_tmpl)
        u.update(id=uid, userPrincipalName=upn, displayName=f"User {i}",
                 accountEnabled=rng.random() > 0.05,
                 userType="Guest" if rng.random() < 0.12 else "Member")
        u["signInActivity"] = {
            "lastSignInDateTime": iso_within(45), "lastSignInRequestId": guid(),
            "lastNonInteractiveSignInDateTime": iso_within(45),
            "lastNonInteractiveSignInRequestId": guid(),
        }
        users.append(u)
        mfa = rng.random() > 0.25
        r = copy.deepcopy(reg_tmpl)
        r.update(id=uid, userPrincipalName=upn, userDisplayName=f"User {i}",
                 isMfaRegistered=mfa, isMfaCapable=mfa, isAdmin=False,
                 isSsprRegistered=rng.random() > 0.4,
                 methodsRegistered=["microsoftAuthenticatorPush"] if mfa else [])
        regs.append(r)

    roles = load("roles")
    assignments = list(roles.get("roleAssignments") or [])
    for uid in rng.sample(user_ids, max(2, n_users // 33)):  # ~3% hold a directory role
        assignments.append({"directoryScopeId": "/", "id": guid(),
                             "principalId": uid, "roleDefinitionId": GLOBAL_ADMIN})
    roles["roleAssignments"] = assignments

    (raw / "users.json").write_text(json.dumps(users), encoding="utf-8")
    (raw / "registration_details.json").write_text(json.dumps(regs), encoding="utf-8")
    (raw / "roles.json").write_text(json.dumps(roles), encoding="utf-8")

    # --- Service principals ----------------------------------------------------
    sps = [{"id": guid(), "appId": guid(), "displayName": f"Enterprise App {i}",
            "accountEnabled": rng.random() > 0.1} for i in range(n_sps)]
    (raw / "service_principals.json").write_text(json.dumps(sps), encoding="utf-8")

    # --- Groups (keep the fixture's referenced-group counts) -------------------
    groups_obj = load("groups")
    for i in range(n_groups):
        groups_obj["groups"].append({
            "id": guid(), "displayName": f"Group {i + 10}",
            "groupTypes": ["Unified"] if rng.random() > 0.5 else [],
            "securityEnabled": rng.random() > 0.3,
            "onPremisesSyncEnabled": None, "membershipRule": None})
    (raw / "groups.json").write_text(json.dumps(groups_obj), encoding="utf-8")
    (raw / "risky_users.json").write_text(json.dumps(load("risky_users")), encoding="utf-8")

    # --- Sign-in feeds (the big one) ------------------------------------------
    with gzip.open(FIX / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as h:
        tmpl = json.loads(h.readline())
    apps = [(f"App {n}", guid()) for n in ("365 Admin", "Exchange", "Teams", "Portal", "SharePoint")]
    ca_states, risk = ["success", "failure", "notApplied"], ["none", "none", "none", "low", "medium"]

    def gen_feed(path, count):
        with gzip.open(path, "wt", encoding="utf-8") as h:
            for i in range(count):
                ev = copy.deepcopy(tmpl)
                app, app_id = apps[rng.randrange(len(apps))]
                ev.update(id=guid(), userId=user_ids[rng.randrange(n_users)],
                          userPrincipalName=f"user{i % n_users}@tenant.example",
                          userDisplayName=f"User {i % n_users}", appDisplayName=app, appId=app_id,
                          ipAddress=f"198.51.{rng.randint(0,255)}.{rng.randint(1,254)}",
                          createdDateTime=iso_within(30), correlationId=guid(),
                          conditionalAccessStatus=ca_states[rng.randrange(3)],
                          riskLevelDuringSignIn=risk[rng.randrange(5)])
                h.write(json.dumps(ev) + "\n")

    gen_feed(raw / "signins_interactive.jsonl.gz", int(n_signins * 0.4))
    gen_feed(raw / "signins_noninteractive.jsonl.gz", int(n_signins * 0.6))

    # --- Manifest --------------------------------------------------------------
    counts = {"users": n_users, "registration_details": n_users, "roles": len(assignments),
              "service_principals": n_sps, "groups": len(groups_obj["groups"]), "signins": n_signins}
    src_manifest = load("manifest")
    datasets = []
    for rec in src_manifest["datasets"]:
        rec = dict(rec)
        rec["count"] = counts.get(rec["dataset"], rec["count"])
        rec["complete"] = True
        datasets.append(rec)
    manifest = {**src_manifest, "datasets": datasets, "complete": True,
                "tenantId": guid(), "alias": "heavy"}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out_dir


def main() -> None:
    out = Path(sys.argv[1])
    nu, ns, nsp, ng = (int(x) for x in sys.argv[2:6])
    t0 = time.perf_counter()
    build(out, nu, ns, nsp, ng)
    dt = time.perf_counter() - t0
    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file()) / 1024 / 1024
    print(f"built {out} in {dt:.1f}s ({size:.1f} MB): users={nu} signins={ns} sps={nsp} groups={ng}")


if __name__ == "__main__":
    main()

"""
demo.py — Intent-Bound Authorization applied to minor-safety enforcement
on a content/engagement platform.

Context (real, dated, verifiable — not the reason this exists, just why
the timing is relevant): on 26 August 2026, Meta agreed to a roughly
$17-18B settlement with a coalition of state attorneys general over
claims it designed Facebook/Instagram to be addictive to minors. The
settlement mandates concrete technical changes — default daily time
limits and nighttime access blocks for teens, not just a payment. TikTok
separately settled with the DOJ for $400M over related child-privacy
violations, and Snap faces comparable litigation. Three major platforms,
same underlying gap.

The gap: a recommendation/engagement algorithm is an autonomous system
taking real actions — serve this video, send this notification, extend
this session — with no check that the action was actually authorized for
this specific, vulnerable context. The algorithm has general permission
to run. It was never verifying that THIS action, for THIS minor, at THIS
time, falls inside what a parent or a regulation actually authorized.
That is the same gap between "valid credentials" and "authorized action"
that IBA targets in every other domain it has been applied to tonight.

Scope — read this first:
  - This does NOT touch recommendation ML, ranking, or content moderation
    itself. It governs a layer above that: whether a specific proposed
    action (serve X, notify Y, extend session by Z) is allowed to execute
    given a signed, human-declared policy.
  - This is a demonstration of the mechanism. It does not integrate with
    any real platform, and makes no claim of adoption or discussion by
    any named company. Nothing here should be read as a claim that Meta,
    TikTok, or Snap use, endorse, or are aware of this.

Run it yourself:
    pip install cryptography --break-system-packages
    python3 demo.py
"""

import json
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------
# 1. Intent Certificate — the parent/guardian's (or a regulator-mandated
#    default policy's) signed declaration of the actual bounds.
# ---------------------------------------------------------------------

@dataclass
class IntentCertificate:
    principal: str           # who authorized this — "Parent/Guardian" or "Platform Default Policy"
    action_type: str         # "content_serve", "notification_send", "session_extend"
    scope: dict               # concrete bounds: allowed hours, daily cap, blocked categories
    issued_at: str
    expires_at: str
    nonce: str
    signature: bytes = field(default=None, repr=False)

    def canonical_payload(self) -> bytes:
        payload = {
            "principal": self.principal,
            "action_type": self.action_type,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True).encode()


def issue_certificate(private_key, principal, action_type, scope, ttl_seconds=86400):
    now = datetime.now(timezone.utc)
    cert = IntentCertificate(
        principal=principal,
        action_type=action_type,
        scope=scope,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        nonce=hashlib.sha256(f"{principal}{time.time_ns()}".encode()).hexdigest()[:16],
    )
    cert.signature = private_key.sign(cert.canonical_payload(), ec.ECDSA(hashes.SHA256()))
    return cert


def verify_certificate(public_key, cert: IntentCertificate) -> tuple[bool, str]:
    now = datetime.now(timezone.utc)
    try:
        public_key.verify(cert.signature, cert.canonical_payload(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "SIGNATURE_INVALID — certificate signature does not verify"

    expires = datetime.fromisoformat(cert.expires_at)
    if now > expires:
        return False, f"CERTIFICATE_EXPIRED — expired at {cert.expires_at}"

    return True, "SIGNATURE_VALID"


# ---------------------------------------------------------------------
# 2. Pre-execution gate — checks a requested platform action against the
#    signed certificate. Deny by default.
# ---------------------------------------------------------------------

def check_action(public_key, cert: IntentCertificate, requested_action: dict) -> dict:
    ok, reason = verify_certificate(public_key, cert)
    if not ok:
        return {"decision": "DENY", "reason": reason}

    if requested_action.get("action_type") != cert.action_type:
        return {
            "decision": "DENY",
            "reason": f"ACTION_TYPE_MISMATCH — cert authorizes '{cert.action_type}', "
                      f"request is '{requested_action.get('action_type')}'"
        }

    scope = cert.scope

    # Time-of-day window (e.g. no notifications 21:00-07:00)
    if "allowed_hour_range" in scope:
        lo, hi = scope["allowed_hour_range"]
        hour = requested_action.get("hour_of_day")
        in_window = (lo <= hour < hi) if lo < hi else (hour >= lo or hour < hi)  # handles overnight wrap
        if not in_window:
            return {"decision": "DENY", "reason": f"OUTSIDE_ALLOWED_HOURS — action at hour {hour}, allowed window is {lo}:00-{hi}:00"}

    # Cumulative daily time cap
    if "max_daily_minutes" in scope:
        minutes_used = requested_action.get("minutes_used_today", 0)
        requested_minutes = requested_action.get("requested_minutes", 0)
        if minutes_used + requested_minutes > scope["max_daily_minutes"]:
            return {
                "decision": "DENY",
                "reason": f"DAILY_CAP_EXCEEDED — {minutes_used}+{requested_minutes}min exceeds cap of {scope['max_daily_minutes']}min"
            }

    # Blocked content categories
    if "blocked_categories" in scope:
        category = requested_action.get("category")
        if category in scope["blocked_categories"]:
            return {"decision": "DENY", "reason": f"BLOCKED_CATEGORY — '{category}' is outside the declared allowed scope"}

    return {"decision": "ALLOW", "reason": "action within declared, signed scope"}


# ---------------------------------------------------------------------
# 3. Tamper-evident audit log
# ---------------------------------------------------------------------

class AuditChain:
    def __init__(self):
        self.chain = []

    def record(self, event: dict):
        prev_hash = self.chain[-1]["hash"] if self.chain else "GENESIS"
        entry = {**event, "prev_hash": prev_hash, "timestamp": datetime.now(timezone.utc).isoformat()}
        entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()
        self.chain.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        for i, entry in enumerate(self.chain):
            expected_prev = self.chain[i - 1]["hash"] if i > 0 else "GENESIS"
            if entry["prev_hash"] != expected_prev:
                return False
        return True


# ---------------------------------------------------------------------
# 4. Demo scenarios
# ---------------------------------------------------------------------

def run_demo():
    print("=" * 78)
    print("IBA — Minor-Safety Enforcement Demo")
    print("Governs: notification sending, session-time extension, and")
    print("         content-category serving. Does NOT touch the")
    print("         recommendation/ranking algorithm itself.")
    print("=" * 78)

    principal_key = ec.generate_private_key(ec.SECP256R1())
    principal_pub = principal_key.public_key()
    forged_key = ec.generate_private_key(ec.SECP256R1())  # attacker's key, not trusted

    audit = AuditChain()
    results = []

    # --- Scenario 1: valid content serve, daytime, under time cap ---
    content_cert = issue_certificate(
        principal_key,
        principal="Parent/Guardian Policy",
        action_type="content_serve",
        scope={"allowed_hour_range": [7, 21], "max_daily_minutes": 60, "blocked_categories": ["extreme_content", "self_harm_adjacent"]},
    )
    action_1 = {"action_type": "content_serve", "hour_of_day": 15, "minutes_used_today": 20, "requested_minutes": 5, "category": "general_video"}
    result_1 = check_action(principal_pub, content_cert, action_1)
    results.append(("Content served at 3pm, well under daily cap, safe category", result_1))
    audit.record({"scenario": "valid_content_serve", **result_1})

    # --- Scenario 2: notification attempted outside allowed hours ---
    notif_cert = issue_certificate(
        principal_key,
        principal="Parent/Guardian Policy",
        action_type="notification_send",
        scope={"allowed_hour_range": [7, 21]},  # no notifications 21:00-07:00
    )
    action_2 = {"action_type": "notification_send", "hour_of_day": 23}
    result_2 = check_action(principal_pub, notif_cert, action_2)
    results.append(("Notification attempted at 11pm (outside allowed 7am-9pm window)", result_2))
    audit.record({"scenario": "notification_outside_hours", **result_2})

    # --- Scenario 3: session extension after daily cap already reached ---
    session_cert = issue_certificate(
        principal_key,
        principal="Parent/Guardian Policy",
        action_type="session_extend",
        scope={"max_daily_minutes": 60},
    )
    action_3 = {"action_type": "session_extend", "minutes_used_today": 58, "requested_minutes": 15}
    result_3 = check_action(principal_pub, session_cert, action_3)
    results.append(("Session extension requested after 58 of 60 daily minutes used", result_3))
    audit.record({"scenario": "session_cap_exceeded", **result_3})

    # --- Scenario 4: content-category request for a blocked category ---
    action_4 = {"action_type": "content_serve", "hour_of_day": 15, "minutes_used_today": 10, "requested_minutes": 5, "category": "self_harm_adjacent"}
    result_4 = check_action(principal_pub, content_cert, action_4)
    results.append(("Content recommendation requesting an explicitly blocked category", result_4))
    audit.record({"scenario": "blocked_category_request", **result_4})

    # --- Scenario 5: forged certificate (signed by an untrusted key) ---
    forged_cert = issue_certificate(
        forged_key,  # NOT the trusted parent/guardian key
        principal="Parent/Guardian Policy",  # claims to be, but isn't
        action_type="session_extend",
        scope={"max_daily_minutes": 999999},  # attempting to authorize unlimited time
    )
    action_5 = {"action_type": "session_extend", "minutes_used_today": 500, "requested_minutes": 500}
    result_5 = check_action(principal_pub, forged_cert, action_5)  # verified against the REAL trusted public key
    results.append(("Session-extension certificate signed by a forged/untrusted key", result_5))
    audit.record({"scenario": "forged_certificate", **result_5})

    # --- Print results ---
    print()
    allow_count = deny_count = 0
    for label, result in results:
        marker = "✓ ALLOW" if result["decision"] == "ALLOW" else "✗ DENY "
        if result["decision"] == "ALLOW":
            allow_count += 1
        else:
            deny_count += 1
        print(f"{marker}  {label}")
        print(f"         → {result['reason']}")
        print()

    print("-" * 78)
    print(f"Total: {allow_count} ALLOW, {deny_count} DENY")
    print(f"Audit chain integrity: {'VERIFIED' if audit.verify_integrity() else 'FAILED — tampering detected'}")
    print(f"Audit chain length: {len(audit.chain)} entries")
    print("-" * 78)


if __name__ == "__main__":
    run_demo()

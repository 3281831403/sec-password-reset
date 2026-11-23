"""One-time password reset tokens with an explicit, deterministic clock.

Storage contract
================
The caller owns a plain dict named store with these keys:

    store["tokens"]       dict[str, dict], keyed by hash_token(raw)
    store["passwords"]    dict[str, str], account name to current password
    store["users"]        set[str], known account names
    store["current_user"] str, the authenticated actor for lookup and consume
    store["rate_events"]  dict[str, list[int]], source IP to attempt times
    store["config"]       dict with ttl_seconds, max_ttl_seconds, bind_user,
                          and rate_limit

A token record stored under a hashed key has this shape:

    {
        "user": str,
        "created_at": int,
        "expires_at": int,
        "used_at": int or None,
    }

Raw tokens are never persisted. All token failures raise ValueError with the
single generic message invalid token, so a caller cannot distinguish an
unknown token, an expired token, a used token, or a token bound to another
user from the exception alone.

Security invariants
===================
Tokens are one time only, are bound to exactly one user, expire with zero
clock tolerance, and are looked up and consumed by their stored hash rather
than by plaintext. Entropy and time are always supplied by the caller; these
functions never read an ambient random source or the wall clock.
"""

import base64
import hashlib
import hmac

_INVALID = "invalid token"


def _is_positive_int(value) -> bool:
    """True only for a real positive int (bool is rejected)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def issue(store: dict, user: str, entropy: bytes, now: int) -> dict:
    """Issue one single-use reset token bound to user.

    entropy must be at least 32 bytes. The returned raw token is a URL-safe
    string of at least 43 characters derived from entropy together with the
    user and now; it is not a sequence number and must not be predictable
    from another issued token. Its lifetime is exactly
    store["config"]["ttl_seconds"] seconds, so expires_at equals now plus
    that TTL. Only hash_token(raw) and the record described in the module
    docstring are written to store["tokens"]; the raw token must not appear
    anywhere in store.

    Return a dict containing raw, token_hash, user, created_at, expires_at,
    and used_at set to None. Raise ValueError for an empty user, entropy
    shorter than 32 bytes, or a non-positive TTL.
    """
    # Defect 1: tokens must be derived from caller-supplied high-entropy
    # bytes, never from an incrementing sequence number.
    if not isinstance(user, str) or not user:
        raise ValueError("invalid user")
    if not isinstance(entropy, (bytes, bytearray)) or len(entropy) < 32:
        raise ValueError("entropy must be at least 32 bytes")

    ttl = store["config"]["ttl_seconds"]
    # Defect 3: the lifetime comes from configuration, not a hard-coded hour.
    if not _is_positive_int(ttl):
        raise ValueError("invalid ttl")

    material = hmac.new(
        entropy, user.encode("utf-8") + b"\x00" + int(now).to_bytes(8, "big"),
        hashlib.sha256,
    ).digest()
    raw = base64.urlsafe_b64encode(material).rstrip(b"=").decode("ascii")

    token_hash = hash_token(raw)
    expires_at = now + ttl
    record = {
        "user": user,
        "created_at": now,
        "expires_at": expires_at,
        "used_at": None,
    }
    # Defect 2: only the hash is ever used as a key or persisted; the raw
    # token exists solely in the value returned to the caller.
    store["tokens"][token_hash] = record

    return {
        "raw": raw,
        "token_hash": token_hash,
        "user": user,
        "created_at": now,
        "expires_at": expires_at,
        "used_at": None,
    }


def hash_token(raw: str) -> str:
    """Return the storage hash for a raw token.

    Use SHA-256 over the UTF-8 bytes of raw and return 64 lowercase hex
    characters. The raw token itself must never be used as a storage key.
    Raise ValueError for an empty or non-string raw value.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError(_INVALID)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _public_record(token_hash: str, record: dict) -> dict:
    """Return a copy of a record that never carries the raw token."""
    return {
        "token_hash": token_hash,
        "user": record["user"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "used_at": record["used_at"],
    }


def lookup(store: dict, raw: str, now: int) -> dict:
    """Look up and validate a token without consuming it.

    Hash raw, load the matching record, and reject it when the record is
    absent, when now is greater than or equal to expires_at, when used_at is
    not None, or when the record is bound to a user other than
    store["current_user"]. The expiry tolerance is exactly zero seconds:
    now equal to expires_at is already expired. When
    store["config"]["bind_user"] is true, a mismatch must raise the same
    generic ValueError as an unknown token; it must never return another
    user's record.

    Return a copy containing token_hash, user, created_at, expires_at, and
    used_at. The raw token is never part of the returned record.
    """
    try:
        token_hash = hash_token(raw)
    except ValueError:
        raise ValueError(_INVALID)

    record = store["tokens"].get(token_hash)
    if record is None:
        raise ValueError(_INVALID)
    # Zero-tolerance expiry: now == expires_at is already expired.
    if now >= record["expires_at"]:
        raise ValueError(_INVALID)
    if record["used_at"] is not None:
        raise ValueError(_INVALID)
    # Defect 4: a token is only ever visible to the user it is bound to.
    if store["config"].get("bind_user") and record["user"] != store["current_user"]:
        raise ValueError(_INVALID)

    return _public_record(token_hash, record)


def consume(store: dict, raw: str, now: int) -> dict:
    """Atomically consume a token and return its record.

    Claim the hashed record with one atomic operation, for example a single
    dict pop, before validating it. Exactly one caller may receive a record
    for a given raw token even when two consumers overlap; every later call
    must raise ValueError. The claim must also verify the zero-tolerance
    expiry and the store["current_user"] binding before reporting success.
    A successful call returns token_hash, user, created_at, expires_at, and
    used_at set to now. A failed call must not leave a reusable token behind.
    """
    try:
        token_hash = hash_token(raw)
    except ValueError:
        raise ValueError(_INVALID)

    # Defect 5: a single atomic pop claims the record before any validation,
    # so two overlapping consumers can never both succeed.
    record = store["tokens"].pop(token_hash, None)
    if record is None:
        raise ValueError(_INVALID)

    expired = now >= record["expires_at"]
    reused = record["used_at"] is not None
    # Defect 4 again: consumption is also bound to the current user.
    wrong_user = (
        store["config"].get("bind_user")
        and record["user"] != store["current_user"]
    )
    if expired or reused or wrong_user:
        # Do not restore: a failed claim must never leave a reusable token.
        raise ValueError(_INVALID)

    record["used_at"] = now
    # Keep the consumed record under its hashed key as an audit trail; it can
    # never be claimed again because its used_at is set, and every later pop
    # fails anyway since the first pop was the only successful claim.
    store["tokens"][token_hash] = record
    return _public_record(token_hash, record)


def revoke_all(store: dict, user: str, now: int) -> int:
    """Revoke every unused token belonging to user.

    Remove all records whose user matches and whose used_at is None,
    including expired but not yet used records. Return the number of records
    removed. Other users' records must be untouched. now is supplied for
    deterministic policy checks and must not be read from the wall clock.
    """
    # Defect 6: revoke the whole set of the user's unused tokens, not one.
    doomed = [
        token_hash
        for token_hash, record in store["tokens"].items()
        if record["user"] == user and record["used_at"] is None
    ]
    for token_hash in doomed:
        del store["tokens"][token_hash]
    return len(doomed)


def rate_limit(store: dict, ip: str, now: int, policy: dict) -> bool:
    """Apply a per-source-IP sliding-window rate limit.

    policy has the shape {"limit": int, "window_seconds": int}. Count
    attempts by ip only, never by token value, so changing tokens cannot
    bypass the limit. Drop events at or before now minus window_seconds,
    deny and return False when the remaining count is at least limit, and
    otherwise record now and return True. A malformed policy raises
    ValueError.
    """
    if not isinstance(policy, dict):
        raise ValueError("invalid policy")
    limit = policy.get("limit")
    window = policy.get("window_seconds")
    if not _is_positive_int(limit) or not _is_positive_int(window):
        raise ValueError("invalid policy")

    # Defect 7: the window is keyed by source IP, so enumerating different
    # tokens from one IP still counts against the same budget.
    events = store["rate_events"].setdefault(ip, [])
    cutoff = now - window
    fresh = [stamp for stamp in events if stamp > cutoff]

    if len(fresh) >= limit:
        store["rate_events"][ip] = fresh
        return False

    fresh.append(now)
    store["rate_events"][ip] = fresh
    return True


def validate_config(config: dict) -> list[str]:
    """Return a list of configuration problem codes.

    An acceptable config has a positive integer ttl_seconds, a positive
    integer max_ttl_seconds, ttl_seconds less than or equal to
    max_ttl_seconds, max_ttl_seconds at most 3600, bind_user exactly true,
    and a rate_limit dict with positive integer limit and window_seconds.
    Return an empty list only when every rule holds. Use these stable codes:
    ttl_seconds_invalid, max_ttl_seconds_invalid, ttl_exceeds_max,
    max_ttl_too_long, user_binding_disabled, rate_limit_missing.
    """
    problems = []

    ttl = config.get("ttl_seconds")
    ttl_ok = _is_positive_int(ttl)
    if not ttl_ok:
        problems.append("ttl_seconds_invalid")

    max_ttl = config.get("max_ttl_seconds")
    max_ttl_ok = _is_positive_int(max_ttl)
    if not max_ttl_ok:
        problems.append("max_ttl_seconds_invalid")

    # Defect 8: enforce the hard upper bound on the token lifetime.
    if max_ttl_ok and max_ttl > 3600:
        problems.append("max_ttl_too_long")

    if ttl_ok and max_ttl_ok and ttl > max_ttl:
        problems.append("ttl_exceeds_max")

    if config.get("bind_user") is not True:
        problems.append("user_binding_disabled")

    rate_limit = config.get("rate_limit")
    rate_ok = (
        isinstance(rate_limit, dict)
        and _is_positive_int(rate_limit.get("limit"))
        and _is_positive_int(rate_limit.get("window_seconds"))
    )
    if not rate_ok:
        problems.append("rate_limit_missing")

    return problems


def reset_batch(requests: list, config: dict, now: int) -> dict:
    """Process password reset attempts independently and return a summary.

    Each request is a dict with store, user, raw, new_password, and ip. Use
    that request's own store for every step: rate limit by ip, set
    store["current_user"] to the claimed user, consume the raw token, require
    the consumed record to be bound to that user, and write new_password to
    store["passwords"][user]. Do not reuse a token iterator, cursor, or
    record between requests; a token may be claimed by exactly one request.
    A failure in one request must not stop the remaining requests.

    Return {"ok_count": int, "fail_count": int, "results": list}. A success
    result is {"ok": True}. An invalid, expired, reused, or wrongly bound
    token, a missing password, or a nonexistent user all produce exactly
    {"ok": False, "error": "invalid_reset"}; the failure shape and text must
    not reveal whether the account exists. A source-IP denial may return
    {"ok": False, "error": "rate_limited"} because it is not user-specific.
    """
    summary = {"ok_count": 0, "fail_count": 0, "results": []}
    generic_failure = {"ok": False, "error": "invalid_reset"}

    for request in requests:
        # Defect 9: every request is handled through its own store and fresh
        # local variables; no cursor, iterator, or record is carried over.
        try:
            store = request["store"]
            user = request["user"]
            raw = request["raw"]
            new_password = request["new_password"]
            ip = request["ip"]

            policy = config["rate_limit"]
            if not rate_limit(store, ip, now, policy):
                summary["results"].append(
                    {"ok": False, "error": "rate_limited"}
                )
                summary["fail_count"] += 1
                continue

            # Defect 10: every user-specific failure collapses into one
            # identical response so account existence cannot be inferred.
            if (
                not isinstance(new_password, str)
                or not new_password
                or user not in store["users"]
            ):
                raise ValueError(_INVALID)

            store["current_user"] = user
            record = consume(store, raw, now)
            if record["user"] != user:
                raise ValueError(_INVALID)

            store["passwords"][user] = new_password
        except (KeyError, TypeError, ValueError):
            summary["results"].append(dict(generic_failure))
            summary["fail_count"] += 1
            continue

        summary["results"].append({"ok": True})
        summary["ok_count"] += 1

    return summary

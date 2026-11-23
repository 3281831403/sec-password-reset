import hashlib

import pytest

from engine.reset import token


def make_store(user="alice", ttl=300):
    return {
        "tokens": {},
        "passwords": {},
        "users": {"alice", "bob"},
        "current_user": user,
        "rate_events": {},
        "config": {
            "ttl_seconds": ttl,
            "max_ttl_seconds": 3600,
            "bind_user": True,
            "rate_limit": {"limit": 20, "window_seconds": 60},
        },
    }


def make_config():
    return {
        "ttl_seconds": 300,
        "max_ttl_seconds": 3600,
        "bind_user": True,
        "rate_limit": {"limit": 20, "window_seconds": 60},
    }


def test_defect_01_tokens_are_not_sequential():
    store = make_store()
    first = token.issue(store, "alice", b"a" * 32, 1000)
    second = token.issue(store, "alice", b"b" * 32, 1001)

    assert first["raw"] != second["raw"]
    assert len(first["raw"]) >= 43
    assert len(second["raw"]) >= 43
    assert not first["raw"].isdigit()
    assert not second["raw"].isdigit()


def test_defect_02_plaintext_token_is_never_stored():
    store = make_store()
    record = token.issue(store, "alice", b"a" * 32, 1000)
    raw = record["raw"]

    assert raw not in repr(store)
    assert token.hash_token(raw) in store["tokens"]
    assert hashlib.sha256(raw.encode("utf-8")).hexdigest() == token.hash_token(raw)


def test_defect_03_expiry_uses_configured_seconds():
    store = make_store(ttl=90)
    now = 1200
    record = token.issue(store, "alice", b"a" * 32, now)

    assert record["expires_at"] == now + 90
    assert record["expires_at"] != now + 3600


def test_defect_04_lookup_rejects_another_users_token():
    store = make_store("alice")
    record = token.issue(store, "alice", b"a" * 32, 1000)
    store["current_user"] = "bob"

    with pytest.raises(ValueError):
        token.lookup(store, record["raw"], 1000)


def test_defect_05_only_one_consume_can_win():
    store = make_store("alice")
    record = token.issue(store, "alice", b"a" * 32, 1000)
    store["current_user"] = "alice"

    outcomes = []
    for _ in range(2):
        try:
            outcomes.append(token.consume(store, record["raw"], 1000))
        except ValueError:
            outcomes.append(None)

    assert len([item for item in outcomes if item is not None]) == 1


def test_defect_06_revoke_all_removes_every_unused_token():
    store = make_store("alice")
    raws = [
        token.issue(store, "alice", bytes([index]) * 32, 1000)["raw"]
        for index in range(1, 4)
    ]
    assert len(set(raws)) == 3

    removed = token.revoke_all(store, "alice", 1000)

    assert removed == 3
    for raw in raws:
        with pytest.raises(ValueError):
            token.lookup(store, raw, 1000)


def test_defect_07_rate_limit_counts_by_source_ip():
    store = make_store()
    now = 2000
    policy = {"limit": 2, "window_seconds": 60}

    assert token.rate_limit(store, "203.0.113.9", now, policy) is True
    assert token.rate_limit(store, "203.0.113.9", now + 1, policy) is True
    assert token.rate_limit(store, "203.0.113.9", now + 2, policy) is False
    assert token.rate_limit(store, "203.0.113.10", now + 2, policy) is True


def test_defect_08_config_rejects_ttl_above_hard_cap():
    config = make_config()
    config["ttl_seconds"] = 86400
    config["max_ttl_seconds"] = 86400

    problems = token.validate_config(config)

    assert "max_ttl_too_long" in problems


def test_defect_09_batch_does_not_reuse_a_token_cursor():
    shared = make_store("alice")
    raw_a = token.issue(shared, "alice", b"a" * 32, 3000)["raw"]
    raw_b = token.issue(shared, "bob", b"b" * 32, 3000)["raw"]

    requests = [
        {
            "store": shared,
            "user": "alice",
            "raw": raw_a,
            "new_password": "new-a",
            "ip": "198.51.100.1",
        },
        {
            "store": shared,
            "user": "bob",
            "raw": raw_b,
            "new_password": "new-b",
            "ip": "198.51.100.2",
        },
    ]
    summary = token.reset_batch(requests, make_config(), 3000)

    assert summary["ok_count"] == 2
    assert summary["fail_count"] == 0
    assert shared["passwords"] == {"alice": "new-a", "bob": "new-b"}
    with pytest.raises(ValueError):
        token.consume(shared, raw_a, 3000)
    with pytest.raises(ValueError):
        token.consume(shared, raw_b, 3000)


def test_defect_10_failure_does_not_reveal_user_existence():
    alice_store = make_store("alice")
    ghost_store = make_store("alice")
    requests = [
        {
            "store": ghost_store,
            "user": "ghost",
            "raw": "never-issued-token",
            "new_password": "new-password",
            "ip": "192.0.2.10",
        },
        {
            "store": alice_store,
            "user": "alice",
            "raw": "never-issued-token",
            "new_password": "new-password",
            "ip": "192.0.2.10",
        },
    ]

    summary = token.reset_batch(requests, make_config(), 4000)
    first, second = summary["results"]

    assert summary["fail_count"] == 2
    assert first == second
    assert first == {"ok": False, "error": "invalid_reset"}


def test_issue_and_consume_succeeds():
    store = make_store("alice")
    now = 5000
    record = token.issue(store, "alice", b"a" * 32, now)

    assert record["user"] == "alice"
    assert record["used_at"] is None
    assert record["expires_at"] == now + 300
    store["current_user"] = "alice"
    found = token.lookup(store, record["raw"], now)
    assert found["user"] == "alice"
    consumed = token.consume(store, record["raw"], now)
    assert consumed["user"] == "alice"
    assert consumed["used_at"] == now


def test_expired_token_is_rejected():
    store = make_store("alice", ttl=60)
    now = 6000
    raw = token.issue(store, "alice", b"a" * 32, now)["raw"]
    store["current_user"] = "alice"

    with pytest.raises(ValueError):
        token.lookup(store, raw, now + 60)


def test_second_consume_is_rejected():
    store = make_store("alice")
    now = 7000
    raw = token.issue(store, "alice", b"a" * 32, now)["raw"]
    store["current_user"] = "alice"
    token.consume(store, raw, now)

    with pytest.raises(ValueError):
        token.consume(store, raw, now)


def test_revoke_invalidates_all_tokens():
    store = make_store("alice")
    now = 8000
    first = token.issue(store, "alice", b"a" * 32, now)["raw"]
    second = token.issue(store, "alice", b"b" * 32, now)["raw"]

    assert token.revoke_all(store, "alice", now) == 2
    with pytest.raises(ValueError):
        token.lookup(store, first, now)
    with pytest.raises(ValueError):
        token.lookup(store, second, now)


def test_batches_match_individual_processing():
    now = 9000
    config = make_config()

    batch_alice = make_store("alice")
    batch_bob = make_store("bob")
    batch_raw_alice = token.issue(batch_alice, "alice", b"a" * 32, now)["raw"]
    batch_raw_bob = token.issue(batch_bob, "bob", b"b" * 32, now)["raw"]
    batch = token.reset_batch(
        [
            {
                "store": batch_alice,
                "user": "alice",
                "raw": batch_raw_alice,
                "new_password": "batch-a",
                "ip": "198.51.100.11",
            },
            {
                "store": batch_bob,
                "user": "bob",
                "raw": batch_raw_bob,
                "new_password": "batch-b",
                "ip": "198.51.100.12",
            },
        ],
        config,
        now,
    )

    solo_alice = make_store("alice")
    solo_bob = make_store("bob")
    solo_raw_alice = token.issue(solo_alice, "alice", b"a" * 32, now)["raw"]
    solo_raw_bob = token.issue(solo_bob, "bob", b"b" * 32, now)["raw"]
    first_solo = token.reset_batch(
        [
            {
                "store": solo_alice,
                "user": "alice",
                "raw": solo_raw_alice,
                "new_password": "batch-a",
                "ip": "198.51.100.11",
            }
        ],
        make_config(),
        now,
    )
    second_solo = token.reset_batch(
        [
            {
                "store": solo_bob,
                "user": "bob",
                "raw": solo_raw_bob,
                "new_password": "batch-b",
                "ip": "198.51.100.12",
            }
        ],
        make_config(),
        now,
    )

    assert batch["ok_count"] == first_solo["ok_count"] + second_solo["ok_count"] == 2
    assert batch["fail_count"] == first_solo["fail_count"] == second_solo["fail_count"] == 0
    assert batch["results"][0] == first_solo["results"][0]
    assert batch["results"][1] == second_solo["results"][0]
    assert solo_alice["passwords"] == {"alice": "batch-a"}
    assert solo_bob["passwords"] == {"bob": "batch-b"}

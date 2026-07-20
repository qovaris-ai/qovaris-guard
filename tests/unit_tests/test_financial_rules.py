"""Tests for the user-defined financial rules (vendor / category / transaction max / off-hours)."""

from datetime import datetime, timedelta

from qovaris.policy_engine import (
    _extract_vendor,
    check_financial_rules,
    fallback_evaluate,
)


def _hhmm(dt):
    return dt.strftime("%H:%M")


# ── Vendor extraction ─────────────────────────────────────────────────────


def test_extract_vendor_from_common_keys():
    assert _extract_vendor({"vendor": "Acme Corp"}) == "Acme Corp"
    assert _extract_vendor({"merchant": " Beta LLC "}) == "Beta LLC"
    assert _extract_vendor({"merchant_name": "Gamma"}) == "Gamma"
    assert _extract_vendor({"seller": "Delta"}) == "Delta"
    assert _extract_vendor({"item": "book", "price": 5}) is None
    assert _extract_vendor({"vendor": ""}) is None


# ── Vendor rules ──────────────────────────────────────────────────────────


def test_vendor_block_rule():
    decision = check_financial_rules(
        {"vendor": "ShadyStore", "price": 10},
        vendor_rules=[{"vendors": ["shadystore"], "action": "block"}],
    )
    assert decision is not None
    assert decision["approved"] is False
    assert decision["requires_hitl"] is False
    assert decision["category"] == "vendor_policy"


def test_vendor_review_rule_requires_hitl():
    decision = check_financial_rules(
        {"merchant": "BigSpend Inc"},
        vendor_rules=[{"vendors": ["bigspend inc"], "action": "review"}],
    )
    assert decision["approved"] is False
    assert decision["requires_hitl"] is True


def test_vendor_allow_list_blocks_unlisted_vendor():
    decision = check_financial_rules(
        {"vendor": "Unknown Shop"},
        vendor_rules=[{"vendors": ["approved shop"], "action": "allow"}],
    )
    assert decision["approved"] is False
    assert "not on the allowed vendor list" in decision["reason"]


def test_vendor_allow_list_passes_listed_and_unknown_vendor():
    rules = [{"vendors": ["approved shop"], "action": "allow"}]
    # Listed vendor passes.
    assert check_financial_rules({"vendor": "Approved Shop"}, vendor_rules=rules) is None
    # A call with no detectable vendor passes (documented MVP semantics).
    assert check_financial_rules({"item": "book"}, vendor_rules=rules) is None


# ── Category rules ────────────────────────────────────────────────────────


def test_category_block_by_slug_and_mcc_code():
    rules = [{"categories": ["tobacco", "5993"], "action": "block"}]
    by_slug = check_financial_rules(
        {"merchant_category": "tobacco_stores"}, category_rules=rules,
    )
    assert by_slug["category"] == "category_policy"
    by_code = check_financial_rules({"mcc_code": "5993"}, category_rules=rules)
    assert by_code["approved"] is False
    # A 4-digit entry must match exactly — different code passes.
    assert check_financial_rules({"mcc_code": "5994"}, category_rules=rules) is None


def test_category_review_rule_requires_hitl():
    decision = check_financial_rules(
        {"merchant_category": "electronics"},
        category_rules=[{"categories": ["electronics"], "action": "review"}],
    )
    assert decision["requires_hitl"] is True


def test_category_limit_rule():
    rules = [{"categories": ["software"], "action": "limit", "limit": 100.0}]
    over = check_financial_rules(
        {"merchant_category": "software", "price": 150.0},
        price=150.0, category_rules=rules,
    )
    assert over["approved"] is False
    assert "100.00" in over["reason"]
    under = check_financial_rules(
        {"merchant_category": "software", "price": 50.0},
        price=50.0, category_rules=rules,
    )
    assert under is None


def test_category_allow_list_blocks_other_categories():
    rules = [{"categories": ["office_supplies"], "action": "allow"}]
    decision = check_financial_rules(
        {"merchant_category": "electronics"}, category_rules=rules,
    )
    assert decision["approved"] is False
    # No category context at all → passes.
    assert check_financial_rules({"item": "book"}, category_rules=rules) is None


# ── Transaction max ───────────────────────────────────────────────────────


def test_transaction_max_blocks_over_limit():
    decision = check_financial_rules(
        {"price": 75.0}, price=75.0, transaction_max=50.0,
    )
    assert decision["approved"] is False
    assert decision["category"] == "budget"
    assert check_financial_rules({"price": 25.0}, price=25.0, transaction_max=50.0) is None


def test_no_rules_returns_none():
    assert check_financial_rules({"vendor": "anyone", "price": 10}) is None


# ── Off-hours rules ───────────────────────────────────────────────────────


def test_off_hours_rule_triggers_hitl_when_inside_window():
    now = datetime.utcnow()
    rules = [{"start": _hhmm(now - timedelta(minutes=5)), "end": _hhmm(now + timedelta(minutes=5))}]
    decision = check_financial_rules({"price": 10}, off_hours_rules=rules)
    assert decision is not None
    assert decision["approved"] is False
    assert decision["requires_hitl"] is True
    assert decision["category"] == "off_hours"


def test_off_hours_rule_passes_when_outside_window():
    now = datetime.utcnow()
    rules = [{"start": _hhmm(now + timedelta(hours=1)), "end": _hhmm(now + timedelta(hours=2))}]
    assert check_financial_rules({"price": 10}, off_hours_rules=rules) is None


def test_off_hours_rule_wraps_midnight():
    # start > end (as times-of-day) means the window crosses midnight —
    # "now" sits just after start, on the wrapped side.
    now = datetime.utcnow()
    rules = [{"start": _hhmm(now - timedelta(minutes=1)), "end": _hhmm(now - timedelta(hours=12))}]
    decision = check_financial_rules({"price": 10}, off_hours_rules=rules)
    assert decision is not None
    assert decision["requires_hitl"] is True


def test_off_hours_rule_ignores_malformed_window():
    assert check_financial_rules({"price": 10}, off_hours_rules=[{"start": "bad", "end": "22:00"}]) is None


# ── Integration with fallback_evaluate ────────────────────────────────────


def test_fallback_evaluate_enforces_vendor_rule():
    decision = fallback_evaluate(
        "Buy a keyboard", "purchase", {"vendor": "ShadyStore", "price": 20.0}, "",
        vendor_rules=[{"vendors": ["shadystore"], "action": "block"}],
    )
    assert decision["approved"] is False
    assert decision["category"] == "vendor_policy"


def test_fallback_evaluate_enforces_transaction_max():
    decision = fallback_evaluate(
        "Buy a $80 keyboard", "purchase", {"price": 80.0}, "",
        transaction_max=50.0,
    )
    assert decision["approved"] is False
    assert decision["category"] == "budget"


def test_fallback_evaluate_hardcoded_mcc_floor_wins_over_allow():
    # The built-in MCC blocklist is a floor: allow-listing a blocked category
    # does not unblock it.
    decision = fallback_evaluate(
        "Place a bet", "purchase",
        {"merchant_category": "gambling_establishments", "price": 5.0}, "",
        category_rules=[{"categories": ["gambling_establishments"], "action": "allow"}],
    )
    assert decision["approved"] is False
    assert decision["category"] == "mcc_policy"


def test_fallback_evaluate_enforces_off_hours():
    now = datetime.utcnow()
    rules = [{"start": _hhmm(now - timedelta(minutes=5)), "end": _hhmm(now + timedelta(minutes=5))}]
    decision = fallback_evaluate(
        "Run a report", "generate_report", {"price": 5.0}, "",
        off_hours_rules=rules,
    )
    assert decision["approved"] is False
    assert decision["requires_hitl"] is True
    assert decision["category"] == "off_hours"


def test_fallback_evaluate_clean_call_passes_with_rules_configured():
    decision = fallback_evaluate(
        "Buy a stapler", "purchase",
        {"vendor": "Office Depot", "price": 12.0}, "",
        spend_threshold=1000.0,
        transaction_max=50.0,
        vendor_rules=[{"vendors": ["shadystore"], "action": "block"}],
        category_rules=[{"categories": ["7995"], "action": "block"}],
    )
    assert decision["approved"] is True

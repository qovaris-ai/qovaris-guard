# Core Concepts

Understand the security model that powers Qovaris.

---

## Architecture Overview

```
        ┌──────────────┐     intent + tool + args     ┌────────────────────┐
 LLM ──▶│  your tool   │ ───────────────────────────▶ │   Qovaris      │
 plans  │  @wrap_tool  │                               │  policy engine     │
        └──────────────┘ ◀─────────────────────────── │  (rules ± LLM)     │
              │            approve / block / review     └────────────────────┘
              │ only runs if approved
              ▼
        real side effect (payment, query, API call)
```

Qovaris sits between the LLM's decision and the tool's execution. Your LLM decides *what* to do. Qovaris decides *whether it's allowed*.

---

## Sessions and Intents

### Sessions

A **session** scopes the user's approved objective. It's created with `guard.session()` as a context manager:

```python
with guard.session("Pay the Acme Corp monthly invoice of $450"):
    # All tool calls in this block are verified against this intent
    pay_vendor("acme-corp", 450.00)
```

Sessions are thread-local, so concurrent agents sharing the same guard instance each have their own active intent.

### Allowed Intent (per-tool)

Each tool also has a **static constraint** via `allowed_intent`:

```python
@guard.wrap_tool(allowed_intent="Execute read-only SELECT queries on the orders table")
def run_query(sql: str) -> str:
    return db.execute(sql)
```

The guard evaluates both the session intent *and* the per-tool intent when making a decision.

---

## Policy Evaluation Pipeline

Every tool call passes through these checks, in order:

### 1. Prompt Injection Detection

Scans tool arguments and intent for known injection patterns:
- `"ignore previous"`, `"override"`, `"bypass"`, `"forget instructions"`
- `"sudo"`, `"jailbreak"`, `"new objective"`

**Result:** Hard block (no HITL override)

### 2. User-Configured Blocked Keywords

Matches against your custom deny-list (configurable per account):

```python
# These keywords are always blocked
blocked_keywords = ["crypto", "gambling", "transfer out"]
```

**Result:** Hard block

### 3. Sensitive Data Access

Blocks access to credential-like fields:
- `password`, `api_key`, `private_key`, `ssn`, `credit_card`, `cvv`

**Result:** Hard block

### 4. Privilege Escalation

Detects attempts to elevate permissions:
- `"superadmin"`, `"grant all"`, `"is_admin = true"`, `"set role admin"`

**Result:** Hard block

### 5. MCC Merchant Blocklist

For payment tools, blocked categories include:
- Gambling, cryptocurrency exchanges, wire transfers
- Cash disbursement, bail/bond, pawn shops, adult entertainment

**Result:** Hard block

### 6. Database Transaction Classification

Classifies SQL found in tool arguments into three tiers:

| Tier | SQL Keywords | Action |
|:-----|:-------------|:-------|
| **Read** | `SELECT` | ✅ Allowed |
| **Write** | `INSERT`, `UPDATE`, `DELETE`, `MERGE` | ⏳ Human review (HITL) |
| **Destructive** | `DROP`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE` | 🛑 Hard block |

### 7. Destructive Tool Names

Tool names containing `delete`, `remove`, `wipe`, `format`, `terminate`, or `destroy` trigger human-in-the-loop review.

**Result:** HITL escalation

### 8. Budget & Spend Controls

- **Budget cap:** Extracts spend limits from the intent text (e.g., "under $50", "max $1000")
- **Spend limit:** Hard ceiling from user configuration
- **HITL threshold:** Configurable per-transaction value that triggers human review

**Result:** Block (over cap) or HITL (over threshold)

---

## Decision Outcomes

Every evaluation produces one of three outcomes:

| Outcome | What Happens | `approved` | `requires_hitl` |
|:--------|:-------------|:-----------|:-----------------|
| **Approved** | Tool executes normally | `true` | `false` |
| **Blocked** | `SecurityBlockException` raised | `false` | `false` |
| **HITL Required** | Routed to human reviewer | `false` | `true` |

In embedded mode, HITL calls go to your `hitl_handler`. In remote mode, they appear in the dashboard review queue.

---

## Dual Evaluation Engine

### Rule-Based Engine (always active)

Deterministic checks that run in microseconds. Covers all the checks described above. This is the **fail-safe fallback** that always works, even offline.

### LLM Semantic Engine (optional)

When a `GEMINI_API_KEY` is set, the guard augments rules with a semantic evaluation using Gemini. The LLM scores the alignment between the agent's proposed action and the user's stated intent. If the LLM is unavailable or times out, the rule engine handles the decision.

```python
# Enable LLM evaluation
import os
os.environ["GEMINI_API_KEY"] = "your-api-key"
```

---

## Reporting & Observability

In embedded mode with `report=True` (default), every decision is fire-and-forget reported to the backend dashboard:

```python
guard = QovarisGuard(
    mode="embedded",
    api_key="nx_live_...",   # enables reporting
    agent_id="my-agent",     # identifies the agent in the dashboard
    report=True,             # default
)
```

This is non-blocking and silent on failure — observability never breaks the agent.

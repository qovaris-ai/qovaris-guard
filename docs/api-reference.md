# API Reference

Complete reference for every class, method, and configuration option in the Qovaris SDK.

---

## `qovaris` module

### `QovarisGuard`

The main guard client. Wraps agent tool calls with security verification.

```python
from qovaris import QovarisGuard
```

#### Constructor

```python
QovarisGuard(
    api_key: str = "nx_free_dev_key",
    gateway_url: str = "http://localhost:8005",
    fail_open: bool = False,
    mode: str = "remote",
    spend_threshold: float = 1000.0,
    hitl_handler: Callable[[dict, dict], bool] | None = None,
    agent_id: str = "",
    report: bool = True,
)
```

| Parameter | Type | Default | Description |
|:----------|:-----|:--------|:------------|
| `api_key` | `str` | `"nx_free_dev_key"` | API key for the backend. Use `nx_free_dev_key` for local dev. |
| `gateway_url` | `str` | `"http://localhost:8005"` | Base URL of the Qovaris backend. |
| `fail_open` | `bool` | `False` | Remote mode: if backend is unreachable, allow the call with a warning. |
| `mode` | `str` | `"remote"` | `"embedded"` (in-process) or `"remote"` (calls backend `/verify`). |
| `spend_threshold` | `float` | `1000.0` | Per-transaction value above which a valid spend needs human review (embedded only). |
| `hitl_handler` | `Callable` | `None` | Embedded: `(payload, decision) -> bool` hook for human review. |
| `agent_id` | `str` | `""` | Identifier surfaced on every dashboard event. |
| `report` | `bool` | `True` | Embedded: fire-and-forget decisions to the backend dashboard. |

#### Methods

##### `session(original_intent: str)`

Context manager scoping the agent's current high-level objective.

```python
with guard.session("Pay the Acme Corp invoice of $450"):
    ...
```

All tool calls inside the block inherit this intent. Sessions are thread-local.

##### `wrap_tool(allowed_intent: str = None)`

Decorator that secures a synchronous tool function.

```python
@guard.wrap_tool(allowed_intent="Purchase office supplies under $50")
def buy(item: str, price: float):
    ...
```

##### `wrap_tool_async(allowed_intent: str = None)`

Decorator that secures an async tool function. The blocking HTTP verification runs in a thread-pool executor.

```python
@guard.wrap_tool_async(allowed_intent="Fetch read-only market data")
async def fetch_quote(symbol: str) -> dict:
    ...
```

##### `current_intent` (property)

Returns the active session intent string.

```python
print(guard.current_intent)
# "Pay the Acme Corp invoice of $450"
```

---

### `SecurityBlockException`

```python
from qovaris import SecurityBlockException
```

Raised when the Qovaris Sentinel gateway blocks a tool invocation. Causes include:

- Semantic intent check failed
- Spending / budget policy violated
- Prompt injection detected
- Gateway unreachable and `fail_open=False`
- HITL required but no handler configured

Inherits from `Exception`. Catch it in your agent to handle blocks gracefully:

```python
try:
    guarded_tool(arg1, arg2)
except SecurityBlockException as e:
    print(f"Action blocked: {e}")
```

---

## `qovaris.integrations.langchain.middleware` module

### `QovarisMiddleware`

```python
from qovaris.integrations.langchain.middleware import QovarisMiddleware
```

An `AgentMiddleware` (LangChain v1 agents framework) that verifies **every** tool
call made by a `create_agent` agent through the Qovaris gateway before execution.
Recommended over per-tool wrapping.

**Requires:** `langchain >= 1.0` (Python ≥ 3.10) — install with the `middleware` extra.

#### Constructor

```python
QovarisMiddleware(
    guard: QovarisGuard,
    allowed_intents: dict[str, str] | None = None,
)
```

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `guard` | `QovarisGuard` | An initialized Qovaris instance (remote or embedded). |
| `allowed_intents` | `dict[str, str] \| None` | Optional per-tool plain-English constraints, keyed by tool name. Tools not listed are verified against the session intent alone. |

Denied calls raise `SecurityBlockException` (same contract as the rest of the SDK),
unless `guard.fail_open` is `True` and the gateway is unreachable. Implements both
the sync `wrap_tool_call` and async `awrap_tool_call` hooks.

#### Usage

```python
from langchain.agents import create_agent

agent = create_agent(
    model="claude-opus-4-8",
    tools=[search, buy],
    middleware=[
        QovarisMiddleware(
            guard,
            allowed_intents={"buy": "Purchase office supplies under $50"},
        )
    ],
)

with guard.session("Order a book under $35"):
    agent.invoke({"messages": [("user", "Order Clean Code")]})
```

---

## `qovaris.integrations.langchain` module

### `QovarisSecureTool`

```python
from qovaris.integrations.langchain import QovarisSecureTool
```

A `BaseTool` wrapper that verifies every invocation through the Qovaris gateway.

**Requires:** `langchain-core >= 0.3.0`

#### Constructor

```python
QovarisSecureTool(
    wrapped_tool: BaseTool,
    guard: QovarisGuard,
    allowed_intent: str = "",
)
```

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `wrapped_tool` | `BaseTool` | The original LangChain tool to protect. |
| `guard` | `QovarisGuard` | An initialized Qovaris instance. |
| `allowed_intent` | `str` | Constraint describing what this tool is permitted to do. |

Inherits the original tool's `name`, `description`, and `args_schema` — it's a transparent drop-in.

#### Usage

```python
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    """Search the catalog."""
    return f"Results for {query}"

secure = QovarisSecureTool(
    wrapped_tool=search,
    guard=guard,
    allowed_intent="Search books under $50",
)

with guard.session("Find affordable books"):
    result = secure.invoke({"query": "python"})
```

---

## `qovaris.integrations.langchain` module

### `QovarisCallback`

```python
from qovaris.integrations.langchain import QovarisCallback
```

A `BaseCallbackHandler` that streams tool invocation and error events to the Qovaris gateway for observability.

**Requires:** `langchain-core >= 0.3.0`

#### Constructor

```python
QovarisCallback(guard: QovarisGuard)
```

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `guard` | `QovarisGuard` | Provides gateway URL and API key for event posting. |

#### Captured Events

| Event | When |
|:------|:-----|
| `tool_start` | A tool begins execution |
| `tool_error` | A tool raises an exception |

This handler is **non-blocking** — it logs events but never prevents execution.

#### Usage

```python
callback = QovarisCallback(guard=guard)
agent.invoke(state, config={"callbacks": [callback]})
```

---

## `qovaris.internal.mpp` module

### `MPPGuard`

```python
from qovaris.internal.mpp import MPPGuard
```

Firewall for [Machine Payments Protocol](https://mpp.dev/) (HTTP 402) purchase intents.

#### Constructor

```python
MPPGuard(
    guard: QovarisGuard,
    allowed_intent: str = "Authorise machine (MPP) payments within session budget",
    reject_expired: bool = True,
)
```

| Parameter | Type | Default | Description |
|:----------|:-----|:--------|:------------|
| `guard` | `QovarisGuard` | — | The guard whose policy engine drives the decision. |
| `allowed_intent` | `str` | `"Authorise machine (MPP) payments within session budget"` | Static constraint for machine payments. |
| `reject_expired` | `bool` | `True` | Reject expired challenges before policy evaluation. |

#### Methods

##### `authorize_challenge(challenge, original_intent=None)`

Evaluate an MPP payment challenge against the firewall.

```python
decision = mpp.authorize_challenge(challenge_header)
```

Returns the decision dict on approval. Raises `SecurityBlockException` if blocked.

##### `guarded_pay(challenge, payer, original_intent=None)`

Authorize then settle — `payer` is only called if approved.

```python
result = mpp.guarded_pay(
    challenge_header,
    payer=lambda c: settle_and_retry(c),
)
```

---

### `PaymentChallenge`

```python
from qovaris.internal.mpp import PaymentChallenge
```

A parsed MPP `Payment` challenge from a `402` response.

#### Attributes

| Attribute | Type | Description |
|:----------|:-----|:------------|
| `id` | `str` | Challenge identifier |
| `realm` | `str` | Auth realm |
| `method` | `str` | Payment method (e.g., `"stripe"`) |
| `intent` | `str` | Payment intent description |
| `expires` | `str` | ISO 8601 expiry timestamp |
| `amount_minor` | `int | None` | Amount in minor units (cents) |
| `amount` | `float | None` | Amount in major units (dollars) |
| `currency` | `str | None` | Currency code |
| `recipient` | `str | None` | Payment recipient |

#### Methods

- `is_expired(now=None)` — Returns `True` if the challenge has expired.
- `to_arguments()` — Builds the firewall arguments dict for this payment.

---

### `parse_payment_challenge(header_value: str)`

Parse a `WWW-Authenticate: Payment ...` header into a `PaymentChallenge`.

```python
from qovaris.internal.mpp import parse_payment_challenge

challenge = parse_payment_challenge(header_value)
print(f"Amount: ${challenge.amount}")
```

Raises `MPPChallengeError` if the header is malformed.

---

## Constants

### Blocked MCC Categories

```python
from qovaris.core import BLOCKED_MCC_CATEGORIES

# {"gambling_establishments", "cryptocurrency_exchanges", "wire_transfers_money_orders",
#  "automated_cash_disburse", "financial_institutions", "bail_and_bond_payments",
#  "pawn_shops", "adult_entertainment"}
```

### Blocked MCC Codes

```python
from qovaris.core import BLOCKED_MCC_CODES

# {"7995", "6051", "6050", "4829", "6011", "6099", "9223", "5933", "7273"}
```

### Default HITL Threshold

```python
from qovaris.core import DEFAULT_HITL_THRESHOLD
# 1000.0
```

---

## Environment Variables

| Variable | Effect |
|:---------|:-------|
| `GEMINI_API_KEY` | Enables LLM-augmented semantic evaluation; rules remain the fallback. |

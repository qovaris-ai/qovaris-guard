# How-To Guides

Step-by-step recipes for common Qovaris integration patterns.

---

## Table of Contents

- [Guard a `create_agent` Agent with Middleware](#guard-a-create_agent-agent-with-middleware)
- [Guard a LangGraph Agent](#guard-a-langgraph-agent)
- [Guard Claude / Anthropic Tool Calls](#guard-claude--anthropic-tool-calls)
- [Guard OpenAI Agent Tool Calls](#guard-openai-agent-tool-calls)
- [Wrap a LangChain BaseTool](#wrap-a-langchain-basetool)
- [Add Observability Callbacks](#add-observability-callbacks)
- [Protect Async Tools](#protect-async-tools)
- [Firewall Stripe MPP Payments](#firewall-stripe-mpp-payments)
- [Implement Human-in-the-Loop](#implement-human-in-the-loop)
- [Set Budget Caps per Session](#set-budget-caps-per-session)
- [Block Custom Keywords](#block-custom-keywords)
- [Report Decisions to the Dashboard](#report-decisions-to-the-dashboard)
- [Handle Gateway Downtime](#handle-gateway-downtime)

---

## Guard a `create_agent` Agent with Middleware

**Goal:** Verify every tool call made by a LangChain ≥ 1.0 `create_agent` agent
with a single drop-in, instead of wrapping each tool. *(Requires
`pip install "qovaris[middleware]"`, Python ≥ 3.10.)*

```python
from langchain.agents import create_agent
from langchain_core.tools import tool
from qovaris import QovarisGuard, SecurityBlockException
from qovaris.integrations.langchain.middleware import QovarisMiddleware

guard = QovarisGuard(mode="embedded", spend_threshold=1000)

@tool
def buy(item: str, price: float) -> str:
    """Buy an item."""
    return f"Bought {item} for ${price}"

agent = create_agent(
    model="claude-opus-4-8",
    tools=[buy],
    # One middleware protects every tool the agent can call.
    middleware=[
        QovarisMiddleware(
            guard,
            allowed_intents={"buy": "Purchase office supplies under $50"},
        )
    ],
)

with guard.session("Order a Python book under $35"):
    # ✅ Aligned + under budget — runs.
    agent.invoke({"messages": [("user", "Order Clean Code for $24.99")]})

    # 🛑 A misaligned or over-budget tool call raises SecurityBlockException.
    try:
        agent.invoke({"messages": [("user", "Order a $5000 laptop")]})
    except SecurityBlockException as e:
        print(f"Blocked: {e}")
```

**Notes:**

- `allowed_intents` is optional and keyed by tool name; tools you omit are still
  verified against the session intent and the guard's policy.
- The middleware enforces the guard's full policy (intent alignment,
  `spend_threshold`, `spend_limit`, `blocked_keywords`) and works in both
  embedded and remote modes.
- For per-tool wrapping or Python 3.9, use
  [`QovarisSecureTool`](#wrap-a-langchain-basetool) instead.

---

## Guard a LangGraph Agent

**Goal:** Protect all tool calls in a LangGraph `StateGraph` agent.

```python
from qovaris import QovarisGuard, SecurityBlockException
from langgraph.graph import StateGraph, END
from langchain_core.tools import tool
from typing import TypedDict

guard = QovarisGuard(mode="embedded", spend_threshold=500)

# Step 1: Decorate your tools
@guard.wrap_tool(allowed_intent="Process vendor payments within approved budget")
@tool
def pay_vendor(vendor_id: str, amount: float) -> dict:
    """Send a payment to a vendor."""
    return {"status": "paid", "vendor": vendor_id, "amount": amount}

@guard.wrap_tool(allowed_intent="Execute approved SQL read queries only")
@tool
def run_query(sql: str) -> list:
    """Run a database query."""
    return [{"result": sql}]

# Step 2: Define your graph
class AgentState(TypedDict):
    messages: list

def agent_node(state: AgentState):
    # Step 3: Open a session with the user's objective
    with guard.session("Pay invoice INV-2024-0391 for Acme Corp, $450"):
        try:
            result = pay_vendor.invoke(
                {"vendor_id": "acme-corp", "amount": 450.00}
            )
            return {"messages": state["messages"] + [str(result)]}
        except SecurityBlockException as e:
            return {"messages": state["messages"] + [f"Blocked: {e}"]}

graph = StateGraph(AgentState)
graph.add_node("agent", agent_node)
graph.set_entry_point("agent")
graph.add_edge("agent", END)
app = graph.compile()

# Run
result = app.invoke({"messages": []})
print(result)
```

**Key points:**
- `@guard.wrap_tool` goes *above* `@tool` so the guard intercepts before LangChain dispatches
- The session intent should match what the user actually approved
- `SecurityBlockException` is catchable — the agent can gracefully report the block

---

## Guard Claude / Anthropic Tool Calls

**Goal:** Intercept every `tool_use` block from Claude before executing it.

```python
from qovaris import QovarisGuard, SecurityBlockException
import anthropic

guard = QovarisGuard(mode="embedded", spend_threshold=1000)
client = anthropic.Anthropic()

# Step 1: Protect your tool functions
@guard.wrap_tool(allowed_intent="Transfer funds between approved accounts only")
def transfer_funds(from_account: str, to_account: str, amount: float):
    """Execute a fund transfer."""
    return {"status": "transferred", "amount": amount}

@guard.wrap_tool(allowed_intent="Read approved database tables for reporting")
def query_database(table: str, filters: dict):
    """Query a database table."""
    return {"table": table, "rows": 42}

# Step 2: Build tool definitions for Claude
tools = [
    {
        "name": "transfer_funds",
        "description": "Transfer money between accounts",
        "input_schema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["from_account", "to_account", "amount"],
        },
    },
]

# Step 3: Dispatch tool calls through guarded functions
TOOL_DISPATCH = {
    "transfer_funds": transfer_funds,
    "query_database": query_database,
}

def run_agent(task: str):
    with guard.session(original_intent=task):
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            tools=tools,
            messages=[{"role": "user", "content": task}],
        )
        for block in response.content:
            if block.type == "tool_use":
                try:
                    fn = TOOL_DISPATCH[block.name]
                    return fn(**block.input)  # ← Qovaris intercepts here
                except SecurityBlockException as e:
                    return {"error": f"Blocked by Qovaris: {e}"}

result = run_agent("Transfer $500 to account ACC-9201 for Q4 supplier invoice")
print(result)
```

---

## Guard OpenAI Agent Tool Calls

**Goal:** Intercept OpenAI `tool_calls` before executing them.

```python
from qovaris import QovarisGuard, SecurityBlockException
from openai import OpenAI
import json

guard = QovarisGuard(mode="embedded", spend_threshold=5000)
client = OpenAI()

# Step 1: Guard critical agent tools
@guard.wrap_tool(allowed_intent="Submit approved purchase orders under $5000")
def submit_purchase_order(vendor: str, items: list, total: float):
    """Submit a purchase order to a vendor."""
    return {"po_id": "PO-2024-0812", "vendor": vendor, "total": total}

# Step 2: Define tools for OpenAI
tools = [
    {
        "type": "function",
        "function": {
            "name": "submit_purchase_order",
            "description": "Submit a purchase order to a vendor",
            "parameters": {
                "type": "object",
                "properties": {
                    "vendor": {"type": "string"},
                    "items": {"type": "array", "items": {"type": "string"}},
                    "total": {"type": "number"},
                },
                "required": ["vendor", "items", "total"],
            },
        },
    },
]

# Step 3: Dispatch through guarded functions
TOOL_DISPATCH = {"submit_purchase_order": submit_purchase_order}

def run_procurement_agent(task: str):
    with guard.session(original_intent=task):
        messages = [{"role": "user", "content": task}]
        response = client.chat.completions.create(
            model="gpt-4o", tools=tools, messages=messages
        )
        call = response.choices[0].message.tool_calls[0]
        try:
            fn = TOOL_DISPATCH[call.function.name]
            args = json.loads(call.function.arguments)
            return fn(**args)  # ← Qovaris verifies intent + policy
        except SecurityBlockException as e:
            return {"blocked": True, "reason": str(e)}

result = run_procurement_agent("Order 50 MacBook Pros for the engineering team")
print(result)
```

---

## Wrap a LangChain BaseTool

**Goal:** Use `QovarisSecureTool` to protect an existing LangChain tool without changing its code.

```python
from langchain_core.tools import tool
from qovaris import QovarisGuard
from qovaris.integrations.langchain import QovarisSecureTool

guard = QovarisGuard(mode="embedded", spend_threshold=1000)

# Your existing tool — no changes needed
@tool
def run_query(sql: str) -> str:
    """Run a database query."""
    return f"Executed: {sql}"

# Wrap it with Qovaris
secure_query = QovarisSecureTool(
    wrapped_tool=run_query,
    guard=guard,
    allowed_intent="Execute read-only SELECT queries on approved tables",
)

# Use the secure version in your chain or agent
with guard.session("How many orders shipped this month?"):
    # ✅ Approved — read query matches intent
    result = secure_query.invoke({"sql": "SELECT count(*) FROM orders"})
    print(result)

    # 🛑 Blocked — destructive SQL detected
    try:
        secure_query.invoke({"sql": "DROP TABLE orders"})
    except Exception as e:
        print(f"Blocked: {e}")
```

**Note:** `QovarisSecureTool` preserves the original tool's `name`, `description`, and `args_schema`, so it's a transparent drop-in replacement.

---

## Add Observability Callbacks

**Goal:** Log tool events to the dashboard without blocking execution.

```python
from qovaris import QovarisGuard
from qovaris.integrations.langchain import QovarisCallback

guard = QovarisGuard(
    mode="remote",
    api_key="nx_live_...",
    agent_id="my-agent",
)

# Create the callback
callback = QovarisCallback(guard=guard)

# Pass to your LangChain / LangGraph agent
agent.invoke(
    {"messages": [...]},
    config={"callbacks": [callback]},
)
```

The callback is **non-blocking** — it logs events but never prevents execution. Use it alongside `QovarisSecureTool` for both enforcement and observability.

---

## Protect Async Tools

**Goal:** Guard async tool functions without blocking the event loop.

```python
import asyncio
from qovaris import QovarisGuard, SecurityBlockException

guard = QovarisGuard(mode="embedded", spend_threshold=500)

@guard.wrap_tool_async(allowed_intent="Fetch read-only market data")
async def fetch_quote(symbol: str) -> dict:
    """Fetch a stock quote from the market API."""
    # Simulating an async API call
    await asyncio.sleep(0.1)
    return {"symbol": symbol, "price": 150.25}

async def main():
    with guard.session("Check current prices for AAPL and GOOGL"):
        result = await fetch_quote("AAPL")
        print(result)  # ✅ approved

asyncio.run(main())
```

The blocking verification runs in a thread-pool executor, so your event loop is never stalled.

---

## Firewall Stripe MPP Payments

**Goal:** Prevent an agent from blindly paying every HTTP 402 challenge.

```python
from qovaris import QovarisGuard
from qovaris.internal.mpp import MPPGuard, parse_payment_challenge

guard = QovarisGuard(mode="embedded", spend_threshold=50)
mpp = MPPGuard(guard)

# Simulating a 402 response with a Payment challenge
challenge_header = (
    'Payment id="ch_123", '
    'method="stripe", '
    'intent="Weather API access", '
    'request="eyJhbW91bnQiOiIxMDAiLCJjdXJyZW5jeSI6InVzZCIsInJlY2lwaWVudCI6ImFjY3RfMTIzIn0"'
)

with guard.session("Fetch one weather report, max $1"):
    try:
        # Parse and evaluate the challenge
        parsed = parse_payment_challenge(challenge_header)
        print(f"Amount: ${parsed.amount}")  # $1.00

        # Authorize through the firewall
        decision = mpp.authorize_challenge(challenge_header)
        print(f"Decision: {decision}")
    except Exception as e:
        print(f"Blocked: {e}")

# Using guarded_pay for authorize + settle in one step
with guard.session("Fetch one weather report, max $1"):
    mpp.guarded_pay(
        challenge_header,
        payer=lambda c: settle_and_retry(c),  # only called if approved
    )
```

---

## Implement Human-in-the-Loop

**Goal:** Allow human approval for high-risk but valid actions.

### Embedded mode (CLI prompt)

```python
from qovaris import QovarisGuard, SecurityBlockException

def approve_action(payload, decision) -> bool:
    """Interactive HITL handler — prompts the user in the terminal."""
    print(f"\n⚠️  REVIEW REQUIRED")
    print(f"   Tool:   {payload.get('tool_name')}")
    print(f"   Args:   {payload.get('arguments')}")
    print(f"   Reason: {decision.get('reason')}")
    return input("   Approve? [y/N] ").strip().lower() == "y"

guard = QovarisGuard(
    mode="embedded",
    spend_threshold=100,
    hitl_handler=approve_action,
)

@guard.wrap_tool(allowed_intent="Process approved payments")
def pay_vendor(vendor: str, amount: float):
    return f"Paid {vendor} ${amount:.2f}"

with guard.session("Pay Acme Corp invoice"):
    # This triggers HITL because amount > spend_threshold
    result = pay_vendor("acme", 500.00)
    print(result)
```

### Remote mode (dashboard)

In remote mode, HITL calls appear in the Qovaris dashboard review queue. No `hitl_handler` is needed — approvals happen through the web UI or Slack/WhatsApp notifications.

---

## Set Budget Caps per Session

**Goal:** Enforce spending limits through intent phrasing and guard configuration.

```python
guard = QovarisGuard(
    mode="embedded",
    spend_threshold=100,  # HITL trigger for amounts >= $100
)

@guard.wrap_tool(allowed_intent="Buy office supplies")
def purchase(item: str, price: float):
    return f"Bought {item} for ${price}"

# Budget cap is automatically extracted from intent text:
with guard.session("Buy office supplies, budget under $50"):
    purchase("Pens", 12.99)       # ✅ approved
    try:
        purchase("Chair", 299.00)  # 🛑 blocked — exceeds $50 budget cap
    except SecurityBlockException as e:
        print(f"Blocked: {e}")
```

The guard automatically parses phrases like:
- `"under $50"`, `"max $1000"`, `"budget of $200"`
- `"limited to $500"`, `"up to $100"`, `"not exceeding $75"`

---

## Block Custom Keywords

**Goal:** Deny tool calls containing specific keywords.

```python
guard = QovarisGuard(mode="embedded")

# Pass blocked keywords during evaluation
result = guard._authorize_embedded(
    payload={
        "original_intent": "Look up account details",
        "tool_name": "lookup",
        "arguments": {"query": "Show me the crypto wallet balance"},
        "allowed_intent": "Query approved accounts",
    },
    tool_name="lookup",
)
# The word "crypto" can be added to the blocked_keywords list
# via the Settings page in the dashboard
```

In remote mode, configure blocked keywords through the **Settings** page in the Qovaris dashboard.

---

## Report Decisions to the Dashboard

**Goal:** Use embedded mode but still see events in the cloud dashboard.

```python
guard = QovarisGuard(
    mode="embedded",
    api_key="nx_live_...",          # enables dashboard reporting
    gateway_url="http://localhost:8005",
    agent_id="procurement-agent",   # shows up on every event
    report=True,                    # default — fire-and-forget
)

# Every decision (approved, blocked, HITL) appears in the dashboard
@guard.wrap_tool(allowed_intent="Purchase supplies")
def buy(item: str, price: float):
    return f"Bought {item}"

with guard.session("Buy office supplies under $50"):
    buy("Pens", 12.99)  # Approved — logged to dashboard
```

Reporting is:
- **Non-blocking** — runs in a daemon thread
- **Silent on failure** — if the backend is down, events are dropped
- **Automatic** — no extra code needed

---

## Handle Gateway Downtime

**Goal:** Choose how your agent behaves when the backend is unreachable.

### Fail closed (default — secure)

```python
guard = QovarisGuard(
    mode="remote",
    api_key="nx_live_...",
    fail_open=False,  # default
)

# If backend is down → SecurityBlockException
# Agent cannot proceed — most secure option
```

### Fail open (with warning)

```python
guard = QovarisGuard(
    mode="remote",
    api_key="nx_live_...",
    fail_open=True,
)

# If backend is down → RuntimeWarning, but tool executes
# Use only when availability > security for this specific agent
```

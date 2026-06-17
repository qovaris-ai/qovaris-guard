# Examples

Complete, runnable examples for every supported framework. Each example runs **fully offline** in embedded mode.

---

## Table of Contents

- [Minimal Example](#minimal-example)
- [LangGraph Agent](#langgraph-agent)
- [Claude / Anthropic](#claude--anthropic)
- [OpenAI Agents](#openai-agents)
- [LangChain with QovarisSecureTool](#langchain-with-qovarissecuretool)
- [Async Tools](#async-tools)
- [Stripe MPP / HTTP 402](#stripe-mpp--http-402)
- [Human-in-the-Loop](#human-in-the-loop)
- [Dashboard Reporting](#dashboard-reporting)
- [Full Agent with Error Handling](#full-agent-with-error-handling)

---

## Minimal Example

The simplest possible Qovaris integration:

```python
from qovaris import QovarisGuard, SecurityBlockException

guard = QovarisGuard(mode="embedded", spend_threshold=100)

@guard.wrap_tool(allowed_intent="Buy office supplies under $50")
def buy(item: str, price: float) -> str:
    return f"Purchased {item} for ${price:.2f}"

with guard.session("Buy a Python book for about $25"):
    print(buy("Clean Code", 24.99))        # ✅ Approved
    try:
        buy("MacBook Pro", 2499.00)        # 🛑 Blocked
    except SecurityBlockException as e:
        print(f"Blocked: {e}")
```

---

## LangGraph Agent

A complete LangGraph agent with multiple guarded tools:

```python
"""
Qovaris + LangGraph Example
================================
Run: python example_langgraph.py

Demonstrates:
  - @guard.wrap_tool decorator on LangGraph tools
  - Session scoping with guard.session()
  - SecurityBlockException handling in graph nodes
  - SQL injection detection
"""
from qovaris import QovarisGuard, SecurityBlockException
from langgraph.graph import StateGraph, END
from langchain_core.tools import tool
from typing import TypedDict, List

guard = QovarisGuard(mode="embedded", spend_threshold=500)

# ── Guarded tools ────────────────────────────────────────────

@guard.wrap_tool(allowed_intent="Process vendor payments within approved budget")
@tool
def pay_vendor(vendor_id: str, amount: float) -> dict:
    """Send a payment to a vendor."""
    return {"status": "paid", "vendor": vendor_id, "amount": amount}

@guard.wrap_tool(allowed_intent="Execute approved SQL read queries only")
@tool
def run_query(sql: str) -> list:
    """Run a database query."""
    return [{"count": 42}]

# ── Graph definition ─────────────────────────────────────────

class AgentState(TypedDict):
    messages: List[str]
    task: str

def process_task(state: AgentState) -> AgentState:
    results = []
    with guard.session(state["task"]):
        # Scenario 1: Valid payment within budget
        try:
            result = pay_vendor.invoke({"vendor_id": "acme-corp", "amount": 450.00})
            results.append(f"✅ Payment: {result}")
        except SecurityBlockException as e:
            results.append(f"🛑 Payment blocked: {e}")

        # Scenario 2: Injection attempt
        try:
            run_query.invoke({"sql": "DROP TABLE users"})
            results.append("✅ Query executed")
        except SecurityBlockException as e:
            results.append(f"🛑 Query blocked: {e}")

        # Scenario 3: Over-budget payment
        try:
            pay_vendor.invoke({"vendor_id": "evil-corp", "amount": 99999.00})
            results.append("✅ Large payment executed")
        except SecurityBlockException as e:
            results.append(f"🛑 Large payment blocked: {e}")

    return {"messages": results, "task": state["task"]}

graph = StateGraph(AgentState)
graph.add_node("process", process_task)
graph.set_entry_point("process")
graph.add_edge("process", END)
app = graph.compile()

# ── Run ──────────────────────────────────────────────────────

result = app.invoke({
    "messages": [],
    "task": "Pay the Acme Corp monthly invoice of $450",
})

for msg in result["messages"]:
    print(msg)
```

Expected output:
```
✅ Payment: {'status': 'paid', 'vendor': 'acme-corp', 'amount': 450.0}
🛑 Query blocked: Blocked execution of 'run_query': Database Policy Violation: ...
🛑 Large payment blocked: Blocked execution of 'pay_vendor': High Value Transaction: ...
```

---

## Claude / Anthropic

```python
"""
Qovaris + Claude Example
==============================
Run: ANTHROPIC_API_KEY=... python example_claude.py

Demonstrates guarding Claude tool_use dispatch.
"""
from qovaris import QovarisGuard, SecurityBlockException
import anthropic

guard = QovarisGuard(mode="embedded", spend_threshold=1000)
client = anthropic.Anthropic()

@guard.wrap_tool(allowed_intent="Transfer funds between approved company accounts")
def transfer_funds(from_account: str, to_account: str, amount: float) -> dict:
    return {"status": "transferred", "from": from_account, "to": to_account, "amount": amount}

@guard.wrap_tool(allowed_intent="Read approved database tables for reporting")
def query_database(table: str, filters: dict) -> dict:
    return {"table": table, "row_count": 156}

TOOL_DISPATCH = {
    "transfer_funds": transfer_funds,
    "query_database": query_database,
}

tools = [
    {
        "name": "transfer_funds",
        "description": "Transfer money between company accounts",
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

def run_claude_agent(task: str):
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
                    result = fn(**block.input)
                    print(f"✅ {block.name}: {result}")
                    return result
                except SecurityBlockException as e:
                    print(f"🛑 {block.name} blocked: {e}")
                    return {"error": str(e)}

# Normal usage
run_claude_agent("Transfer $500 from ops-account to vendor ACC-9201 for Q4 invoice")
```

---

## OpenAI Agents

```python
"""
Qovaris + OpenAI Example
===============================
Run: OPENAI_API_KEY=... python example_openai.py

Demonstrates guarding OpenAI tool_calls dispatch.
"""
from qovaris import QovarisGuard, SecurityBlockException
from openai import OpenAI
import json

guard = QovarisGuard(mode="embedded", spend_threshold=5000)
client = OpenAI()

@guard.wrap_tool(allowed_intent="Submit purchase orders for approved vendors under $5000")
def submit_purchase_order(vendor: str, items: list, total: float) -> dict:
    return {"po_id": "PO-2024-0812", "vendor": vendor, "total": total, "status": "submitted"}

TOOL_DISPATCH = {"submit_purchase_order": submit_purchase_order}

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

def run_openai_agent(task: str):
    with guard.session(original_intent=task):
        messages = [{"role": "user", "content": task}]
        response = client.chat.completions.create(
            model="gpt-4o", tools=tools, messages=messages
        )
        if response.choices[0].message.tool_calls:
            call = response.choices[0].message.tool_calls[0]
            try:
                fn = TOOL_DISPATCH[call.function.name]
                args = json.loads(call.function.arguments)
                result = fn(**args)
                print(f"✅ {call.function.name}: {result}")
                return result
            except SecurityBlockException as e:
                print(f"🛑 Blocked: {e}")
                return {"blocked": True, "reason": str(e)}

run_openai_agent("Order 50 ergonomic keyboards for the engineering team, budget $2000")
```

---

## LangChain with QovarisSecureTool

```python
"""
Qovaris + LangChain QovarisSecureTool
=========================================
Run: pip install "qovaris[langchain]" && python example_langchain.py
"""
from langchain_core.tools import tool
from qovaris import QovarisGuard
from qovaris.integrations.langchain import QovarisSecureTool

guard = QovarisGuard(mode="embedded", spend_threshold=1000)

@tool
def search_catalog(query: str) -> str:
    """Search the product catalog."""
    return f"Found 3 results for '{query}'"

@tool
def place_order(product_id: str, quantity: int, price: float) -> str:
    """Place an order for a product."""
    return f"Order placed: {quantity}x {product_id} @ ${price}"

# Wrap with Qovaris security
secure_search = QovarisSecureTool(
    wrapped_tool=search_catalog,
    guard=guard,
    allowed_intent="Search the product catalog for approved items",
)

secure_order = QovarisSecureTool(
    wrapped_tool=place_order,
    guard=guard,
    allowed_intent="Place orders for approved products under $500",
)

with guard.session("Find and order ergonomic keyboards under $200"):
    # ✅ Search is always safe
    results = secure_search.invoke({"query": "ergonomic keyboard"})
    print(results)

    # ✅ Within budget
    order = secure_order.invoke({
        "product_id": "KB-ERGO-100",
        "quantity": 5,
        "price": 89.99,
    })
    print(order)
```

---

## Async Tools

```python
"""
Qovaris — Async Tools Example
====================================
Run: python example_async.py
"""
import asyncio
from qovaris import QovarisGuard, SecurityBlockException

guard = QovarisGuard(mode="embedded", spend_threshold=500)

@guard.wrap_tool_async(allowed_intent="Fetch read-only stock quotes")
async def fetch_quote(symbol: str) -> dict:
    await asyncio.sleep(0.1)  # simulate API call
    prices = {"AAPL": 189.25, "GOOGL": 141.80, "MSFT": 378.91}
    return {"symbol": symbol, "price": prices.get(symbol, 0)}

@guard.wrap_tool_async(allowed_intent="Submit trade orders under $10000")
async def place_trade(symbol: str, quantity: int, price: float) -> dict:
    await asyncio.sleep(0.1)
    return {"trade_id": "T-99201", "symbol": symbol, "total": quantity * price}

async def main():
    with guard.session("Check AAPL price and buy 10 shares if under $200"):
        quote = await fetch_quote("AAPL")
        print(f"✅ Quote: {quote}")

        if quote["price"] < 200:
            trade = await place_trade("AAPL", 10, quote["price"])
            print(f"✅ Trade: {trade}")

asyncio.run(main())
```

---

## Stripe MPP / HTTP 402

```python
"""
Qovaris — MPP (Machine Payments Protocol) Example
========================================================
Run: python example_mpp.py

Demonstrates:
  - Parsing WWW-Authenticate: Payment challenges
  - Budget enforcement on machine payments
  - guarded_pay for authorize + settle
"""
from qovaris import QovarisGuard, SecurityBlockException
from qovaris.internal.mpp import MPPGuard, parse_payment_challenge
import base64, json

guard = QovarisGuard(mode="embedded", spend_threshold=5)
mpp = MPPGuard(guard)

# Simulate a 402 challenge
request_blob = base64.urlsafe_b64encode(
    json.dumps({"amount": "100", "currency": "usd", "recipient": "acct_weather"}).encode()
).decode().rstrip("=")

challenge = f'Payment id="ch_1", method="stripe", intent="Weather API", request="{request_blob}"'

# Scenario 1: Within budget
with guard.session("Fetch one weather report, max $5"):
    parsed = parse_payment_challenge(challenge)
    print(f"Challenge amount: ${parsed.amount}")  # $1.00

    try:
        decision = mpp.authorize_challenge(challenge)
        print(f"✅ Approved: {decision}")
    except SecurityBlockException as e:
        print(f"🛑 Blocked: {e}")

# Scenario 2: Over budget
expensive_blob = base64.urlsafe_b64encode(
    json.dumps({"amount": "50000", "currency": "usd", "recipient": "acct_evil"}).encode()
).decode().rstrip("=")

expensive_challenge = f'Payment id="ch_2", method="stripe", intent="Data API", request="{expensive_blob}"'

with guard.session("Fetch one report, budget under $5"):
    try:
        mpp.authorize_challenge(expensive_challenge)
    except SecurityBlockException as e:
        print(f"🛑 Expensive payment blocked: {e}")
```

---

## Human-in-the-Loop

```python
"""
Qovaris — Human-in-the-Loop Example
==========================================
Run: python example_hitl.py

Demonstrates interactive approval for high-value actions.
"""
from qovaris import QovarisGuard, SecurityBlockException

def interactive_approve(payload, decision) -> bool:
    """Terminal-based HITL handler."""
    print("\n" + "=" * 60)
    print("⚠️  HUMAN REVIEW REQUIRED")
    print("=" * 60)
    print(f"  Tool:      {payload.get('tool_name')}")
    print(f"  Arguments: {payload.get('arguments')}")
    print(f"  Intent:    {payload.get('original_intent')}")
    print(f"  Reason:    {decision.get('reason')}")
    print(f"  Category:  {decision.get('category')}")
    print("=" * 60)
    response = input("  Approve this action? [y/N]: ").strip().lower()
    return response == "y"

guard = QovarisGuard(
    mode="embedded",
    spend_threshold=100,        # anything >= $100 triggers review
    hitl_handler=interactive_approve,
)

@guard.wrap_tool(allowed_intent="Process approved vendor payments")
def pay_vendor(vendor: str, amount: float) -> str:
    return f"✅ Paid {vendor} ${amount:.2f}"

with guard.session("Pay Acme Corp for Q4 services"):
    # Under threshold — auto-approved
    print(pay_vendor("acme", 50.00))

    # Over threshold — triggers HITL
    try:
        print(pay_vendor("acme", 500.00))
    except SecurityBlockException as e:
        print(f"🛑 Denied: {e}")
```

---

## Dashboard Reporting

```python
"""
Qovaris — Dashboard Reporting Example
============================================
Run: python example_dashboard.py

Demonstrates embedded mode with dashboard reporting enabled.
Every decision appears in the web dashboard for monitoring.
"""
from qovaris import QovarisGuard, SecurityBlockException

guard = QovarisGuard(
    mode="embedded",
    api_key="nx_live_...",
    gateway_url="http://localhost:8005",
    agent_id="procurement-bot",
    spend_threshold=500,
    report=True,  # fire-and-forget to dashboard
)

@guard.wrap_tool(allowed_intent="Purchase approved office supplies")
def buy_supplies(item: str, price: float) -> str:
    return f"Ordered: {item} for ${price:.2f}"

@guard.wrap_tool(allowed_intent="Execute read-only database queries")
def run_query(sql: str) -> str:
    return f"Result: {sql}"

with guard.session("Restock office kitchen supplies, budget $200"):
    # ✅ Approved — appears in dashboard as APPROVED
    print(buy_supplies("Coffee pods", 45.99))

    # 🛑 Blocked — appears in dashboard as BLOCKED
    try:
        run_query("DROP TABLE inventory")
    except SecurityBlockException as e:
        print(f"Blocked: {e}")

    # ⏳ Budget violation — appears in dashboard as BLOCKED
    try:
        buy_supplies("Espresso machine", 899.00)
    except SecurityBlockException as e:
        print(f"Blocked: {e}")

print("\n📊 Check the dashboard at http://localhost:8005 for the full audit log.")
```

---

## Full Agent with Error Handling

```python
"""
Qovaris — Production Agent Pattern
=========================================
A complete example showing the recommended production pattern
with proper error handling, logging, and graceful degradation.
"""
import logging
from qovaris import QovarisGuard, SecurityBlockException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent")

# ── Configure guard ──────────────────────────────────────────

guard = QovarisGuard(
    mode="embedded",
    spend_threshold=500,
    agent_id="production-agent",
)

# ── Define guarded tools ─────────────────────────────────────

@guard.wrap_tool(allowed_intent="Query customer data for authorized lookups")
def lookup_customer(customer_id: str) -> dict:
    return {"id": customer_id, "name": "Acme Corp", "balance": 15000}

@guard.wrap_tool(allowed_intent="Process refunds for verified orders under $1000")
def process_refund(order_id: str, amount: float, reason: str) -> dict:
    return {"refund_id": f"RF-{order_id}", "amount": amount, "status": "processed"}

@guard.wrap_tool(allowed_intent="Send email notifications to verified addresses")
def send_email(to: str, subject: str, body: str) -> dict:
    return {"status": "sent", "to": to}

# ── Agent loop ───────────────────────────────────────────────

def execute_tool(tool_fn, **kwargs) -> dict:
    """Execute a tool with standardized error handling."""
    try:
        result = tool_fn(**kwargs)
        logger.info(f"✅ {tool_fn.__name__} succeeded: {result}")
        return {"success": True, "result": result}
    except SecurityBlockException as e:
        logger.warning(f"🛑 {tool_fn.__name__} blocked: {e}")
        return {"success": False, "blocked": True, "reason": str(e)}
    except Exception as e:
        logger.error(f"❌ {tool_fn.__name__} failed: {e}")
        return {"success": False, "error": str(e)}

def run_agent(task: str):
    logger.info(f"Starting agent with task: {task}")
    with guard.session(task):
        # Step 1: Look up the customer
        customer = execute_tool(lookup_customer, customer_id="CUST-001")
        if not customer["success"]:
            return customer

        # Step 2: Process refund
        refund = execute_tool(
            process_refund,
            order_id="ORD-5521",
            amount=149.99,
            reason="Product defective",
        )

        # Step 3: Notify customer
        email = execute_tool(
            send_email,
            to="customer@acme.com",
            subject="Refund processed",
            body="Your refund of $149.99 has been processed.",
        )

        return {
            "customer": customer,
            "refund": refund,
            "notification": email,
        }

# Run
result = run_agent("Process refund for order ORD-5521, amount $149.99, defective product")
print(f"\nFinal result: {result}")
```

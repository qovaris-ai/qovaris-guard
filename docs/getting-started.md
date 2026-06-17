# Getting Started

Get Qovaris protecting your AI agent in under 5 minutes.

---

## Installation

The core guard is **dependency-free** (Python ≥ 3.9, standard library only):

```bash
pip install qovaris
```

Add extras only for the integrations you use:

```bash
# LangChain / LangGraph wrappers
pip install "qovaris[langchain]"

# Development / testing
pip install "qovaris[dev]"
```

### Install from source

```bash
git clone https://github.com/Augis363/qovaris.git
cd qovaris
pip install -e ".[dev]"
```

---

## Your First Guarded Agent (5 minutes)

### Step 1: Import and create a guard

```python
from qovaris import QovarisGuard, SecurityBlockException

# Embedded mode — runs fully in-process, no backend needed
guard = QovarisGuard(mode="embedded", spend_threshold=1000)
```

### Step 2: Decorate your tools

Add `@guard.wrap_tool()` to any function your agent can call. The `allowed_intent` parameter describes what this tool is allowed to do:

```python
@guard.wrap_tool(allowed_intent="Purchase office supplies under $50")
def buy_item(item: str, price: float) -> str:
    """Purchase an item from the office store."""
    return f"Purchased {item} for ${price:.2f}"


@guard.wrap_tool(allowed_intent="Execute read-only database queries")
def run_query(sql: str) -> str:
    """Run a SQL query against the database."""
    return f"Query result: {sql}"
```

### Step 3: Open a session and run

A session scopes the user's high-level objective. Every tool call inside the `with` block is verified against this intent:

```python
with guard.session("Buy a Python programming book for about $25"):
    # ✅ This will be APPROVED — matches intent and budget
    result = buy_item(item="Clean Code", price=24.99)
    print(result)

    # 🛑 This will be BLOCKED — price way over stated intent
    try:
        buy_item(item="MacBook Pro", price=2499.00)
    except SecurityBlockException as e:
        print(f"Blocked: {e}")

    # 🛑 This will be BLOCKED — destructive SQL detected
    try:
        run_query(sql="DROP TABLE users")
    except SecurityBlockException as e:
        print(f"Blocked: {e}")
```

### Step 4: Run it

```bash
python my_agent.py
```

Output:
```
Purchased Clean Code for $24.99
Blocked: Blocked execution of 'buy_item': High Value Transaction: ...
Blocked: Blocked execution of 'run_query': Database Policy Violation: ...
```

---

## Choosing a Mode

| Feature | Embedded | Remote |
|:--------|:---------|:-------|
| **Setup** | Zero — just `pip install` | Requires running the backend |
| **Network** | No HTTP calls | Calls backend `/verify` endpoint |
| **Dashboard** | Optional (fire-and-forget reporting) | Full audit log + HITL queue |
| **Best for** | Tests, notebooks, scripts, air-gapped | Production, org-wide policy |
| **API key needed** | No (optional for reporting) | Yes |

### Embedded mode

```python
guard = QovarisGuard(
    mode="embedded",
    spend_threshold=1000,  # HITL trigger threshold
)
```

### Remote mode

```python
guard = QovarisGuard(
    mode="remote",
    gateway_url="http://localhost:8005",
    api_key="nx_live_...",          # from your dashboard
    agent_id="procurement-agent",   # shows up on every event
)
```

The decorator usage is identical — only the constructor changes.

---

## Next Steps

- **[Core Concepts](core-concepts.md)** — understand the security model
- **[How-To Guides](how-to-guides.md)** — integration recipes for every framework
- **[Examples](examples.md)** — copy-paste runnable scripts
- **[API Reference](api-reference.md)** — complete class/method docs

# 🛡️ Qovaris Documentation

> **The Security SDK for Autonomous AI Agents**
>
> An intent-verification firewall for agent tool calls — stop prompt injection, runaway spend, and unauthorized actions *before* a tool ever runs.

---

## 📚 Documentation

| Guide | Description |
|:------|:------------|
| [Getting Started](getting-started.md) | Install, configure, and run your first guarded agent in 5 minutes |
| [Core Concepts](core-concepts.md) | Understand sessions, intents, policy evaluation, and the security model |
| [How-To Guides](how-to-guides.md) | Step-by-step recipes for common integration patterns |
| [API Reference](api-reference.md) | Complete reference for every class, method, and configuration option |
| [Examples](examples.md) | Runnable, copy-paste examples for every supported framework |

---

## Quick Links

- **Install:** `pip install qovaris`
- **GitHub:** [github.com/Augis363/qovaris](https://github.com/Augis363/qovaris)
- **License:** MIT

---

## What Qovaris Protects Against

| Threat | Without Qovaris | With Qovaris |
|:-------|:--------------------|:-----------------|
| **Prompt injection** | Agent obeys injected instructions | Semantic firewall detects intent mismatch |
| **Spending loops** | Retry loop charges $50,000 | Budget policy blocks overspend |
| **Destructive SQL** | `DROP TABLE users` executes | SQL classifier blocks or escalates |
| **Credential leakage** | Agent reads `password_hash` | Sensitive-field access blocked |
| **Rogue payments** | Agent pays every HTTP 402 | MPPGuard evaluates before settlement |
| **Shadow actions** | "Clean up" becomes `DELETE /users` | Destructive verbs trigger human review |

---

## Supported Frameworks

Qovaris works with any Python-based agent framework:

- 🕸️ **LangGraph** — `@guard.wrap_tool` decorator + `QovarisSecureTool`
- 🦜 **LangChain** — `QovarisSecureTool` BaseTool wrapper
- 🤖 **Claude / Anthropic** — wrap your `tool_use` dispatch
- ⚡ **OpenAI Agents** — wrap `tool_calls` function dispatch
- 🚢 **CrewAI** — decorate crew tool functions
- 🔮 **AutoGen** — decorate any callable tool
- 💳 **Stripe MPP** — `MPPGuard` for HTTP 402 payment challenges

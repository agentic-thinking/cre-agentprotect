# CRE-AgentProtect Light

**Open-source HookBus subscriber for Microsoft's Agent Governance Toolkit (AGT).**

MIT-licensed. Full source on GitHub. This is the public Light package: one small adapter that translates HookBus normalised events into Microsoft AGT `SemanticPolicyEngine.classify()` calls and translates the verdicts back to HookBus responses.

---

## What this is (and what it is not)

**CRE-AgentProtect Light is an adapter, not a fork.** Microsoft AGT is a Microsoft project, MIT-licensed by Microsoft Corporation. CRE-AgentProtect Light is the bridge between any HookBus publisher and AGT's `SemanticPolicyEngine`. We:

- do **not** vendor, redistribute, or modify AGT source code
- do **not** claim any rights, patents, or copyrights in AGT
- do **not** claim affiliation with, endorsement by, or partnership with Microsoft
- **do** depend on AGT as an upstream runtime dependency (`pip install agent-os-kernel`)

**Microsoft maintains the engine. Agentic Thinking maintains the adapter.**

If Microsoft ships their own HookBus-compatible adapter tomorrow, use theirs. This exists because today HookBus publishers need a zero-friction bridge to AGT and none existed.

---

## Install (60 seconds)

One shell command installs the public HookBus stack with CRE-AgentProtect Light. The interactive menu lets you pick a publisher shim for your agent runtime.

```bash
curl -fsSL https://agenticthinking.uk/install.sh | bash
```

Non-interactive variants:

```bash
# Hermes-agent users
curl -fsSL https://agenticthinking.uk/install.sh | bash -s -- --runtime hermes

# OpenClaw users
curl -fsSL https://agenticthinking.uk/install.sh | bash -s -- --runtime openclaw

# Bus + CRE-AgentProtect Light only, skip publisher
curl -fsSL https://agenticthinking.uk/install.sh | bash -s -- --runtime skip --noninteractive
```

The script prints the dashboard URL + bearer token on completion. Re-run any time, it is idempotent.

_Prefer not to pipe curl to bash? Inspect first:_ `curl -fsSL https://agenticthinking.uk/install.sh > install.sh && less install.sh && bash install.sh`

---

## Manual install

If you prefer to see every step, or you are building an immutable / reproducible deployment, here is the full manual install.

CRE-AgentProtect Light is designed as a subscriber on a HookBus stack. The easiest way to run it is via the HookBus quickstart, which runs this image alongside the bus and wires it as a subscriber:

```bash
# Follow the HookBus quickstart:
#   https://github.com/agentic-thinking/hookbus#quick-start-60-seconds
```

**Build the image on its own** if you are wiring CRE-AgentProtect into an existing HookBus deployment:

```bash
git clone https://github.com/agentic-thinking/cre-agentprotect.git
cd cre-agentprotect
docker build -t agentic-thinking/cre-agentprotect:latest .

docker run -d --name cre-agentprotect \
  -v hookbus-auth:/root/.hookbus:ro \
  -p 8878:8878 \
  agentic-thinking/cre-agentprotect:latest
```

Then add it to `subscribers.yaml`:

```yaml
- name: cre-agentprotect
  type: sync
  transport: http
  address: http://cre-agentprotect:8878
  events: [PreToolUse, PostToolUse, PostLLMCall]
```

## What CRE-AgentProtect Light does

| Event | Behaviour |
|---|---|
| `PreToolUse` | Classifies tool call via AGT, denies on `DESTRUCTIVE_DATA` / `DATA_EXFILTRATION` / `PRIVILEGE_ESCALATION` / `SYSTEM_MODIFICATION` above confidence threshold |
| `PostToolUse` | Allows + observes |
| Other | Allows |

## Policy rules

CRE-AgentProtect calls AGT's `SemanticPolicyEngine()` with its default sample rules (regex patterns hardcoded in `agent_os/semantic_policy.py`, installed via `agent-os-kernel`). Coverage includes `rm -rf`, `curl | sh`, `DROP TABLE`, `sudo`, `chmod 777`, and similar common threat patterns across seven intent categories (`DESTRUCTIVE_DATA`, `DATA_EXFILTRATION`, `PRIVILEGE_ESCALATION`, `SYSTEM_MODIFICATION`, `CODE_EXECUTION`, `NETWORK_ACCESS`, `DATA_READ` / `DATA_WRITE`).

For richer coverage (prompt injection, PII detection, SQL safety, MCP security, etc.), Microsoft ships additional YAML policy files at [microsoft/agent-governance-toolkit/examples/policies](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/policies):

- [`semantic-policy.yaml`](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/policies/semantic-policy.yaml) — default reference policy
- [`prompt-injection-safety.yaml`](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/policies/prompt-injection-safety.yaml)
- [`pii-detection.yaml`](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/policies/pii-detection.yaml)
- [`lotl_prevention_policy.yaml`](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/policies/lotl_prevention_policy.yaml) — living-off-the-land prevention
- [`sql-safety.yaml`](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/policies/sql-safety.yaml)
- [`mcp-security.yaml`](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/policies/mcp-security.yaml)

Load one via `load_semantic_policy_config()` if you are extending the adapter yourself.

## Scope

This repository and container package are **CRE-AgentProtect Light** only. They do not include the enterprise dashboard, curated regulated-industry policy packs, delegated approval workflows, SLA, support, or commercial deployment bundle.

For the enterprise product, see [agenticthinking.uk](https://agenticthinking.uk).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `CRE_AGENTPROTECT_HOST` | `0.0.0.0` | Bind address |
| `CRE_AGENTPROTECT_PORT` | `8878` | Bind port |
| `CRE_AGENTPROTECT_CONFIDENCE_THRESHOLD` | `0.5` | Minimum AGT confidence to deny |

## Licensing

| Layer | Licence | Holder |
|---|---|---|
| This adapter (CRE-AgentProtect) | MIT | © 2026 Agentic Thinking Limited |
| Microsoft AGT (upstream dependency) | MIT | © Microsoft Corporation |
| HookBus envelope schema | CC0 1.0 (public domain) | Defensively published, Zenodo DOI `10.5281/zenodo.19642020` |

MIT covers **only** the adapter code in this repository. Microsoft AGT remains under Microsoft's MIT licence; nothing here re-licenses or overrides that. CRE-AgentProtect is a thin one-layer adapter, so MIT is the cleanest fit and matches the AGT upstream.

## Trademarks & attribution

- **Microsoft** and **Agent Governance Toolkit (AGT)** are trademarks of Microsoft Corporation. Used here nominatively, solely to identify the upstream project this adapter depends on. No affiliation with, endorsement by, or sponsorship from Microsoft Corporation is claimed or implied.
- **HookBus™** is a trademark (common-law) of Agentic Thinking Limited.

## Contributing

PRs welcome for:
- Additional backends (OPA, Asqav, Casbin, custom)
- Metadata passthrough (organisation ID, user ID, session info)
- Confidence threshold tuning per category
- Integration tests

Before submitting a PR, sign the CLA (see `/CLA.md` once released).

---

Built by [Agentic Thinking Limited](https://agenticthinking.uk) (UK Company 17152930). Contact: contact@agenticthinking.uk

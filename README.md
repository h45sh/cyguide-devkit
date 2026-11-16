# CyGuide DevKit (`cyguide-devkit`)

An independent toolkit, CLI utility, and agent skill for authoring, scaffolding, validating, and testing production-grade tool adapters for **[CyGuide](https://github.com/h45sh/cyguide)**.

---

## Overview

CyGuide uses the **Smart Adapter / Stupid Framework** architecture. The core application engine (`cyguide/engine`) manages process execution, deterministic graph persistence, and user interfaces without hardcoding tool-specific commands or parsing logic. 

Every tool plugin lives in its own self-contained folder:
```text
tools/<tool_name>/
├── __init__.py
├── manifest.toml         # Declarative contracts, parameters, curriculum recipes, protocol theory
├── adapter.py            # ToolAdapter (validate_install, build_command, parse_output, sanitize_output)
└── cli.py                # (Optional) Pure-Python CLI entry point for bundled utilities
```

This project (`cyguide-devkit`) provides both:
1. **A Standalone CLI Tool**: To scaffold new adapters, validate manifest syntax & schemas, list schema definitions, and inspect wordlists.
2. **An Agent Skill (`SKILL.md`)**: Designed for AI coding assistants (Antigravity, Claude, Codex, Gemini) to author deep, curriculum-grade tool adapters conforming strictly to CyGuide invariants.

---

## Installation

Install directly with `pip` or use locally in editable mode:

```bash
git clone https://github.com/h45sh/cyguide-devkit.git
cd cyguide-devkit
pip install -e .
```

Requires **Python 3.11+** (uses built-in `tomllib` with zero external runtime dependencies).

---

## CLI Usage

### 1. Scaffold a New Adapter
Quickly bootstrap an adapter directory, manifest, parser implementation, sample fixture, and hermetic pytest suite:

```bash
cyguide-devkit new masscan \
  --target-dir /path/to/cyguide \
  --category "Network Discovery" \
  --categories network portscan recon \
  --accepts network.netblock network.host \
  --produces network.service \
  --target-flag "-p"
```

Files generated:
* `tools/<tool_name>/__init__.py`
* `tools/<tool_name>/manifest.toml`
* `tools/<tool_name>/adapter.py`
* `tests/fixtures/mock_tools/<tool_name>.txt`
* `tests/unit/test_parsers/test_<tool_name>_parser.py`

### 2. Validate Tool Manifests & Adapters
Verify TOML syntax, required fields, curriculum recipe fields, theory blocks, and static AST implementation:

```bash
# Validate a specific tool directory
cyguide-devkit validate /path/to/cyguide/tools/ffuf

# Validate a single manifest.toml file
cyguide-devkit validate /path/to/cyguide/tools/nmap/manifest.toml
```

### 3. List Registered Finding Schemas
Display all valid finding schemas, primary identification keys (PIKs), and parent associations:

```bash
cyguide-devkit list-schemas
```

### 4. List Supported Wordlist Macros
Display available centralized wordlist tokens:

```bash
cyguide-devkit list-wordlists
```

---

## Manifest Contract (`manifest.toml`)

Manifests must specify:
* `[meta]`: `name`, `description`, `one_line_summary`, `category`, `categories`, and `binary`. (Note: `categories` map to CyGuide AI Explainer directives: `network`, `recon`, `web`, `vulnerability`, `osint`, `dns`, `exploit`).
* `[modes]`: `learning` and `power` booleans.
* `[input].accepts`: Supported finding schemas (e.g. `network.host`, `web.endpoint`).
* `[output].produces`: Emitted finding schemas (e.g. `web.endpoint`, `audit.misconfig`).
* `[[learning.recipes]]`: Syllabus recipes with:
  * `name`, `difficulty` (`Beginner`, `Intermediate`, `Advanced`), `description`, and `flags`.
  * `[learning.recipes.theory]`: `concept`, `explanation`, `packet_wire_summary`, and `remediation`.

---

## Using as an Agent Skill

Copy or link `SKILL.md` to your agent skills directory:
* **Antigravity / Gemini / Claude**: Place in `.agents/skills/cyguide-devkit/SKILL.md` or global agent configuration directory (`~/.agents/skills/cyguide-devkit/`).
* The skill provides exhaustive instructions on non-interactive flags, streaming JSON parsing, wordlist substitution, graph relationship auto-wiring, AI explainer category directives, optional output sanitization hooks (`sanitize_output`), and the repository ecosystem checklist.

---

## Running Tests

Run the hermetic test suite:

```bash
pytest tests/
```

---

## License

MIT

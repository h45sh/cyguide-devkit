# CyGuide DevKit (`cyguide-devkit`)

An independent developer toolkit, CLI utility, and agent skill for authoring, scaffolding, validating, and testing production-grade tool adapters for **[CyGuide](https://github.com/h45sh/cyguide)**.

---

## Overview

CyGuide adheres to the **Smart Adapter / Stupid Framework** architecture. The core application engine (`cyguide/engine`) manages process execution, deterministic graph persistence, and user interfaces without hardcoding tool-specific execution flags or stdout parsing.

Every tool plugin lives in its own self-contained directory:
```text
tools/<tool_name>/
├── __init__.py
├── manifest.toml         # Declarative contracts, parameters, curriculum recipes, protocol theory
├── adapter.py            # ToolAdapter (validate_install, build_command, parse_output, sanitize_output)
└── cli.py                # (Optional) Pure-Python CLI entry point for bundled utilities
```

This project (`cyguide-devkit`) provides:
1. **A Standalone CLI Tool**: Scaffolds new adapters, performs static AST & schema validation, validates entire directories of adapters in batch mode, and inspects schemas/wordlists.
2. **An Agent Skill (`SKILL.md`)**: Designed for AI coding assistants (Antigravity, Claude, Codex, Gemini) to author deep, curriculum-grade tool adapters strictly obeying CyGuide invariants.

---

## Installation

Install directly with `pip` or use locally in editable mode:

```bash
git clone https://github.com/h45sh/cyguide-devkit.git
cd cyguide-devkit
pip install -e ".[dev]"
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

#### Single Adapter Directory or Manifest:
```bash
# Validate a specific tool directory
cyguide-devkit validate /path/to/cyguide/tools/ffuf

# Validate a single manifest.toml file
cyguide-devkit validate /path/to/cyguide/tools/nmap/manifest.toml
```

#### Batch Validation:
Validate an entire collection of tool plugins in one shot (automatically skipping hidden or `__pycache__` directories):
```bash
cyguide-devkit validate /path/to/cyguide/tools
```

Sample output:
```text
[*] Running batch validation across 9 candidate tool adapter(s) in: /path/to/cyguide/tools
================================================================================
Tool Adapter             | Status   | Errors   | Warnings
--------------------------------------------------------------------------------
dnspython                | PASS     | 0        | 0       
ffuf                     | PASS     | 0        | 0       
gobuster                 | PASS     | 0        | 0       
nikto                    | PASS     | 0        | 0       
nmap                     | PASS     | 0        | 0       
nuclei                   | PASS     | 0        | 0       
searchsploit             | PASS     | 0        | 0       
subfinder                | PASS     | 0        | 0       
whois                    | PASS     | 0        | 0       
--------------------------------------------------------------------------------
Total: 9 | Passed: 9 | Failed: 0
================================================================================

[✓] All adapters in batch strictly passed validation!
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

## Core Contracts & Invariants

* **Command Construction Safety**: `build_command()` must construct and return a `List[str]`. Never concatenate raw shell strings or pass `shell=True`.
* **Non-Zero Exit Code Resilience**: Security scanners frequently terminate with exit status 1 or 2 when findings are detected. Adapters must parse stdout and emit findings regardless of the exit code.
* **Output Sanitization Hook (`sanitize_output`)**: Strips ASCII art logos (figlet banners), carriage return progress meters (`\r`), and noisy headers before feeding scan logs to the AI tutor, conserving LLM prompt tokens.
* **Hermetic Tests**: Every adapter must include unit tests running against raw fixtures in `tests/fixtures/mock_tools/` without needing the security binary installed.

---

## Using as an Agent Skill

Copy or link `SKILL.md` to your agent skills directory:
* **Antigravity / Gemini / Claude**: Place in `.agents/skills/cyguide-devkit/SKILL.md` or global agent configuration directory (`~/.agents/skills/cyguide-devkit/`).
* The skill provides exhaustive instructions on non-interactive flags, streaming JSON parsing, wordlist substitution, graph relationship auto-wiring, AI explainer category directives, output sanitization hooks (`sanitize_output`), and the repository ecosystem checklist.

---

## Running Tests

Run the hermetic test suite:

```bash
pytest tests/
```

---

## License

MIT

---
name: adapter-authoring
description: Expert skill for authoring comprehensive CyGuide tool adapters. Inspects CLI tools, authors typed manifest.toml with curriculum-grade recipes and protocol theory, implements adapter.py with JSON/regex streaming parsers and graph relation auto-wiring, and creates hermetic pytest fixtures.
---

# CyGuide Adapter Authoring Skill

This skill guides the creation and maintenance of production-grade, deep tool adapters for CyGuide. Every tool in CyGuide is isolated into its own self-contained directory under `tools/<tool_name>/` using the **Smart Adapter / Stupid Framework** architecture. The core framework (`cyguide/engine`) manages the subprocess lifecycle, deterministic SQLite entity graph, and user interface without containing tool-specific execution or parsing logic.

---

## 1. Directory Structure Contract

Every tool plugin must adhere to this file layout:

```text
tools/<tool_name>/
├── __init__.py
├── manifest.toml         # Metadata, contracts, modes, and curriculum recipes
├── adapter.py            # ToolAdapter (build_command + parse_output + sanitize_output)
└── cli.py                # (Optional) Pure-Python CLI entry point for bundled tools (e.g. dnspython)

tests/fixtures/mock_tools/<tool_name>.(json|jsonl|txt)  # Raw sample output captured from tool
tests/unit/test_parsers/test_<tool_name>_parser.py     # Hermetic pytest unit test suite
```

---

## 2. Declarative Manifest Contract (`manifest.toml`)

The manifest defines the tool's integration points, schema input/output contracts, parameter configurations, and educational syllabus.

```toml
[meta]
name = "<tool_name>"
description = "Detailed multi-sentence explanation of tool purpose, mechanics, and capabilities."
one_line_summary = "Concise action-oriented summary for UI headers and tool selector badges."
category = "Web Application Analysis" # UI grouping category
categories = ["web", "recon", "fuzzing", "vulnerability"]
binary = "<binary_name>" # Executable name verified via shutil.which()

[modes]
learning = true
power = true

[input]
accepts = ["network.host", "network.service", "web.endpoint"] # Must match schemas from SCHEMA_REGISTRY.md

[output]
produces = ["web.endpoint", "audit.misconfig", "vulnerability.found"] # Emitted finding schemas

[learning]
enabled = true

[[learning.recipes]]
name = "Standard Directory Discovery"
difficulty = "Beginner" # Beginner | Intermediate | Advanced
description = "Enumerate common directories and sensitive configuration files on target server."
flags = ["-u", "{url}", "-w", "{wordlist:common_dirs}"]

[learning.recipes.theory]
concept = "HTTP Response Code Analysis & Forced Browsing"
explanation = """
1. What the tool does: Emits rapid HTTP GET requests for dictionary entries appended to the base URL.
2. Flag selection: '-u' defines the endpoint target; '-w' mounts the wordlist.
3. Response interpretation: Status 200 indicates accessible resources; 301/302 indicates redirects; 403 reveals protected administrative surfaces.
"""
packet_wire_summary = "Client GET /admin -> Server HTTP/1.1 200 OK (Content-Length: 1024)"
remediation = "Disable directory listings, enforce strict role-based access control, and remove exposed backup/test files."
```

### Supported Macro Variables in Recipe Flags:
* `{target}`: Target IP, hostname, or endpoint URL.
* `{url}`: Full formatted HTTP/HTTPS URL (e.g., `http://10.0.0.1:80`).
* `{ip}`: Target host IP address.
* `{domain}`: Domain name identifier.
* `{port}`: Target service port number.
* `{wordlist}` / `{wordlist:<name>}`: Centralized wordlist macro expanded by `cyguide.engine.wordlists`. Built-in names:
  - `common_dirs`: Top web directories and files.
  - `subdomains_500`: High-frequency DNS subdomains.
  - `common_params`: Frequent HTTP GET/POST parameter names.
  - `common_usernames`: Standard administrative and service usernames.
  - `common_passwords`: Default credentials and common passwords.

### AI Explainer Category Directives:
Manifest `categories` (e.g. `["web", "recon", "fuzzing"]`) are actively leveraged by CyGuide's AI Explainer engine ([`cyguide/engine/explainer.py`](../../cyguide/engine/explainer.py)). The engine matches declared category keywords against `CATEGORY_DIRECTIVES` to supply targeted pedagogical scaffolding to the AI Tutor during briefings and Q&A:
* **`network`**: Focus on identified open ports, exposed services, transport protocol flags, default credentials risks, and flag mechanics.
* **`recon`**: Analyze discovered targets, endpoints, subdomains, external network perimeter, and attack surface.
* **`web`**: Highlight web application paths, HTTP status codes (200, 301, 401, 403), sensitive resources (`.env`, `.git`), and API endpoints.
* **`vulnerability`**: Detail discovered vulnerability checks, severity ratings (CVSS), CVE identifiers, and actionable remediation steps.
* **`osint`**: Examine registration details, ownership records, public intelligence, and DNS configurations.
* **`dns`**: Assess DNS record configurations (A, MX, TXT, SPF, DMARC), zone delegation, and mail routing misconfigurations.
* **`exploit`**: Assess exploit viability, target software versions, matching CVEs, and privilege escalation vectors.

---

## 3. Adapter Implementation Contract (`adapter.py`)

All adapters inherit from `ToolAdapter` in [`cyguide/engine/adapter.py`](../../cyguide/engine/adapter.py) and implement three core methods (plus an optional hook for output sanitization):

```python
"""<Tool Name> adapter."""

import json
import shlex
import shutil
from typing import Any, AsyncIterator, Dict, List, Optional

from cyguide.engine.adapter import ToolAdapter
from cyguide.engine.wordlists import substitute_wordlist_macros
from cyguide.schemas.base import BaseFinding
from cyguide.schemas.vulnerability import AuditMisconfig
from cyguide.schemas.web import WebEndpoint


class ExampleAdapter(ToolAdapter):
    """Adapter for <tool_name>."""

    def validate_install(self) -> bool:
        """Verify binary is present in system PATH (or Python dependency is importable)."""
        return shutil.which("<binary_name>") is not None

    def sanitize_output(self, raw_stdout: str) -> str:
        """Strip tool-specific ASCII banners, progress lines, or noisy output before LLM prompting."""
        lines = []
        for line in raw_stdout.splitlines():
            s = line.strip()
            # Strip tool-specific ASCII art, progress meters, or loading logs:
            if s.startswith("::") or "Progress: [" in s or s.startswith("____"):
                continue
            lines.append(line)
        return "\n".join(lines)

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Construct CLI arguments safely as an argument list (preventing shell injection)."""
        # 1. Extract target identifiers
        url = target.pik.get("url") or target.data.get("url")
        if not url:
            raise ValueError(f"Target finding {target.schema_type} missing valid URL.")

        # 2. Process user flags and expand wordlist macros
        raw_flags = params.get("raw_flags", "").strip()
        raw_flags, _ = substitute_wordlist_macros(raw_flags)
        flag_args = shlex.split(raw_flags) if raw_flags else []

        args = ["<binary_name>"]

        # 3. Enforce programmatic non-interactive & structured output flags
        if "-u" not in flag_args:
            args.extend(["-u", url])
        if "-oJ" not in flag_args and "--json" not in flag_args:
            args.append("--json")

        args.extend(flag_args)
        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Parse streaming raw stdout into typed finding models with graph parent wiring."""
        cleaned = raw_stdout.strip()
        if not cleaned:
            return

        host_ip = target.pik.get("host_ip") or target.pik.get("ip") or target.data.get("host_ip")

        # 1. Parse JSON / JSONL output
        for line in cleaned.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            endpoint_url = item.get("url", "").strip()
            if endpoint_url:
                # Yield finding with parent host_ip preserved
                yield WebEndpoint.create(
                    url=endpoint_url,
                    host_ip=host_ip,
                    status_code=int(item.get("status", 200)),
                )
```

### Core Implementation Invariants:
1. **Never block interactively**: Enforce non-interactive flags (`--batch`, `-oJ`, `-q`, `-silent`, `--noninteractive`).
2. **Prefer structured JSON/JSONL output**: Modern security tools (`nuclei`, `ffuf`, `searchsploit`, `dnspython`) output structured data. If a tool prints console banners before JSON, implement slice extraction:
   ```python
   start = cleaned.find("{")
   end = cleaned.rfind("}")
   if start != -1 and end != -1 and end > start:
       data = json.loads(cleaned[start : end + 1])
   ```
3. **Wordlist macro substitution**: If the tool takes wordlists, process flags through `substitute_wordlist_macros(raw_flags)` so users can write `{wordlist:common_dirs}` or `{wordlist}`.
4. **Auto-wire graph relationships**: Extract the target's primary keys (`host_ip`, `port`, `url`, `domain`, `cve_id`) and pass them to the `.create(...)` factory of emitted child findings. This ensures the SQLite entity graph auto-wires parent and child nodes seamlessly.
5. **Pure-Python adapters**: For tools implemented directly in Python (e.g. `dnspython`), `validate_install()` verifies the package can be imported, and `build_command()` invokes `sys.executable -m tools.<tool_name>.cli`.
6. **Strip tool noise with `sanitize_output()` (Optional but recommended)**: Tool-specific ASCII art banners (e.g. `ffuf`, `nuclei`), template loading statistics, and progress bars waste valuable LLM prompt tokens and can confuse local AI models (such as Ollama 8B). Override `sanitize_output(self, raw_stdout: str) -> str` to strip tool-specific noise. CyGuide's core engine automatically cleans ANSI color escape sequences and invokes `adapter.sanitize_output(raw_output)` before feeding scan logs to the AI tutor. If omitted, the default `ToolAdapter` implementation returns `raw_stdout` untouched.

---

## 4. Hermetic Test Fixture & Parser Test Suite

Every adapter must have a hermetic unit test that runs in CI without requiring the real security binary to be installed on the host:

1. Save a sample output file to `tests/fixtures/mock_tools/<tool_name>.(json|jsonl|txt)`.
2. Implement `tests/unit/test_parsers/test_<tool_name>_parser.py`:
   - Test `validate_install()` returns a boolean.
   - Test `build_command()` properly formats target variables, user flags, and macro expansions.
   - Load the mock fixture text and test `parse_output()`.
   - Assert `len(findings) > 0`.
   - Assert specific field values, PIK dictionaries, data attributes, and parent relationship keys on the emitted findings.
   - Test handling of empty strings and malformed noisy output.
   - Test `sanitize_output()` (if customized): Verify that ASCII art banners, progress lines, or noisy headers are stripped while leaving scan findings intact.

---

## 5. Ecosystem Registration Checklist

When creating or significantly updating an adapter, update all corresponding touchpoints across the repository:

| Component | Target File | Required Update |
| :--- | :--- | :--- |
| **Diagnostics** | [`cyguide/engine/diagnostics.py`](../../cyguide/engine/diagnostics.py) | Add package manager installation hint to `INSTALLATION_HINTS`. |
| **System Installer** | [`scripts/install_deps.sh`](../../scripts/install_deps.sh) | Add tool to apt, pacman, dnf, zypper, apk, and brew; add binary release installer function (`install_<tool>_release`); update `verify_tools`. |
| **Docker Image** | [`Dockerfile`](../../Dockerfile) | Add package installation or binary release download to container build; copy `assets/ assets/`. |
| **Mock Fixture** | [`tests/fixtures/mock_tools/<tool>.(json\|jsonl\|txt)`](../../tests/fixtures/mock_tools) | Raw sample output fixture for hermetic tests. |
| **Parser Tests** | [`tests/unit/test_parsers/test_<tool>_parser.py`](../../tests/unit/test_parsers) | Unit tests verifying `validate_install`, `build_command`, `parse_output`, and `sanitize_output`. |
| **Schema Registry** | [`scripts/generate_schema_registry.py`](../../scripts/generate_schema_registry.py) | If emitting any new finding schemas, update parent/association heuristics and run `--check`. |
| **Documentation** | [`README.md`](../../README.md), [`docs/user/USER_MANUAL.md`](../../docs/user/USER_MANUAL.md) | Add the tool to the supported security tools list and package installation guides. |

---

## 6. Reference Tool Matrix

The 9 production adapters in CyGuide serve as standard reference implementations:

| Tool Name | Binary / Module | Primary Finding Schemas Emitted | Category | Reference Source |
| :--- | :--- | :--- | :--- | :--- |
| **nmap** | `nmap` | `network.host`, `network.service` | Network Discovery & Port Scanning | [`tools/nmap/`](../../tools/nmap) |
| **whois** | `whois` | `domain.info`, `network.netblock`, `network.host` | OSINT & Domain Intelligence | [`tools/whois/`](../../tools/whois) |
| **gobuster** | `gobuster` | `web.endpoint` | Web Directory & DNS Brute-Forcing | [`tools/gobuster/`](../../tools/gobuster) |
| **nikto** | `nikto` | `web.vulnerability`, `vulnerability.found` | Web Server Vulnerability Scanning | [`tools/nikto/`](../../tools/nikto) |
| **subfinder** | `subfinder` | `dns.record` | Passive Subdomain Enumeration | [`tools/subfinder/`](../../tools/subfinder) |
| **dnspython** | Pure-Python (`dns.resolver`) | `dns.record` | DNS Resolution & Zone Transfers | [`tools/dnspython/`](../../tools/dnspython) |
| **searchsploit** | `searchsploit` | `exploit.reference` | Exploit-DB Offline Querying | [`tools/searchsploit/`](../../tools/searchsploit) |
| **ffuf** | `ffuf` | `web.endpoint`, `audit.misconfig` | High-Performance Web Fuzzing | [`tools/ffuf/`](../../tools/ffuf) |
| **nuclei** | `nuclei` | `web.technology`, `audit.misconfig`, `vulnerability.found` | Template-Based Vulnerability Scanning | [`tools/nuclei/`](../../tools/nuclei) |

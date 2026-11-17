---
name: cyguide-devkit
description: Expert developer toolkit and authoring skill for CyGuide security tool adapters. Use when creating or scaffolding a new tool adapter in tools/, editing manifest.toml recipes or protocol theory, implementing ToolAdapter parsers and command builders, sanitizing CLI output, writing hermetic parser tests, or running cyguide-devkit validation.
---

# CyGuide Adapter Authoring Skill

This skill guides the creation and maintenance of production-grade, deep tool adapters for **CyGuide**. Every security tool in CyGuide is isolated into its own self-contained directory under `tools/<tool_name>/` using the **Smart Adapter / Stupid Framework** architecture. The core framework (`cyguide/engine`) manages process lifecycles, pub/sub event streams, the deterministic SQLite entity graph, and user interfaces without containing tool-specific execution or parsing logic.

Consult the standalone developer toolkit and CLI at [`h45sh/cyguide-devkit`](https://github.com/h45sh/cyguide-devkit) for automated scaffolding (`cyguide-devkit new`) and static AST validation (`cyguide-devkit validate`).

---

## 1. Directory Structure Contract

Every tool plugin must adhere to this file layout:

```text
tools/<tool_name>/
├── __init__.py
├── manifest.toml         # Metadata, contracts, modes, and curriculum recipes
├── adapter.py            # ToolAdapter (validate_install + build_command + parse_output + sanitize_output)
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
categories = ["web", "recon", "fuzzing", "vulnerability"] # AI explainer category tags
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
Manifest `categories` (e.g. `["web", "recon", "fuzzing"]`) are actively leveraged by CyGuide's AI Explainer engine (`cyguide/engine/explainer.py`). The engine matches declared category keywords against `CATEGORY_DIRECTIVES` to supply targeted pedagogical scaffolding to the AI Tutor during briefings and Q&A:
* **`network`**: Focus on identified open ports, exposed services, transport protocol flags, default credentials risks, and flag mechanics.
* **`recon`**: Analyze discovered targets, endpoints, subdomains, external network perimeter, and attack surface.
* **`web`**: Highlight web application paths, HTTP status codes (200, 301, 401, 403), sensitive resources (`.env`, `.git`), and API endpoints.
* **`vulnerability`**: Detail discovered vulnerability checks, severity ratings (CVSS), CVE identifiers, and actionable remediation steps.
* **`osint`**: Examine registration details, ownership records, public intelligence, and DNS configurations.
* **`dns`**: Assess DNS record configurations (A, MX, TXT, SPF, DMARC), zone delegation, and mail routing misconfigurations.
* **`exploit`**: Assess exploit viability, target software versions, matching CVEs, and privilege escalation vectors.

---

## 3. Adapter Implementation Contract (`adapter.py`)

All adapters inherit from `ToolAdapter` in `cyguide.engine.adapter` and implement three core methods (plus an optional hook for output sanitization):

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
        """
        Strip tool-specific ASCII banners, progress lines, or noisy output before LLM prompting.
        Conserves prompt tokens and prevents local AI models from hallucinating on ASCII art.
        """
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

---

## 4. Core Implementation Rules & Invariants

### 4.1 Command Construction Safety Contract
* **Return `List[str]` only**: `build_command()` must always construct and return a `List[str]`.
* **Zero shell interpolation**: Never use shell string concatenation (e.g. `f"nmap {ip}"`), and never invoke subshells with `shell=True`, `os.system`, `subprocess.getoutput`, or `asyncio.create_subprocess_shell`. All arguments must be separated cleanly into token elements.
* **Non-interactive execution**: Always enforce non-interactive flags (`--batch`, `-oJ`, `-q`, `-silent`, `--noninteractive`) so subprocesses never hang waiting for stdin.

### 4.2 Non-Zero Exit Code Resilience Contract
* **Security tool exit code realities**: Security scanners and enumeration tools frequently terminate with non-zero exit codes during normal, productive operations:
  - `nikto`: Exits with code `1` whenever web server vulnerabilities or misconfigurations are discovered.
  - `nuclei`: Exits with code `1` or `2` when vulnerabilities are matched or network timeouts occur.
  - `nmap`: Exits with non-zero codes on target connection timeouts or partial network unreachable states.
* **Parsing Invariant**: The adapter's `parse_output()` method **must parse valid stdout and yield findings regardless of the process exit code**. Never discard output or fail silently simply because the return code was non-zero.

### 4.3 Output Sanitization (`sanitize_output`) Standards
* **Why sanitize?**: High-speed scanners (`ffuf`, `nuclei`, `subfinder`, `gobuster`) output large ASCII art headers (figlet banners), terminal progress indicators (`
`), and redundant diagnostic statistics. When scan logs are fed to the AI Explainer/Tutor, these noise tokens consume prompt token context and can cause local LLMs (e.g. Ollama 8B) to hallucinate.
* **Mechanism**:
  - The CyGuide core engine automatically strips ANSI color escape codes from stdout.
  - The core engine then calls `adapter.sanitize_output(raw_stdout)` before presenting output in briefings or prompts.
  - In `sanitize_output()`, strip:
    1. Figlet / ASCII art logos (e.g. lines starting with `::`, `___`, `====`, or containing `v2.x.x`).
    2. Carriage return progress meters (`Progress: [...]`, `[ETA ...]`).
    3. Redundant separator lines.
  - Keep actual findings, endpoints, status codes, and scan summaries intact.

### 4.4 Streaming JSON & Partial Slice Extraction
Modern security tools output structured JSON or JSONL. When tools prepend ASCII banners or status text before valid JSON, implement slice extraction:
```python
start = cleaned.find("{")
end = cleaned.rfind("}")
if start != -1 and end != -1 and end > start:
    data = json.loads(cleaned[start : end + 1])
```

### 4.5 Deterministic Graph Auto-Wiring & PIK Keys
Every finding model inherits from `BaseFinding` and utilizes Primary Identification Keys (PIKs):
* Extract the target's primary keys (`host_ip`, `ip`, `port`, `url`, `domain`, `cve_id`) from `target.pik` or `target.data`.
* Pass these keys to the `.create(...)` factory of child findings.
* This guarantees that the SQLite entity graph auto-wires parent and child entities deterministically.

### 4.6 Pure-Python Adapters
For tools implemented directly in Python (e.g. `dnspython`):
* `validate_install()` verifies the Python package is importable (`importlib.util.find_spec(...)`).
* `build_command()` invokes `[sys.executable, "-m", "tools.<tool_name>.cli", ...]`.

---

## 5. Hermetic Test Fixture & Parser Test Suite

Every adapter must have a hermetic unit test that runs in CI without requiring the real security binary to be installed on the host:

1. Save a sample output file to `tests/fixtures/mock_tools/<tool_name>.(json|jsonl|txt)`.
2. Implement `tests/unit/test_parsers/test_<tool_name>_parser.py`:
   - Test `validate_install()` returns a boolean.
   - Test `build_command()` properly formats target variables, user flags, and macro expansions as a `List[str]`.
   - Test `sanitize_output()`: Verify that ASCII art banners and progress lines are stripped while scan findings remain intact.
   - Load the mock fixture text and test `parse_output()`.
   - Assert `len(findings) > 0`.
   - Assert specific field values, PIK dictionaries, data attributes, and parent relationship keys on the emitted findings.
   - Test handling of empty strings and malformed noisy output.

---

## 6. Ecosystem Registration Checklist

When creating or significantly updating an adapter, update all corresponding touchpoints across the repository:

| Component | Target File | Required Update |
| :--- | :--- | :--- |
| **Diagnostics** | `cyguide/engine/diagnostics.py` | Add package manager installation hint to `INSTALLATION_HINTS`. |
| **System Installer** | `scripts/install_deps.sh` | Add tool to apt, pacman, dnf, zypper, apk, and brew; add binary release installer function (`install_<tool>_release`); update `verify_tools`. |
| **Docker Image** | `Dockerfile` | Add package installation or binary release download to container build; copy `assets/ assets/`. |
| **Mock Fixture** | `tests/fixtures/mock_tools/<tool>.(json|jsonl|txt)` | Raw sample output fixture for hermetic tests. |
| **Parser Tests** | `tests/unit/test_parsers/test_<tool>_parser.py` | Unit tests verifying `validate_install`, `build_command`, `parse_output`, and `sanitize_output`. |
| **Schema Registry** | `scripts/generate_schema_registry.py` | If emitting any new finding schemas, update parent/association heuristics and run `--check`. |
| **Documentation** | `README.md`, `docs/user/USER_MANUAL.md` | Add the tool to the supported security tools list and package installation guides. |

---

## 7. Reference Tool Matrix

The 9 production adapters in CyGuide serve as standard reference implementations:

| Tool Name | Binary / Module | Primary Finding Schemas Emitted | Category | Reference Source |
| :--- | :--- | :--- | :--- | :--- |
| **nmap** | `nmap` | `network.host`, `network.service` | Network Discovery & Port Scanning | `tools/nmap/` |
| **whois** | `whois` | `domain.info`, `network.netblock`, `network.host` | OSINT & Domain Intelligence | `tools/whois/` |
| **gobuster** | `gobuster` | `web.endpoint` | Web Directory & DNS Brute-Forcing | `tools/gobuster/` |
| **nikto** | `nikto` | `web.vulnerability`, `vulnerability.found` | Web Server Vulnerability Scanning | `tools/nikto/` |
| **subfinder** | `subfinder` | `dns.record` | Passive Subdomain Enumeration | `tools/subfinder/` |
| **dnspython** | Pure-Python (`dns.resolver`) | `dns.record` | DNS Resolution & Zone Transfers | `tools/dnspython/` |
| **searchsploit** | `searchsploit` | `exploit.reference` | Exploit-DB Offline Querying | `tools/searchsploit/` |
| **ffuf** | `ffuf` | `web.endpoint`, `audit.misconfig` | High-Performance Web Fuzzing | `tools/ffuf/` |
| **nuclei** | `nuclei` | `web.technology`, `audit.misconfig`, `vulnerability.found` | Template-Based Vulnerability Scanning | `tools/nuclei/` |

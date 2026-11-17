# Contributing to CyGuide DevKit (`cyguide-devkit`)

Thank you for contributing to `cyguide-devkit`! This repository contains the developer CLI tools, schema validators, scaffolding generators, and AI agent skills for authoring tool plugins for **[CyGuide](https://github.com/h45sh/cyguide)**.

---

## 1. Development Setup

Clone the repository and install it in editable mode with development dependencies:

```bash
git clone https://github.com/h45sh/cyguide-devkit.git
cd cyguide-devkit
pip install -e ".[dev]"
```

Requirements:
- **Python 3.11+**
- Zero external runtime dependencies (relies strictly on standard library modules such as `tomllib`, `ast`, and `argparse`).

---

## 2. Repository Structure

```text
cyguide-devkit/
├── LICENSE              # MIT License
├── README.md            # User manual and CLI overview
├── CONTRIBUTING.md      # Contributor and development guide
├── SKILL.md             # Canonical Agent Skill for AI coding assistants
├── pyproject.toml       # Package metadata, scripts, and pytest configuration
├── src/
│   └── cyguide_devkit/
│       ├── __init__.py  # Package exports
│       ├── cli.py       # Command-line entry points (new, validate, list-schemas, list-wordlists)
│       ├── generator.py # Scaffolding engine for creating adapter boilerplates
│       ├── schemas.py   # Registry of supported CyGuide schemas and wordlist macros
│       ├── validator.py # AST inspection and TOML schema validation
│       └── templates/   # Template files used by scaffolding generator
└── tests/               # Hermetic pytest suite
    ├── test_cli.py
    ├── test_generator.py
    └── test_validator.py
```

---

## 3. Running Verification & Tests

Always run the test suite before submitting pull requests:

```bash
pytest tests/
```

To test against real adapters in the CyGuide repository:
```bash
python -m cyguide_devkit.cli validate /path/to/cyguide/tools
```

---

## 4. Coding & Architecture Standards

1. **Zero External Runtime Dependencies**:
   `cyguide-devkit` is designed to be lightweight and portable. Do not add runtime dependencies unless strictly necessary.
2. **Deterministic & Hermetic**:
   Tests must run offline without internet access or real security tool binaries installed.
3. **AST Linting & Safety**:
   When updating the validator or generator, ensure the contracts defined in `SKILL.md` are upheld:
   - Command construction safety (`List[str]` only, zero `shell=True` or subshell invocation).
   - Non-zero exit code resilience for parsers.
   - Synchronous `sanitize_output` hook signature.

---

## 5. Pull Requests & Conventional Commits

We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat: ...` for new features or CLI capabilities.
- `fix: ...` for bug fixes in validation or generation logic.
- `docs: ...` for documentation or `SKILL.md` updates.
- `test: ...` for unit test enhancements.

Ensure your branch is clean, up-to-date with `main`, and all tests pass.

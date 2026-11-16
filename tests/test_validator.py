"""Tests for manifest and adapter validation."""

import tempfile
from pathlib import Path
import pytest

from cyguide_adapter_authoring.validator import (
    validate_manifest_content,
    validate_manifest_file,
    validate_adapter_directory,
)


def test_valid_manifest_content():
    content = """
[meta]
name = "testtool"
description = "A comprehensive test tool"
one_line_summary = "test tool summary"
category = "Network Discovery"
categories = ["network"]
binary = "testtool"

[modes]
learning = true
power = false

[input]
accepts = ["network.host"]

[output]
produces = ["network.service"]

[learning]
enabled = true

[[learning.recipes]]
name = "Standard Run"
difficulty = "Beginner"
description = "Default scan"
flags = ["-t", "{target}"]

[learning.recipes.theory]
concept = "Testing Concept"
explanation = "Detailed explanation"
packet_wire_summary = "SYN -> ACK"
remediation = "Fix ports"
"""
    result, data = validate_manifest_content(content)
    assert result.is_valid
    assert len(result.errors) == 0


def test_invalid_manifest_missing_meta():
    content = """
[modes]
learning = true
power = false
"""
    result, _ = validate_manifest_content(content)
    assert not result.is_valid
    assert any("Missing or invalid [meta]" in e for e in result.errors)


def test_invalid_difficulty():
    content = """
[meta]
name = "testtool"
description = "A test tool"
one_line_summary = "test summary"
category = "Network Discovery"
categories = ["network"]
binary = "testtool"

[modes]
learning = true
power = false

[input]
accepts = ["network.host"]

[output]
produces = ["network.service"]

[learning]
enabled = true

[[learning.recipes]]
name = "Standard Run"
difficulty = "SuperHard"
description = "Default scan"
flags = ["-t", "{target}"]

[learning.recipes.theory]
concept = "Concept"
explanation = "Explanation"
packet_wire_summary = "Wire"
remediation = "Remediation"
"""
    result, _ = validate_manifest_content(content)
    assert not result.is_valid
    assert any("invalid 'difficulty'" in e for e in result.errors)


def test_validate_adapter_sanitize_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        tool_dir = Path(tmpdir)
        (tool_dir / "__init__.py").write_text("", encoding="utf-8")
        (tool_dir / "manifest.toml").write_text("""
[meta]
name = "santool"
description = "Sanitizer test tool"
one_line_summary = "test summary"
category = "Network"
categories = ["network"]
binary = "santool"

[modes]
learning = true
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.service"]
""", encoding="utf-8")

        # 1. Valid synchronous sanitize_output
        (tool_dir / "adapter.py").write_text("""
class SantoolAdapter:
    def validate_install(self): return True
    def build_command(self, target, params): return ["santool"]
    async def parse_output(self, raw_stdout, target, context=None): pass
    def sanitize_output(self, raw_stdout: str) -> str: return raw_stdout.strip()
""", encoding="utf-8")

        res = validate_adapter_directory(tool_dir)
        assert res.is_valid

        # 2. Invalid async sanitize_output
        (tool_dir / "adapter.py").write_text("""
class SantoolAdapter:
    def validate_install(self): return True
    def build_command(self, target, params): return ["santool"]
    async def parse_output(self, raw_stdout, target, context=None): pass
    async def sanitize_output(self, raw_stdout: str) -> str: return raw_stdout.strip()
""", encoding="utf-8")

        res_async = validate_adapter_directory(tool_dir)
        assert not res_async.is_valid
        assert any("defines 'sanitize_output' as async" in e for e in res_async.errors)

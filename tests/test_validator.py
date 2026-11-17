"""Tests for manifest and adapter validation."""

import tempfile
from pathlib import Path
import pytest

from cyguide_devkit.validator import (
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


def test_validate_adapter_directory_rejects_dunder_and_hidden():
    with tempfile.TemporaryDirectory() as tmpdir:
        dunder_dir = Path(tmpdir) / "__pycache__"
        dunder_dir.mkdir()
        res = validate_adapter_directory(dunder_dir)
        assert not res.is_valid
        assert any("Cannot validate internal or hidden directory" in e for e in res.errors)

        hidden_dir = Path(tmpdir) / ".git"
        hidden_dir.mkdir()
        res_hidden = validate_adapter_directory(hidden_dir)
        assert not res_hidden.is_valid
        assert any("Cannot validate internal or hidden directory" in e for e in res_hidden.errors)


def test_validate_adapter_ast_security_shell_true():
    with tempfile.TemporaryDirectory() as tmpdir:
        tool_dir = Path(tmpdir)
        (tool_dir / "__init__.py").write_text("", encoding="utf-8")
        (tool_dir / "manifest.toml").write_text("""
[meta]
name = "shelltool"
description = "Shell tool"
one_line_summary = "test summary"
category = "Network"
categories = ["network"]
binary = "shelltool"

[modes]
learning = true
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.service"]
""", encoding="utf-8")

        (tool_dir / "adapter.py").write_text("""
import subprocess

class ShellToolAdapter:
    def validate_install(self): return True
    def build_command(self, target, params):
        subprocess.run("echo hi", shell=True)
        return ["shelltool"]
    async def parse_output(self, raw_stdout, target, context=None): pass
""", encoding="utf-8")

        res = validate_adapter_directory(tool_dir)
        assert not res.is_valid
        assert any("invokes process with shell=True" in e for e in res.errors)


def test_validate_adapter_ast_security_unsafe_functions():
    with tempfile.TemporaryDirectory() as tmpdir:
        tool_dir = Path(tmpdir)
        (tool_dir / "__init__.py").write_text("", encoding="utf-8")
        (tool_dir / "manifest.toml").write_text("""
[meta]
name = "unsafetool"
description = "Unsafe tool"
one_line_summary = "test summary"
category = "Network"
categories = ["network"]
binary = "unsafetool"

[modes]
learning = true
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.service"]
""", encoding="utf-8")

        (tool_dir / "adapter.py").write_text("""
import os

class UnsafeToolAdapter:
    def validate_install(self): return True
    def build_command(self, target, params):
        os.system("whoami")
        return ["unsafetool"]
    async def parse_output(self, raw_stdout, target, context=None): pass
""", encoding="utf-8")

        res = validate_adapter_directory(tool_dir)
        assert not res.is_valid
        assert any("invokes unsafe shell execution" in e for e in res.errors)


def test_validate_adapter_ignores_helper_classes():
    with tempfile.TemporaryDirectory() as tmpdir:
        tool_dir = Path(tmpdir)
        (tool_dir / "__init__.py").write_text("", encoding="utf-8")
        (tool_dir / "manifest.toml").write_text("""
[meta]
name = "helpertool"
description = "Helper tool"
one_line_summary = "test summary"
category = "Network"
categories = ["network"]
binary = "helpertool"

[modes]
learning = true
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.service"]
""", encoding="utf-8")

        (tool_dir / "adapter.py").write_text("""
class ParseState:
    '''Helper state class with no adapter methods.'''
    count = 0

class HelperToolAdapter:
    def validate_install(self): return True
    def build_command(self, target, params): return ["helpertool"]
    async def parse_output(self, raw_stdout, target, context=None): pass
""", encoding="utf-8")

        res = validate_adapter_directory(tool_dir)
        assert res.is_valid
        # ParseState should not produce missing method warnings
        assert not any("ParseState" in w for w in res.warnings)

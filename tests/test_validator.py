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

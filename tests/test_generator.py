"""Tests for adapter generator."""

import tempfile
from pathlib import Path

from cyguide_adapter_authoring.generator import scaffold_adapter
from cyguide_adapter_authoring.validator import validate_adapter_directory


def test_scaffold_adapter():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        paths = scaffold_adapter(
            tool_name="dummy_tool",
            target_root=tmp_path,
            binary="dummy",
            category="Network Discovery",
            categories=["network"],
            accepts=["network.host"],
            produces=["network.service"],
        )

        assert paths["manifest"].exists()
        assert paths["adapter"].exists()
        assert paths["fixture"].exists()
        assert paths["test"].exists()

        # Validate generated adapter directory
        tool_dir = tmp_path / "tools" / "dummy_tool"
        result = validate_adapter_directory(tool_dir)
        assert result.is_valid
        assert len(result.errors) == 0

"""Tests for CLI interface."""

import tempfile
from pathlib import Path
import pytest

from cyguide_devkit.cli import main


def test_cli_list_schemas(capsys):
    ret = main(["list-schemas"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "network.host" in captured.out
    assert "web.endpoint" in captured.out


def test_cli_list_wordlists(capsys):
    ret = main(["list-wordlists"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "{wordlist:common_dirs}" in captured.out


def test_cli_new_and_validate(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        ret = main(["new", "testscan", "--target-dir", tmpdir])
        assert ret == 0

        target_tool = Path(tmpdir) / "tools" / "testscan"
        assert target_tool.exists()

        val_ret = main(["validate", str(target_tool)])
        assert val_ret == 0


def test_cli_batch_validate_success(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        # Scaffold two valid tools
        main(["new", "toolone", "--target-dir", tmpdir])
        main(["new", "tooltwo", "--target-dir", tmpdir])

        # Add a non-adapter directory and a hidden/dunder directory
        tools_root = Path(tmpdir) / "tools"
        (tools_root / "common_docs").mkdir()
        (tools_root / "__pycache__").mkdir()
        (tools_root / ".cache").mkdir()

        # Batch validate
        ret = main(["validate", str(tools_root)])
        assert ret == 0

        captured = capsys.readouterr()
        assert "toolone" in captured.out
        assert "tooltwo" in captured.out
        assert "PASS" in captured.out
        assert "All adapters in batch strictly passed validation" in captured.out


def test_cli_batch_validate_failure(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        tools_root = Path(tmpdir) / "tools"
        tools_root.mkdir()

        # Create broken adapter (has adapter.py but missing manifest.toml)
        broken_tool = tools_root / "brokentool"
        broken_tool.mkdir()
        (broken_tool / "adapter.py").write_text("class BrokenAdapter: pass")

        ret = main(["validate", str(tools_root)])
        assert ret == 1

        captured = capsys.readouterr()
        assert "brokentool" in captured.out
        assert "FAIL" in captured.out
        assert "Batch validation failed" in captured.err


def test_cli_batch_validate_empty(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_dir = Path(tmpdir) / "empty_tools"
        empty_dir.mkdir()

        ret = main(["validate", str(empty_dir)])
        assert ret == 1

        captured = capsys.readouterr()
        assert "No tool adapters found" in captured.err

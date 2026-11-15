"""Tests for CLI interface."""

import tempfile
from pathlib import Path
import pytest

from cyguide_adapter_authoring.cli import main


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

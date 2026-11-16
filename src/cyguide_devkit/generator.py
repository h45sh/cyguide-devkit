"""Scaffolding and generation logic for CyGuide tool adapters."""

import json
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

from cyguide_devkit.schemas import SUPPORTED_SCHEMAS


def to_pascal_case(name: str) -> str:
    """Convert snake_case or kebab-case name to PascalCase."""
    clean = re.sub(r"[^a-zA-Z0-9]+", " ", name)
    return "".join(word.capitalize() for word in clean.split())


def get_schema_import_info(produces: List[str]) -> Tuple[str, str]:
    """Return appropriate schema import lines and finding instantiation yield snippet."""
    imports = []
    yield_lines = []

    if any(p.startswith("web.") for p in produces):
        imports.append("from cyguide.schemas.web import WebEndpoint")
        yield_lines.append(
            'yield WebEndpoint.create(\n                url=item.get("target") or item.get("url") or f"http://{host_ip}",\n                host_ip=host_ip,\n                status_code=int(item.get("status", 200)),\n            )'
        )
    elif any(p.startswith("network.") for p in produces):
        imports.append("from cyguide.schemas.network import NetworkService")
        yield_lines.append(
            'yield NetworkService.create(\n                host_ip=host_ip or "127.0.0.1",\n                port=int(item.get("port", 80)),\n                protocol=item.get("protocol", "tcp"),\n                service_name=item.get("service", "unknown"),\n            )'
        )
    elif any(p.startswith("vulnerability.") or p.startswith("audit.") for p in produces):
        imports.append("from cyguide.schemas.vulnerability import AuditMisconfig")
        yield_lines.append(
            'yield AuditMisconfig.create(\n                target=item.get("target", str(host_ip)),\n                check_id=item.get("check_id", "detected-issue"),\n                title=item.get("title", "Discovered Issue"),\n                severity=item.get("severity", "medium"),\n                host_ip=host_ip,\n            )'
        )
    else:
        imports.append("from cyguide.schemas.base import BaseFinding")
        yield_lines.append(
            'yield BaseFinding(\n                schema_type=item.get("schema_type", "'
            + (produces[0] if produces else "network.host")
            + '"),\n                pik={"target": item.get("target", "unknown")},\n                data=item,\n            )'
        )

    import_str = "\n".join(imports)
    yield_str = "\n            ".join(yield_lines)
    return import_str, yield_str


def scaffold_adapter(
    tool_name: str,
    target_root: Path,
    binary: Optional[str] = None,
    category: str = "Network Discovery",
    categories: Optional[List[str]] = None,
    accepts: Optional[List[str]] = None,
    produces: Optional[List[str]] = None,
    target_flag: str = "-t",
) -> Dict[str, Path]:
    """Scaffold complete tool adapter files into target directory."""
    tool_slug = tool_name.strip().lower().replace("-", "_")
    binary_name = binary or tool_slug
    class_name = f"{to_pascal_case(tool_slug)}Adapter"
    categories_list = categories or ["network", "recon"]
    accepts_list = accepts or ["network.host"]
    produces_list = produces or ["network.service"]

    templates_dir = Path(__file__).parent / "templates"
    manifest_tmpl = (templates_dir / "manifest.toml.template").read_text(encoding="utf-8")
    adapter_tmpl = (templates_dir / "adapter.py.template").read_text(encoding="utf-8")
    test_tmpl = (templates_dir / "test_parser.py.template").read_text(encoding="utf-8")
    fixture_tmpl = (templates_dir / "fixture.txt.template").read_text(encoding="utf-8")

    schema_imports, primary_yield = get_schema_import_info(produces_list)

    # 1. Render manifest.toml
    default_flags_json = json.dumps([target_flag, "{target}", "--json"]) if target_flag else json.dumps(["{target}"])
    rendered_manifest = manifest_tmpl.format(
        tool_name=tool_slug,
        tool_title=to_pascal_case(tool_slug),
        description=f"High-performance {tool_slug} security assessment utility.",
        one_line_summary=f"security scanning and enumeration via {tool_slug}",
        category=category,
        categories=json.dumps(categories_list),
        binary=binary_name,
        accepts=json.dumps(accepts_list),
        produces=json.dumps(produces_list),
        default_flags=default_flags_json,
    )

    # 2. Render adapter.py
    rendered_adapter = adapter_tmpl.format(
        tool_name=tool_slug,
        tool_title=to_pascal_case(tool_slug),
        class_name=class_name,
        binary=binary_name,
        target_flag=target_flag,
        schema_imports=schema_imports,
        primary_finding_yield=primary_yield,
    )

    # 3. Render test file
    rendered_test = test_tmpl.format(
        tool_name=tool_slug,
        class_name=class_name,
        binary=binary_name,
        primary_input_schema=accepts_list[0],
        produced_schemas_csv=", ".join(f'"{p}"' for p in produces_list),
    )

    # Create destination paths
    tool_dir = target_root / "tools" / tool_slug
    fixture_dir = target_root / "tests" / "fixtures" / "mock_tools"
    parser_tests_dir = target_root / "tests" / "unit" / "test_parsers"

    tool_dir.mkdir(parents=True, exist_ok=True)
    fixture_dir.mkdir(parents=True, exist_ok=True)
    parser_tests_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "init": tool_dir / "__init__.py",
        "manifest": tool_dir / "manifest.toml",
        "adapter": tool_dir / "adapter.py",
        "fixture": fixture_dir / f"{tool_slug}.txt",
        "test": parser_tests_dir / f"test_{tool_slug}_parser.py",
    }

    paths["init"].write_text("", encoding="utf-8")
    paths["manifest"].write_text(rendered_manifest, encoding="utf-8")
    paths["adapter"].write_text(rendered_adapter, encoding="utf-8")
    paths["fixture"].write_text(fixture_tmpl, encoding="utf-8")
    paths["test"].write_text(rendered_test, encoding="utf-8")

    return paths

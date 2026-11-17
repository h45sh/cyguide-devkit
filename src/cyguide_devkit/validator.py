"""Validation logic for CyGuide tool manifests and adapters."""

import ast
from pathlib import Path
import re
import tomllib
from typing import Any, Dict, List, Tuple

from cyguide_devkit.schemas import (
    SUPPORTED_SCHEMAS,
    VALID_DIFFICULTIES,
    VALID_MACROS,
)


class ValidationResult:
    """Holds validation errors and warnings."""

    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


def validate_manifest_content(content: str) -> Tuple[ValidationResult, Dict[str, Any]]:
    """Validate TOML string content according to CyGuide manifest rules."""
    result = ValidationResult()
    try:
        data = tomllib.loads(content)
    except Exception as exc:
        result.add_error(f"Invalid TOML syntax: {exc}")
        return result, {}

    # 1. Validate [meta]
    meta = data.get("meta")
    if not isinstance(meta, dict):
        result.add_error("Missing or invalid [meta] section")
    else:
        for req_field in ["name", "description", "one_line_summary", "category", "binary"]:
            val = meta.get(req_field)
            if not val or not isinstance(val, str) or not val.strip():
                result.add_error(f"[meta] missing required non-empty string field: '{req_field}'")
        categories = meta.get("categories")
        if not isinstance(categories, list) or len(categories) == 0:
            result.add_warning("[meta].categories should be a non-empty list of tags")

    # 2. Validate [modes]
    modes = data.get("modes")
    if not isinstance(modes, dict):
        result.add_error("Missing or invalid [modes] section")
    else:
        if "learning" not in modes or not isinstance(modes["learning"], bool):
            result.add_error("[modes].learning must be a boolean")
        if "power" not in modes or not isinstance(modes["power"], bool):
            result.add_error("[modes].power must be a boolean")

    # 3. Validate [input]
    input_sec = data.get("input")
    if not isinstance(input_sec, dict):
        result.add_error("Missing or invalid [input] section")
    else:
        accepts = input_sec.get("accepts", [])
        if not isinstance(accepts, list) or len(accepts) == 0:
            result.add_error("[input].accepts must be a non-empty list of schema types")
        else:
            for s in accepts:
                if s not in SUPPORTED_SCHEMAS:
                    result.add_warning(
                        f"[input].accepts contains unrecognized schema '{s}'. Valid schemas: {sorted(SUPPORTED_SCHEMAS.keys())}"
                    )

    # 4. Validate [output]
    output_sec = data.get("output")
    if not isinstance(output_sec, dict):
        result.add_error("Missing or invalid [output] section")
    else:
        produces = output_sec.get("produces", [])
        if not isinstance(produces, list) or len(produces) == 0:
            result.add_error("[output].produces must be a non-empty list of schema types")
        else:
            for s in produces:
                if s not in SUPPORTED_SCHEMAS:
                    result.add_warning(
                        f"[output].produces contains unrecognized schema '{s}'. Valid schemas: {sorted(SUPPORTED_SCHEMAS.keys())}"
                    )

    # 5. Validate [learning]
    learning = data.get("learning")
    if isinstance(learning, dict) and learning.get("enabled", False):
        recipes = learning.get("recipes", [])
        if not isinstance(recipes, list) or len(recipes) == 0:
            result.add_error("[learning].enabled is true but [[learning.recipes]] is empty")
        else:
            macro_pattern = re.compile(r"\{[a-zA-Z0-9_:]+\}")
            for idx, recipe in enumerate(recipes):
                prefix = f"[[learning.recipes]][{idx}]"
                r_name = recipe.get("name")
                if not r_name or not isinstance(r_name, str):
                    result.add_error(f"{prefix} missing valid 'name'")
                diff = recipe.get("difficulty")
                if diff not in VALID_DIFFICULTIES:
                    result.add_error(
                        f"{prefix} invalid 'difficulty' ('{diff}'). Must be one of {sorted(VALID_DIFFICULTIES)}"
                    )
                flags = recipe.get("flags")
                if not isinstance(flags, list):
                    result.add_error(f"{prefix} 'flags' must be a list of strings")
                else:
                    for f in flags:
                        if not isinstance(f, str):
                            result.add_error(f"{prefix} 'flags' items must be strings")
                        for m in macro_pattern.findall(str(f)):
                            if m not in VALID_MACROS and not m.startswith("{target."):
                                result.add_warning(f"{prefix} uses uncommon macro '{m}'")

                theory = recipe.get("theory")
                if not isinstance(theory, dict):
                    result.add_error(f"{prefix} missing [learning.recipes.theory] section")
                else:
                    for t_field in ["concept", "explanation", "packet_wire_summary", "remediation"]:
                        if not theory.get(t_field):
                            result.add_error(f"{prefix}.theory missing required field '{t_field}'")

    return result, data


def validate_manifest_file(file_path: Path) -> ValidationResult:
    """Validate a manifest.toml file path."""
    res = ValidationResult()
    if not file_path.exists():
        res.add_error(f"File not found: {file_path}")
        return res
    content = file_path.read_text(encoding="utf-8")
    val_res, _ = validate_manifest_content(content)
    return val_res


def validate_adapter_directory(dir_path: Path) -> ValidationResult:
    """Validate a complete tool directory (manifest.toml, adapter.py, __init__.py)."""
    res = ValidationResult()
    if dir_path.name.startswith((".", "__")):
        res.add_error(f"Cannot validate internal or hidden directory: '{dir_path.name}'")
        return res

    if not dir_path.is_dir():
        res.add_error(f"Directory not found: {dir_path}")
        return res

    manifest_path = dir_path / "manifest.toml"
    if not manifest_path.exists():
        res.add_error(f"Missing manifest.toml in {dir_path}")
    else:
        m_res = validate_manifest_file(manifest_path)
        res.errors.extend(m_res.errors)
        res.warnings.extend(m_res.warnings)

    adapter_path = dir_path / "adapter.py"
    if not adapter_path.exists():
        res.add_error(f"Missing adapter.py in {dir_path}")
    else:
        # Static AST inspection of adapter.py
        try:
            tree = ast.parse(adapter_path.read_text(encoding="utf-8"))
            adapter_classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            if not adapter_classes:
                res.add_error(f"adapter.py does not define any class: {adapter_path}")
            else:
                # Filter for adapter class (ToolAdapter subclass or *Adapter name)
                target_classes = [
                    cls for cls in adapter_classes
                    if any(
                        (isinstance(b, ast.Name) and b.id == "ToolAdapter")
                        or (isinstance(b, ast.Attribute) and b.attr == "ToolAdapter")
                        for b in cls.bases
                    ) or cls.name.endswith("Adapter")
                ]
                classes_to_check = target_classes if target_classes else adapter_classes

                for cls in classes_to_check:
                    methods = {n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    for req_method in ["validate_install", "build_command", "parse_output"]:
                        if req_method not in methods:
                            res.add_warning(
                                f"Class '{cls.name}' in adapter.py might be missing method '{req_method}'"
                            )
                    for n in cls.body:
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "sanitize_output":
                            if isinstance(n, ast.AsyncFunctionDef):
                                res.add_error(
                                    f"Class '{cls.name}' in adapter.py defines 'sanitize_output' as async, but it must be synchronous"
                                )

            # AST Security Lint: Check for unsafe shell execution / command construction violations
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check for shell=True keyword argument
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                res.add_error(
                                    "adapter.py invokes process with shell=True (violates Command Construction Safety Contract)"
                                )
                    # Check for calls to unsafe functions
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        val = node.func.value
                        prefix = getattr(val, "id", "")
                        func_name = f"{prefix}.{node.func.attr}" if prefix else node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    if func_name in {
                        "os.system",
                        "system",
                        "subprocess.getoutput",
                        "getoutput",
                        "subprocess.getstatusoutput",
                        "getstatusoutput",
                        "asyncio.create_subprocess_shell",
                        "create_subprocess_shell",
                    }:
                        res.add_error(
                            f"adapter.py invokes unsafe shell execution '{func_name}' (violates Command Construction Safety Contract)"
                        )

        except (SyntaxError, UnicodeDecodeError, OSError) as e:
            res.add_error(f"Error reading or parsing adapter.py: {e}")

    init_path = dir_path / "__init__.py"
    if not init_path.exists():
        res.add_warning(f"Missing __init__.py in {dir_path}")

    return res

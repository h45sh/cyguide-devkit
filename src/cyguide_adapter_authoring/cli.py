"""Command-line interface for cyguide-adapter-authoring."""

import argparse
from pathlib import Path
import sys

from cyguide_adapter_authoring.generator import scaffold_adapter
from cyguide_adapter_authoring.schemas import SUPPORTED_SCHEMAS, SUPPORTED_WORDLISTS
from cyguide_adapter_authoring.validator import validate_adapter_directory, validate_manifest_file


def cmd_new(args: argparse.Namespace) -> int:
    """Handle 'new' subcommand."""
    target_root = Path(args.target_dir).resolve()
    print(f"[*] Scaffolding CyGuide adapter for '{args.tool_name}' into: {target_root}")

    paths = scaffold_adapter(
        tool_name=args.tool_name,
        target_root=target_root,
        binary=args.binary,
        category=args.category,
        categories=args.categories,
        accepts=args.accepts,
        produces=args.produces,
        target_flag=args.target_flag,
    )

    print("\n[+] Created adapter files successfully:")
    for key, path in paths.items():
        print(f"  - {key.upper()}: {path}")

    print("\n[*] Next Steps:")
    print(f"  1. Edit {paths['manifest']} to refine recipes and protocol theory.")
    print(f"  2. Edit {paths['adapter']} to implement tool-specific parsing logic.")
    print(f"  3. Replace sample fixture in {paths['fixture']} with real tool output.")
    print(f"  4. Run validation: cyguide-adapter-authoring validate {paths['manifest'].parent}")
    print(f"  5. Run pytest: pytest {paths['test']}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Handle 'validate' subcommand."""
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(f"[!] Target path does not exist: {target_path}", file=sys.stderr)
        return 1

    if target_path.is_dir():
        print(f"[*] Validating tool adapter plugin directory: {target_path}")
        result = validate_adapter_directory(target_path)
    else:
        print(f"[*] Validating manifest file: {target_path}")
        result = validate_manifest_file(target_path)

    if result.warnings:
        print("\n[!] Warnings:")
        for w in result.warnings:
            print(f"  - {w}")

    if not result.is_valid:
        print("\n[x] Validation Failed with errors:", file=sys.stderr)
        for err in result.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("\n[✓] Manifest and adapter contracts are strictly valid!")
    return 0


def cmd_list_schemas(args: argparse.Namespace) -> int:
    """Handle 'list-schemas' subcommand."""
    print("===============================================================================")
    print(" CyGuide Registered Finding Schemas")
    print("===============================================================================")
    print(f"{'Schema Type':<22} | {'Parent Finding':<28} | {'PIK Fields'}")
    print("-" * 79)
    for schema, info in sorted(SUPPORTED_SCHEMAS.items()):
        print(f"{schema:<22} | {info['parent']:<28} | {info['pik']}")
    print("-" * 79)
    return 0


def cmd_list_wordlists(args: argparse.Namespace) -> int:
    """Handle 'list-wordlists' subcommand."""
    print("===============================================================================")
    print(" CyGuide Centralized Wordlist Macro Tokens")
    print("===============================================================================")
    print(f"{'Macro Token':<30} | {'Description'}")
    print("-" * 79)
    for name, desc in sorted(SUPPORTED_WORDLISTS.items()):
        print(f"{{wordlist:{name}}}".ljust(30) + f" | {desc}")
    print("{wordlist}".ljust(30) + " | Default alias (resolves to common_dirs)")
    print("-" * 79)
    return 0


def main(argv=None) -> int:
    """Entry point for CLI."""
    parser = argparse.ArgumentParser(
        prog="cyguide-adapter-authoring",
        description="Scaffolding and validation toolkit for CyGuide tool adapters",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: new
    p_new = subparsers.add_parser("new", help="Scaffold a new tool adapter directory and tests")
    p_new.add_argument("tool_name", help="Name of the security tool (e.g. masscan, feroxbuster)")
    p_new.add_argument(
        "--target-dir",
        default=".",
        help="Target project directory root (where tools/ and tests/ reside, defaults to current directory)",
    )
    p_new.add_argument("--binary", default=None, help="Executable binary name (defaults to tool name)")
    p_new.add_argument("--category", default="Network Discovery", help="UI Category header")
    p_new.add_argument(
        "--categories",
        nargs="+",
        default=["network", "recon"],
        help="Category tags (e.g. web recon fuzzing)",
    )
    p_new.add_argument(
        "--accepts",
        nargs="+",
        default=["network.host"],
        help="Input finding schemas accepted by the tool",
    )
    p_new.add_argument(
        "--produces",
        nargs="+",
        default=["network.service"],
        help="Output finding schemas emitted by the tool",
    )
    p_new.add_argument("--target-flag", default="-t", help="Target specification flag (e.g. -u, -h, -t)")
    p_new.set_defaults(func=cmd_new)

    # Subcommand: validate
    p_val = subparsers.add_parser("validate", help="Validate a manifest.toml or tool adapter folder")
    p_val.add_argument("path", help="Path to manifest.toml or tool directory")
    p_val.set_defaults(func=cmd_validate)

    # Subcommand: list-schemas
    p_ls = subparsers.add_parser("list-schemas", help="List all standard CyGuide finding schemas")
    p_ls.set_defaults(func=cmd_list_schemas)

    # Subcommand: list-wordlists
    p_lw = subparsers.add_parser("list-wordlists", help="List supported wordlist macro tokens")
    p_lw.set_defaults(func=cmd_list_wordlists)

    parsed = parser.parse_args(argv)
    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())

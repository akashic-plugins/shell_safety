from __future__ import annotations

import ast
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def _module_identity(path: Path) -> dict[str, object]:
    """Read the v3 identity literals without importing the plugin module."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    identity: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if value is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id not in {"name", "version", "api_version"}:
                continue
            identity[target.id] = ast.literal_eval(value)
    return identity


def test_static_manifest_matches_v3_module_without_importing() -> None:
    """Keep static identity aligned with the plugin source namespace."""

    manifest = tomllib.loads(
        (ROOT / "akashic.plugin.toml").read_text(encoding="utf-8")
    )
    module = _module_identity(ROOT / "plugin.py")

    assert manifest["schema_version"] == 1
    assert manifest["name"] == module["name"] == "shell_safety"
    assert manifest["version"] == module["version"] == "2.0.0"
    assert manifest["api_version"] == module["api_version"] == 3
    assert manifest["entrypoint"] == "plugin.py"

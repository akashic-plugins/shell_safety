from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import plugin as shell_safety
from agent.plugin_composition import CompositionRoot, PluginRuntime
from agent.plugins.composable import ComposablePlugin
from agent.plugins.manager import PluginManager
from agent.plugins.snapshot import (
    RuntimeSnapshotCompiler,
    RuntimeSnapshotStore,
    bind_runtime_snapshot,
    reset_runtime_snapshot,
)
from agent.tool_hooks.executor import ToolExecutor
from agent.tool_hooks.types import ToolExecutionRequest
from bus.event_bus import EventBus


def test_v3_namespace_is_loadable() -> None:
    loaded = ComposablePlugin.from_module(shell_safety)

    assert loaded.name == "shell_safety"
    assert loaded.version == "2.0.0"
    assert loaded.inject == ()


def test_blocks_sudo_without_non_interactive() -> None:
    reason = shell_safety.deny_reason("sudo pacman -Syu --noconfirm")
    assert "sudo -n" in reason


def test_blocks_interactive_editor() -> None:
    reason = shell_safety.deny_reason("sudo -n vim /etc/example.service")
    assert "vim" in reason


def test_blocks_package_write_without_noconfirm() -> None:
    reason = shell_safety.deny_reason("pacman -Syu package")
    assert "--noconfirm" in reason


def test_blocks_system_editor() -> None:
    assert "系统编辑器" in shell_safety.deny_reason("systemctl edit sshd")
    assert "系统编辑器" in shell_safety.deny_reason("crontab -e")


def test_allows_non_interactive_write() -> None:
    reason = shell_safety.deny_reason("sudo -n pacman -Syu --noconfirm")
    assert reason == ""
    assert shell_safety.deny_reason("sudo -nE pacman -Syu --noconfirm") == ""
    assert (
        shell_safety.deny_reason("sudo -nuroot pacman -Syu --noconfirm") == ""
    )
    assert (
        shell_safety.deny_reason(
            "sudo -n --preserve-env=HOME pacman -Syu --noconfirm"
        )
        == ""
    )


def test_sudo_option_value_containing_n_is_not_non_interactive() -> None:
    reason = shell_safety.deny_reason("sudo -unroot pacman -Syu --noconfirm")
    assert "sudo -n" in reason


@pytest.mark.parametrize("mode_flag", ["-e", "-l", "-s", "-i", "-v", "-h"])
def test_sudo_mode_flag_is_denied_after_non_interactive(
    mode_flag: str,
) -> None:
    reason = shell_safety.deny_reason(f"sudo -n {mode_flag} rm /tmp/a.txt")
    assert "不作为普通命令执行" in reason


def test_malformed_shell_is_left_to_shell_boundary() -> None:
    assert shell_safety.deny_reason("sudo '") == ""


@pytest.mark.asyncio
async def test_authorizer_denies_without_invoking(tmp_path: Path) -> None:
    root = CompositionRoot("shell-safety-direct")
    _ = await root.mount(
        lambda ctx: shell_safety.apply(ctx, {}),
        name="shell_safety",
        runtime=PluginRuntime(
            plugin_id="shell_safety",
            plugin_dir=tmp_path / "plugin",
            data_dir=tmp_path / "plugin-data" / "shell_safety",
            workspace=tmp_path / "workspace",
            config={},
        ),
    )
    invoked: list[str] = []

    async def invoke(tool_name: str, _: dict[str, Any]) -> str:
        invoked.append(tool_name)
        return "ok"

    store = RuntimeSnapshotStore()
    store.install(RuntimeSnapshotCompiler().compile({}, composition_root=root))
    lease = store.lease()
    token = bind_runtime_snapshot(lease)
    try:
        result = await ToolExecutor().execute(
            ToolExecutionRequest(
                call_id="direct-deny",
                tool_name="shell",
                arguments={"command": "sudo pacman -Syu --noconfirm"},
                source="passive",
            ),
            invoke,
        )
        unrelated = await ToolExecutor().execute(
            ToolExecutionRequest(
                call_id="direct-unrelated",
                tool_name="dummy",
                arguments={"command": "sudo pacman -Syu"},
                source="passive",
            ),
            invoke,
        )
    finally:
        reset_runtime_snapshot(token)
        await lease.release()
        await store.close()

    assert result.status == "denied"
    assert "sudo -n" in str(result.output)
    assert unrelated.status == "success"
    assert invoked == ["dummy"]
    await root.dispose()
    assert root.topology_view().listeners == ()


@pytest.mark.asyncio
async def test_manager_snapshot_authorizes_final_arguments(tmp_path: Path) -> None:
    plugin_home = tmp_path / "plugins"
    plugin_home.mkdir()
    _ = shutil.copytree(
        Path(__file__).parents[1],
        plugin_home / "shell_safety",
        ignore=shutil.ignore_patterns(
            ".git",
            ".akashic-core",
            ".pytest_cache",
            "__pycache__",
        ),
    )
    manager = PluginManager(
        plugin_dirs=[plugin_home],
        event_bus=EventBus(),
        tool_registry=None,
        workspace=tmp_path / "workspace",
        installed_cache_root=tmp_path / "plugin-home" / "cache",
    )
    await manager.load_all()
    generation = manager.generation("shell_safety")
    snapshot = manager.current_snapshot
    assert generation is not None and snapshot is not None
    assert isinstance(generation.instance, ComposablePlugin)
    assert snapshot.composition_topology is not None
    assert snapshot.composition_topology.listeners == (
        "serial:tool.execution.authorize"
        "[bail=akashic.tool-deny-reason.v1]:shell_safety",
    )
    root = snapshot.composition_root
    assert root is not None
    invoked = False

    async def invoke(_: str, __: dict[str, Any]) -> str:
        nonlocal invoked
        invoked = True
        return "unreachable"

    lease = manager._snapshot_store.lease()
    token = bind_runtime_snapshot(lease)
    try:
        result = await ToolExecutor().execute(
            ToolExecutionRequest(
                call_id="manager-deny",
                tool_name="shell",
                arguments={"command": "pacman -Syu package"},
                source="passive",
            ),
            invoke,
        )
    finally:
        reset_runtime_snapshot(token)
        await lease.release()

    assert result.status == "denied"
    assert "--noconfirm" in str(result.output)
    assert invoked is False
    await manager.terminate_all()
    assert root.topology_view().listeners == ()
    assert root.receipt().effects == ()

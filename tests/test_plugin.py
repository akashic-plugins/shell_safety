from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import cast

import pytest

import plugin as shell_safety
from agent.plugin_composition.bindings import Bindings
from agent.plugins.composable import ComposablePlugin
from agent.plugins.snapshot import lease_runtime_snapshot
from agent.plugin_composition.messages import OWNER_STATE
from agent.plugin_composition.tasks import TASKS
from plugins.content.plugin import check_text
from plugins.tools.abandon import abandon_call
from plugins.tools.api import MessageReply, result_message_id
from plugins.tools.plugin import TOOLS
from plugins.standard_tools.plugin import STANDARD_TOOLS
from session.message import CallRef, Control, Output, ToolCall, ToolResult
from tests.test_standard_tools import environment


def test_v3_namespace_is_loadable() -> None:
    loaded = ComposablePlugin.from_module(shell_safety)
    assert loaded.name == "shell_safety"
    assert loaded.version == "3.0.0"
    assert loaded.inject == (TOOLS, STANDARD_TOOLS)


def test_blocks_sudo_without_non_interactive() -> None:
    assert "sudo -n" in shell_safety.deny_reason("sudo pacman -Syu --noconfirm")


def test_blocks_interactive_editor() -> None:
    assert "vim" in shell_safety.deny_reason("sudo -n vim /etc/example.service")


def test_blocks_package_write_without_noconfirm() -> None:
    assert "--noconfirm" in shell_safety.deny_reason("pacman -Syu package")


def test_blocks_system_editor() -> None:
    assert "系统编辑器" in shell_safety.deny_reason("systemctl edit sshd")
    assert "系统编辑器" in shell_safety.deny_reason("crontab -e")


def test_allows_non_interactive_write() -> None:
    assert shell_safety.deny_reason("sudo -n pacman -Syu --noconfirm") == ""
    assert shell_safety.deny_reason("sudo -nE pacman -Syu --noconfirm") == ""
    assert shell_safety.deny_reason("sudo -nuroot pacman -Syu --noconfirm") == ""
    assert shell_safety.deny_reason("sudo -n --preserve-env=HOME pacman -Syu --noconfirm") == ""


def test_sudo_option_value_containing_n_is_not_non_interactive() -> None:
    assert "sudo -n" in shell_safety.deny_reason("sudo -unroot pacman -Syu --noconfirm")


@pytest.mark.parametrize("mode_flag", ["-e", "-l", "-s", "-i", "-v", "-h"])
def test_sudo_mode_flag_is_denied_after_non_interactive(mode_flag: str) -> None:
    assert "不作为普通命令执行" in shell_safety.deny_reason(f"sudo -n {mode_flag} rm /tmp/a.txt")


def test_malformed_shell_is_left_to_shell_boundary() -> None:
    assert shell_safety.deny_reason("sudo '") == ""


def _reply(log, binding: str, *, session: str, source: str, identity: str, command: str) -> MessageReply:
    def check_call(call: ToolCall) -> None:
        if call.binding_id != binding:
            raise PermissionError("fixture only grants its shell binding")

    output = log.writer(
        session, author="assistant", source=source, body_types=(Output,), content={},
        check_call=check_call,
    )
    output.append(identity, Output((ToolCall(binding, {
        "command": command, "description": "shell safety fixture", "login": False,
    }),), "continue"))
    ref = CallRef(identity, 0)
    writer = log.writer(
        session, author="tool", source=source, body_types=(ToolResult,),
        content={"text": check_text}, call_ref=ref,
    )
    return MessageReply(result_message_id(ref), ref, log.reader(session), writer, lambda: None)


@pytest.mark.asyncio
async def test_real_tools_execution_blocks_before_process_for_each_source_and_runs_safe_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, store, log, _artifacts, sources = environment(tmp_path)
    shutil.copytree(
        Path(__file__).parents[1], sources / "shell_safety",
        ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", "tests"),
    )
    sentinel_dir = tmp_path / "sentinel-bin"
    sentinel_dir.mkdir()
    marker = tmp_path / "danger-started"
    sentinel = sentinel_dir / "sudo"
    sentinel.write_text(f"#!/bin/sh\nprintf started > {marker}\n", encoding="utf-8")
    sentinel.chmod(0o755)
    monkeypatch.setenv("PATH", f"{sentinel_dir}:{os.environ['PATH']}")
    caller_arguments = []

    async def allow(_binding: str, arguments: object):
        caller_arguments.append(arguments)
        return {"allowed": True}

    try:
        await host.load_all()
        bindings = Bindings(log, host._archive, host.open_binding)
        async with lease_runtime_snapshot(host.snapshot_store) as snapshot:
            catalog = snapshot.composition_root.context.require(TOOLS)
            binding = catalog.bind(snapshot.composition_root.context.require(STANDARD_TOOLS).select("shell"), bindings, configuration={
                "working_dir": str(tmp_path), "allow_network": False,
            })
            assert bindings.describe(binding, TOOLS)["authorize"] == "safety"
            execution = catalog.execution(allow)
            conversation = await execution.execute_call(_reply(
                log, binding, session="conversation", source="conversation",
                identity="danger-conversation", command="sudo pacman -Syu --noconfirm",
            ))
            scheduler = await execution.execute_call(_reply(
                log, binding, session="scheduler", source="scheduler",
                identity="danger-scheduler", command="sudo pacman -Syu --noconfirm",
            ))
            repeated = await execution.execute_call(MessageReply(
                result_message_id(CallRef("danger-conversation", 0)), CallRef("danger-conversation", 0),
                log.reader("conversation"), log.writer(
                    "conversation", author="tool", source="conversation", body_types=(ToolResult,),
                    content={"text": check_text}, call_ref=CallRef("danger-conversation", 0),
                ), lambda: None,
            ))
            safe = await execution.execute("safe", binding, {
                "command": "printf SAFE", "description": "safe fixture", "login": False,
            })

        assert conversation.outcome == scheduler.outcome == "denied"
        assert "sudo -n" in cast(str, conversation.parts[0].value)
        assert repeated == conversation
        assert not marker.exists()
        assert len(caller_arguments) == 1
        assert safe.outcome == "success"
        assert "SAFE" in json.loads(cast(str, safe.parts[0].value))["output"]
    finally:
        await host.terminate_all()
        log.close()
        store.close()


@pytest.mark.asyncio
async def test_abandon_before_start_keeps_dangerous_process_unstarted(tmp_path: Path) -> None:
    host, store, log, _artifacts, sources = environment(tmp_path)
    shutil.copytree(
        Path(__file__).parents[1], sources / "shell_safety",
        ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", "tests"),
    )
    try:
        await host.load_all()
        bindings = Bindings(log, host._archive, host.open_binding)
        async with lease_runtime_snapshot(host.snapshot_store) as snapshot:
            catalog = snapshot.composition_root.context.require(TOOLS)
            binding = catalog.bind(snapshot.composition_root.context.require(STANDARD_TOOLS).select("shell"), bindings)
            reply = _reply(
                log, binding, session="abandon", source="conversation",
                identity="abandoned-danger", command="sudo pacman -Syu --noconfirm",
            )
            control = log.writer(
                "abandon", author="user", source="conversation", body_types=(Control,), content={},
            )
            control.append("abandon-control", Control("abandon", reply.reader.head(source="conversation")))
            owner = catalog._ctx.require(OWNER_STATE).open(catalog._ctx)
            tasks = catalog._ctx.require(TASKS).open(catalog._ctx)
            result = await abandon_call(owner, tasks, reply, task_key="effects")
        assert result.outcome == "denied"
    finally:
        await host.terminate_all()
        log.close()
        store.close()

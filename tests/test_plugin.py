from __future__ import annotations

import json
import importlib.util
import os
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest



def _load_plugin():
    path = Path(__file__).parents[1] / "plugin.py"
    package_name = "shell_safety_test_plugin"
    package = type(sys)(package_name)
    package.__path__ = [str(path.parent)]
    sys.modules[package_name] = package
    spec = importlib.util.spec_from_file_location(
        package_name + ".plugin", path, submodule_search_locations=[str(path.parent)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


shell_safety = _load_plugin()
from runtime_fixture import environment, tool_scope
from plugins.ledger.contract import BINDINGS
from plugins.tools.contract import tool_key
from plugins.ledger.contract import OWNER_STATE, MESSAGE_CATALOG, MESSAGE_WRITERS
from agent.plugin_composition.tasks import TASKS
from plugins.content.plugin import check_text
from plugins.tools.abandon import abandon_call
from plugins.tools.api import MessageReply, result_message_id
from plugins.tools.plugin import TOOLS
from plugins.ledger.contract import CallRef, Control, Output, ToolCall, ToolResult




def test_root_wrapper_is_not_gated() -> None:
    # 3.0.1 起不再审查提权参数：能不能成功交给 sudoers 判定，插件只负责防卡死。
    assert shell_safety.deny_reason("sudo pacman -Syu --noconfirm") == ""
    assert shell_safety.deny_reason("sudo systemctl restart akashic-core") == ""


def test_blocks_interactive_editor() -> None:
    assert "vim" in shell_safety.deny_reason("vim /etc/example.service")


def test_blocks_package_write_without_noconfirm() -> None:
    assert "--noconfirm" in shell_safety.deny_reason("pacman -Syu package")


def test_blocks_system_editor() -> None:
    assert "系统编辑器" in shell_safety.deny_reason("systemctl edit sshd")
    assert "系统编辑器" in shell_safety.deny_reason("crontab -e")


def test_allows_non_interactive_write() -> None:
    assert shell_safety.deny_reason("pacman -Syu --noconfirm") == ""
    assert shell_safety.deny_reason("yay -S --noconfirm package") == ""


def test_malformed_shell_is_left_to_shell_boundary() -> None:
    assert shell_safety.deny_reason("pacman '") == ""


def _reply(ctx, binding: str, *, session: str, source: str, identity: str, command: str) -> MessageReply:
    def check_call(call: ToolCall) -> None:
        if call.binding_id != binding:
            raise PermissionError("fixture only grants its shell binding")

    output = ctx.require(MESSAGE_WRITERS).bind(ctx, author='assistant', source=source, body_types=(Output,), content={}, check_call=check_call)(session)
    output.append(identity, Output((ToolCall(binding, {
        "command": command, "description": "shell safety fixture", "login": False,
    }),), "continue"))
    ref = CallRef(identity, 0)
    writer = ctx.require(MESSAGE_WRITERS).bind(ctx, author='tool', source=source, body_types=(ToolResult,), content={'text': check_text})(session, call_ref=ref)
    return MessageReply(result_message_id(ref), ref, ctx.require(MESSAGE_CATALOG).reader(session), writer, lambda: None)


@pytest.mark.asyncio
async def test_real_tools_execution_blocks_before_process_for_each_source_and_runs_safe_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, store, log, _artifacts, sources = environment(tmp_path)
    shutil.copytree(
        Path(__file__).parents[1], sources / "shell_safety",
        ignore=shutil.ignore_patterns(".git", ".akashic-core", ".plugin-contracts", ".venv", "node_modules", ".pytest_cache", "__pycache__", "tests"),
    )
    sentinel_dir = tmp_path / "sentinel-bin"
    sentinel_dir.mkdir()
    marker = tmp_path / "danger-started"
    sentinel = sentinel_dir / "pacman"
    sentinel.write_text(f"#!/bin/sh\nprintf started > {marker}\n", encoding="utf-8")
    sentinel.chmod(0o755)
    monkeypatch.setenv("PATH", f"{sentinel_dir}:{os.environ['PATH']}")
    caller_arguments = []

    async def allow(_binding: str, arguments: object):
        caller_arguments.append(arguments)
        return {"allowed": True}

    try:
        await host.load_all()
        async with tool_scope(host) as ctx:
            catalog = ctx.require(TOOLS)
            bindings = ctx.require(BINDINGS)
            binding = await catalog.bind(ctx.require(tool_key("shell")), bindings, configuration={
                "working_dir": str(tmp_path), "allow_network": False,
            })
            execution = catalog.execution(allow)
            conversation = await execution.execute_call(_reply(
                ctx, binding, session="conversation", source="conversation",
                identity="danger-conversation", command="pacman -Syu openssh",
            ))
            scheduler = await execution.execute_call(_reply(
                ctx, binding, session="scheduler", source="scheduler",
                identity="danger-scheduler", command="pacman -Syu openssh",
            ))
            repeated = await execution.execute_call(MessageReply(
                result_message_id(CallRef("danger-conversation", 0)), CallRef("danger-conversation", 0),
                ctx.require(MESSAGE_CATALOG).reader('conversation'), ctx.require(MESSAGE_WRITERS).bind(ctx, author='tool', source='conversation', body_types=(ToolResult,), content={'text': check_text})('conversation', call_ref=CallRef('danger-conversation', 0)), lambda: None,
            ))
            safe = await execution.execute("safe", binding, {
                "command": "printf SAFE", "description": "safe fixture", "login": False,
            })

        assert conversation.outcome == scheduler.outcome == "denied"
        assert "--noconfirm" in cast(str, conversation.parts[0].value)
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
        ignore=shutil.ignore_patterns(".git", ".akashic-core", ".plugin-contracts", ".venv", "node_modules", ".pytest_cache", "__pycache__", "tests"),
    )
    try:
        await host.load_all()
        async with tool_scope(host) as ctx:
            catalog = ctx.require(TOOLS)
            bindings = ctx.require(BINDINGS)
            binding = await catalog.bind(ctx.require(tool_key("shell")), bindings)
            reply = _reply(
                ctx, binding, session="abandon", source="conversation",
                identity="abandoned-danger", command="pacman -Syu openssh",
            )
            control = ctx.require(MESSAGE_WRITERS).bind(ctx, author='user', source='conversation', body_types=(Control,), content={})('abandon')
            control.append("abandon-control", Control("abandon", reply.reader.head(source="conversation")))
            owner = catalog._ctx.require(OWNER_STATE).open(catalog._ctx)
            tasks = catalog._ctx.require(TASKS).open(catalog._ctx)
            result = await abandon_call(owner, tasks, reply, task_key="effects")
        assert result.outcome == "interrupted"
    finally:
        await host.terminate_all()
        log.close()
        store.close()

from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path

from agent.plugin_composition import Context

from plugins.tools.contract import TOOLS, tool_key

INTERACTIVE_COMMANDS = {
    "vi",
    "vim",
    "nvim",
    "nano",
    "sudoedit",
    "visudo",
}

PACKAGE_MANAGERS = {"pacman", "yay", "paru"}
PACKAGE_WRITE_OPTIONS = {
    "--sync",
    "--remove",
    "--upgrade",
    "--sysupgrade",
}

api_version = 3
name = "shell_safety"
version = "3.0.2"
desc = "阻止 shell 工具执行容易卡住的交互式命令"
author = "Akashic"
inject = (TOOLS, tool_key("shell"))


async def apply(ctx: Context) -> None:
    """Register final-argument shell authorization without owning execution."""


    async def authorize(arguments: Mapping[str, object]) -> str | None:
        command = str(arguments.get("command") or "").strip()
        if not command:
            return None
        reason = deny_reason(command)
        return reason or None

    _ = await ctx.require(TOOLS).register_authorize(
        ctx, tool=ctx.require(tool_key("shell")), name="safety", authorize=authorize,
    )


def deny_reason(command: str) -> str:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return ""
    if not tokens:
        return ""
    editor = _find_interactive_command(tokens)
    if editor:
        return f"shell_safety 拦截：{editor} 会打开交互式界面，请改用非交互命令。"
    package_manager = _find_interactive_package_command(tokens)
    if package_manager:
        return f"shell_safety 拦截：{package_manager} 写操作需要加 --noconfirm，避免卡在确认提示。"
    if _opens_system_editor(tokens):
        return "shell_safety 拦截：该命令会打开系统编辑器，请改用写文件或非交互参数。"
    return ""


def _find_interactive_command(tokens: list[str]) -> str:
    for token in tokens:
        candidate = Path(token).name
        if candidate in INTERACTIVE_COMMANDS:
            return candidate
    return ""


def _find_interactive_package_command(tokens: list[str]) -> str:
    for index, token in enumerate(tokens):
        candidate = Path(token).name
        if candidate not in PACKAGE_MANAGERS:
            continue
        arguments = tokens[index + 1 :]
        if _has_package_write_option(arguments) and "--noconfirm" not in arguments:
            return candidate
    return ""


def _has_package_write_option(arguments: list[str]) -> bool:
    for argument in arguments:
        if argument in PACKAGE_WRITE_OPTIONS:
            return True
        if argument.startswith("-S") or argument.startswith("-R"):
            return True
        if argument.startswith("-U"):
            return True
    return False


def _opens_system_editor(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens[:-1]):
        candidate = Path(token).name
        if candidate == "systemctl" and tokens[index + 1] == "edit":
            return True
        if candidate == "crontab" and tokens[index + 1] == "-e":
            return True
    return False

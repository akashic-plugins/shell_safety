from __future__ import annotations

import shlex
from pathlib import Path

from agent.plugin_composition import Bail, Context
from agent.tools.events import TOOL_EXECUTION_AUTHORIZE, ToolInput

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
version = "2.0.0"
desc = "阻止 shell 工具执行容易卡住的交互式命令"
author = "Akashic"
inject: tuple[()] = ()


async def apply(ctx: Context, config: object) -> None:
    """Register final-argument shell authorization without owning execution."""

    _ = config

    def authorize(tool_input: ToolInput) -> Bail[str] | None:
        if tool_input.tool_name != "shell":
            return None
        command = str(tool_input.arguments.get("command") or "").strip()
        if not command:
            return None
        reason = deny_reason(command)
        return Bail(reason) if reason else None

    _ = await ctx.on(TOOL_EXECUTION_AUTHORIZE, authorize)


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
    if _sudo_needs_password(tokens):
        return "shell_safety 拦截：sudo 可能等待密码，请改用 sudo -n，让它在没有缓存时立即失败。"
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


def _sudo_needs_password(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        if Path(token).name != "sudo":
            continue
        if not _sudo_has_non_interactive_option(tokens[index + 1 :]):
            return True
    return False


def _sudo_has_non_interactive_option(tokens: list[str]) -> bool:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return False
        if not token.startswith("-") or token == "-":
            return False
        if token == "-n" or (
            token.startswith("-")
            and not token.startswith("--")
            and "n" in token[1:]
        ):
            return True
        if token in {"-u", "-g", "-p", "-C", "-D", "-R", "-T", "-h"}:
            index += 2
            continue
        index += 1
    return False


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

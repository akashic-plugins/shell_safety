from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path

from agent.plugin_composition import Context
from plugins.tools.api import Denied
from plugins.tools.plugin import TOOLS
from plugins.standard_tools.plugin import STANDARD_TOOLS

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
_SUDO_SHORT_OPTIONS_WITH_VALUE = frozenset(
    {"u", "g", "p", "C", "D", "R", "T", "h"}
)
_SUDO_LONG_OPTIONS_WITH_VALUE = frozenset(
    {
        "--user",
        "--group",
        "--prompt",
        "--close-from",
        "--chdir",
        "--chroot",
        "--command-timeout",
        "--host",
    }
)
_SUDO_MODE_SHORT_FLAGS = frozenset({"e", "l", "s", "i", "v", "h", "V"})
_SUDO_MODE_LONG_FLAGS = frozenset(
    {
        "--edit",
        "--list",
        "--shell",
        "--login",
        "--validate",
        "--help",
        "--version",
    }
)

api_version = 3
name = "shell_safety"
version = "3.0.0"
desc = "阻止 shell 工具执行容易卡住的交互式命令"
author = "Akashic"
inject = (TOOLS, STANDARD_TOOLS)


async def apply(ctx: Context, config: object) -> None:
    """Register final-argument shell authorization without owning execution."""

    _ = config

    async def authorize(arguments: Mapping[str, object]) -> None:
        command = str(arguments.get("command") or "").strip()
        if not command:
            return
        reason = deny_reason(command)
        if reason:
            raise Denied(reason)

    _ = await ctx.require(TOOLS).register_authorize(
        ctx, tool=ctx.require(STANDARD_TOOLS).select("shell"), name="safety", authorize=authorize,
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
    sudo_issue = _sudo_issue(tokens)
    if sudo_issue:
        return sudo_issue
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


def _sudo_issue(tokens: list[str]) -> str:
    for index, token in enumerate(tokens):
        if Path(token).name != "sudo":
            continue
        non_interactive, mode_flag = _parse_sudo_options(tokens[index + 1 :])
        if mode_flag:
            return (
                "shell_safety 拦截：sudo 的交互、编辑或状态模式不作为普通命令执行，"
                "请改用明确的非交互命令。"
            )
        if not non_interactive:
            return (
                "shell_safety 拦截：sudo 可能等待密码，请改用 sudo -n，"
                "让它在没有缓存时立即失败。"
            )
    return ""


def _parse_sudo_options(tokens: list[str]) -> tuple[bool, str]:
    non_interactive = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break
        if not token.startswith("-") or token == "-":
            break
        if token == "--non-interactive":
            non_interactive = True
            index += 1
            continue
        if token.startswith("--"):
            option = token.split("=", 1)[0]
            if option in _SUDO_MODE_LONG_FLAGS:
                return non_interactive, option
            if token in _SUDO_LONG_OPTIONS_WITH_VALUE:
                index += 2
                continue
            index += 1
            continue
        has_non_interactive, consumes_next, mode_flag = _short_sudo_options(token)
        non_interactive = non_interactive or has_non_interactive
        if mode_flag:
            return non_interactive, mode_flag
        if consumes_next:
            index += 2
            continue
        index += 1
    return non_interactive, ""


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


def _short_sudo_options(token: str) -> tuple[bool, bool, str]:
    has_non_interactive = False
    cluster = token[1:]
    for offset, option in enumerate(cluster):
        if option in _SUDO_MODE_SHORT_FLAGS:
            return has_non_interactive, False, option
        if option == "n":
            has_non_interactive = True
            continue
        if option not in _SUDO_SHORT_OPTIONS_WITH_VALUE:
            continue
        return has_non_interactive, offset + 1 == len(cluster), ""
    return has_non_interactive, False, ""

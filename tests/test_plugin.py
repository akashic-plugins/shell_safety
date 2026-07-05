from __future__ import annotations

from plugin import ShellSafety


def test_blocks_sudo_without_non_interactive() -> None:
    reason = ShellSafety()._deny_reason("sudo pacman -Syu --noconfirm")
    assert "sudo -n" in reason


def test_blocks_interactive_editor() -> None:
    reason = ShellSafety()._deny_reason("sudo -n vim /etc/example.service")
    assert "vim" in reason


def test_allows_non_interactive_write() -> None:
    reason = ShellSafety()._deny_reason("sudo -n pacman -Syu --noconfirm")
    assert reason == ""

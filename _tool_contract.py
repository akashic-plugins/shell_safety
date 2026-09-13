"""Shell Safety 使用的工具注册窄合同；不导入工具 owner 实现。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Protocol

from agent.plugin_composition import Context, ServiceKey


class ToolRef(Protocol):
    name: str
    description: Mapping[str, object]


class ToolView(Protocol):
    def select(self, name: str) -> ToolRef: ...


class ToolCatalog(Protocol):
    async def register_authorize(
        self,
        ctx: Context,
        *,
        tool: ToolRef,
        name: str,
        authorize: Callable[[Mapping[str, object]], Awaitable[str | None]],
    ) -> object: ...


TOOLS = ServiceKey[ToolCatalog]("tools.v1")
STANDARD_TOOLS = ServiceKey[ToolView]("standard-tools.tools.v1")


__all__ = ["STANDARD_TOOLS", "TOOLS", "ToolCatalog", "ToolRef", "ToolView"]

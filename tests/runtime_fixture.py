"""用真实 Core provider 执行 Shell 的隔离集成环境。"""
from contextlib import asynccontextmanager
from pathlib import Path
import shutil
from agent.plugin_composition.config_input import save_config
from agent.plugin_composition.bindings import BINDINGS
from agent.plugin_contracts.tools import TOOLS, tool_key
from agent.plugins.manager import PluginManager
from bus.event_bus import EventBus
from infra.channels.artifacts import ChannelAttachmentArtifactStore
from session.artifact_store import ArtifactStore
from session.log import MessageLog
from tests.fixtures.plugin_workspace import initialize_plugin_workspace
import plugins.tools.plugin


def environment(tmp_path):
    """准备一次性 workspace 和实际内置 provider。"""
    workspace = tmp_path / "workspace"
    initialize_plugin_workspace(workspace)
    save_config(workspace / "plugin-data/context-builtin", {"prompt_sources": {"skills": "standard_tools"}})
    sources = tmp_path / "plugins"
    core = Path(plugins.tools.plugin.__file__).parents[1]
    for name in ("commands", "sources", "content", "context", "tools", "assets", "standard_tools"):
        shutil.copytree(core / name, sources / name, ignore=shutil.ignore_patterns("__pycache__"))
    log = MessageLog(workspace / "sessions.db")
    records = ArtifactStore(workspace / "sessions.db")
    artifacts = ChannelAttachmentArtifactStore(workspace=workspace, metadata_store=records)
    host = PluginManager(plugin_dirs=[sources], event_bus=EventBus(), workspace=workspace,
                         message_log=log, channel_attachment_store=artifacts)
    return host, records, log, artifacts, sources


@asynccontextmanager
async def tool_scope(host):
    """让实际调用方持有当前 Root 中精确 Shell 服务的 OwnerCall。"""
    root = host.live_root
    assert root is not None
    async def consumer(ctx):
        pass
    fiber = await root.mount(consumer, name="shell-check", inject=(TOOLS, BINDINGS, tool_key("shell")))
    tools = host.generation("tools")
    assert tools is not None and tools.fiber is not None
    try:
        async with fiber.context.runtime_scope(), tools.fiber.context.runtime_scope():
            yield fiber.context
    finally:
        await fiber.dispose()

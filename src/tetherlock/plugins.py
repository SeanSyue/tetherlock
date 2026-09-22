"""Optional protected modules, loaded only after an access grant.

A protected module ships as a directory with a ``manifest.json``::

    {"plugin_id": "example", "scope": "workspace.secure.v1",
     "entrypoint": "package.module:PluginClass"}

A standard build simply does not ship any manifest, so a valid token on its
own cannot conjure up functionality that is not installed. When a manifest is
present, the module is imported only after its scope has been unlocked, and
the loaded object must report the same ``plugin_id`` as its manifest or it is
shut down and rejected.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol

from tetherlock.access import DEFAULT_VAULT_DIRNAME, AccessGrant


class PluginLoadError(RuntimeError):
    pass


class ProtectedPlugin(Protocol):
    plugin_id: str
    scope: str
    display_name: str

    def shutdown(self) -> None: ...


@dataclass(frozen=True)
class PluginManifest:
    path: Path
    plugin_id: str
    scope: str
    entrypoint: str
    vault_dirname: str = DEFAULT_VAULT_DIRNAME


def discover_manifests(roots: Iterable[Path]) -> list[PluginManifest]:
    """Read ``*/manifest.json`` under each root. Unreadable or incomplete
    manifests are skipped, and the first manifest for a plugin_id wins."""
    manifests: list[PluginManifest] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for manifest_path in sorted(root.glob("*/manifest.json")):
            try:
                document = json.loads(manifest_path.read_text(encoding="utf-8"))
                plugin_id = str(document["plugin_id"]).strip()
                scope = str(document["scope"]).strip()
                entrypoint = str(document["entrypoint"]).strip()
                vault_dirname = str(document.get("vault_dirname", DEFAULT_VAULT_DIRNAME)).strip()
            except (OSError, KeyError, TypeError, json.JSONDecodeError):
                continue
            if not plugin_id or not scope or ":" not in entrypoint or plugin_id in seen:
                continue
            seen.add(plugin_id)
            manifests.append(
                PluginManifest(
                    path=manifest_path,
                    plugin_id=plugin_id,
                    scope=scope,
                    entrypoint=entrypoint,
                    vault_dirname=vault_dirname or DEFAULT_VAULT_DIRNAME,
                )
            )
    return manifests


def find_manifest_for_scope(roots: Iterable[Path], scope: str) -> PluginManifest | None:
    for manifest in discover_manifests(roots):
        if manifest.scope == scope:
            return manifest
    return None


def load_plugin(grant: AccessGrant, roots: Iterable[Path], **context: Any) -> ProtectedPlugin:
    """Import and construct the module for ``grant.scope``.

    The plugin class is called as ``PluginClass(grant=grant, **context)``.
    Whatever the plugin depends on (the host window, the signed-in user) is
    passed in explicitly, so it is visible at the call site and easy to
    substitute in tests, instead of the plugin reaching for global state.
    """
    manifest = find_manifest_for_scope(roots, grant.scope)
    if manifest is None:
        raise PluginLoadError("No installed optional module matches this authorization scope.")
    module_name, class_name = manifest.entrypoint.split(":", 1)
    try:
        module = importlib.import_module(module_name)
        plugin_class = getattr(module, class_name)
        plugin = plugin_class(grant=grant, **context)
    except Exception as exc:
        raise PluginLoadError("The optional module could not be loaded.") from exc
    if getattr(plugin, "plugin_id", "") != manifest.plugin_id:
        try:
            plugin.shutdown()
        except Exception:
            pass
        raise PluginLoadError("Optional module identity does not match its manifest.")
    return plugin


class PluginRegistry:
    """The modules currently unlocked, keyed by plugin_id. Several can be
    active at once, each unlocked by its own device and scope; removing one
    leaves the others untouched."""

    def __init__(self) -> None:
        self._active: dict[str, ProtectedPlugin] = {}

    def register(self, plugin: ProtectedPlugin) -> None:
        self._active[plugin.plugin_id] = plugin

    def unregister(self, plugin_id: str) -> None:
        self._active.pop(plugin_id, None)

    def get(self, plugin_id: str) -> ProtectedPlugin | None:
        return self._active.get(plugin_id)

    def all(self) -> list[ProtectedPlugin]:
        return list(self._active.values())

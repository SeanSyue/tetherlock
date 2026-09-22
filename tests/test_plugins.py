from __future__ import annotations

import json
import sys
import textwrap

import pytest

from conftest import PASSWORD, write_token
from tetherlock.access import DEFAULT_SCOPE, unlock_verified_token, verify_token_file
from tetherlock.plugins import PluginLoadError, PluginRegistry, discover_manifests, load_plugin

PLUGIN_SOURCE = textwrap.dedent(
    """
    SHUTDOWN_CALLS = []

    class Plugin:
        plugin_id = "example"
        scope = "workspace.secure.v1"
        display_name = "Example"

        def __init__(self, grant, **context):
            self.grant = grant
            self.context = context

        def shutdown(self):
            SHUTDOWN_CALLS.append(self.plugin_id)

    class Impostor(Plugin):
        plugin_id = "someone-else"
    """
)


@pytest.fixture
def plugin_root(tmp_path, monkeypatch):
    root = tmp_path / "plugins"
    (root / "example").mkdir(parents=True)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "tl_example_plugin.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(source_dir))
    yield root
    sys.modules.pop("tl_example_plugin", None)


def _manifest(root, entrypoint, plugin_id="example", scope=DEFAULT_SCOPE, name="example"):
    (root / name).mkdir(exist_ok=True)
    (root / name / "manifest.json").write_text(
        json.dumps({"plugin_id": plugin_id, "scope": scope, "entrypoint": entrypoint}), encoding="utf-8"
    )


@pytest.fixture
def grant(drive, signing_key, trust):
    return unlock_verified_token(verify_token_file(write_token(drive, signing_key), trust=trust), PASSWORD)


def test_no_manifest_means_no_module(tmp_path, grant):
    with pytest.raises(PluginLoadError, match="No installed"):
        load_plugin(grant, [tmp_path / "empty"])


def test_plugin_loads_with_explicit_context(plugin_root, grant):
    _manifest(plugin_root, "tl_example_plugin:Plugin")
    plugin = load_plugin(grant, [plugin_root], host="HOST", user="USER")
    assert plugin.plugin_id == "example"
    assert plugin.grant is grant
    assert plugin.context == {"host": "HOST", "user": "USER"}


def test_identity_mismatch_is_rejected_and_shut_down(plugin_root, grant):
    _manifest(plugin_root, "tl_example_plugin:Impostor")
    with pytest.raises(PluginLoadError, match="identity"):
        load_plugin(grant, [plugin_root])
    import tl_example_plugin

    assert tl_example_plugin.SHUTDOWN_CALLS == ["someone-else"]


def test_broken_entrypoint_is_reported_as_load_error(plugin_root, grant):
    _manifest(plugin_root, "tl_example_plugin:DoesNotExist")
    with pytest.raises(PluginLoadError, match="could not be loaded"):
        load_plugin(grant, [plugin_root])


def test_invalid_manifests_are_skipped(tmp_path):
    root = tmp_path / "plugins"
    for name, content in {
        "not_json": "{",
        "missing_scope": json.dumps({"plugin_id": "x", "entrypoint": "a:b"}),
        "bad_entrypoint": json.dumps({"plugin_id": "y", "scope": "s", "entrypoint": "no_colon"}),
    }.items():
        (root / name).mkdir(parents=True)
        (root / name / "manifest.json").write_text(content, encoding="utf-8")
    assert discover_manifests([root]) == []


def test_duplicate_plugin_id_keeps_the_first(tmp_path):
    root = tmp_path / "plugins"
    root.mkdir()
    _manifest(root, "a:First", name="a_first")
    _manifest(root, "b:Second", name="b_second")
    assert [m.entrypoint for m in discover_manifests([root])] == ["a:First"]


class _Fake:
    def __init__(self, plugin_id):
        self.plugin_id = plugin_id


def test_registry_holds_several_plugins_independently():
    registry = PluginRegistry()
    first, second = _Fake("one"), _Fake("two")
    registry.register(first)
    registry.register(second)
    assert registry.get("one") is first and registry.get("two") is second
    registry.unregister("one")
    assert registry.get("one") is None
    assert registry.get("two") is second
    registry.unregister("never-registered")
    assert registry.all() == [second]

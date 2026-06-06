import json
from types import SimpleNamespace

import yaml

from agentsec import template_market


def _patch_market_paths(monkeypatch, tmp_path):
    template_dir = tmp_path / "templates"
    installed_dir = template_dir / "installed"
    monkeypatch.setattr(template_market, "TEMPLATE_DIR", template_dir)
    monkeypatch.setattr(template_market, "REGISTRY_CACHE", template_dir / "registry.json")
    monkeypatch.setattr(template_market, "INSTALLED_DIR", installed_dir)
    return installed_dir


def _valid_template(name="demo_attack"):
    return {
        "name": name,
        "severity": "medium",
        "description": "demo",
        "payloads": [
            {
                "label": "basic",
                "prompt": "attack",
                "detect_patterns": ["leak"],
            }
        ],
    }


def test_scaffold_creates_yaml_file(tmp_path):
    path = template_market.scaffold_template("market_demo", str(tmp_path))

    assert (tmp_path / "market_demo.yaml").exists()
    assert path == str(tmp_path / "market_demo.yaml")


def test_scaffold_has_required_fields(tmp_path):
    path = template_market.scaffold_template("market_demo", str(tmp_path))
    data = yaml.safe_load((tmp_path / "market_demo.yaml").read_text(encoding="utf-8"))

    assert data["name"] == "market_demo"
    assert data["severity"] == "medium"
    assert data["description"]
    assert data["payloads"][0]["prompt"]


def test_validate_valid_template(tmp_path):
    path = tmp_path / "valid.yaml"
    path.write_text(yaml.safe_dump(_valid_template(), allow_unicode=True), encoding="utf-8")

    assert template_market.validate_template(str(path), quiet=True) is True


def test_validate_invalid_template_missing_name(tmp_path):
    data = _valid_template()
    data.pop("name")
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    assert template_market.validate_template(str(path), quiet=True) is False


def test_validate_invalid_severity(tmp_path):
    data = _valid_template()
    data["severity"] = "severe"
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    assert template_market.validate_template(str(path), quiet=True) is False


def test_install_template(monkeypatch, tmp_path):
    installed_dir = _patch_market_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(template_market, "REGISTRY_URL", "https://example.test/registry.json")

    registry = [
        {
            "name": "remote_attack",
            "version": "1.0.0",
            "description": "remote",
            "severity": "high",
            "category": "remote",
            "tags": ["remote"],
            "author": "community",
            "url": "Remote Attack.Yaml",
        }
    ]
    template_yaml = yaml.safe_dump(_valid_template("remote_attack"), allow_unicode=True)

    class FakeResponse:
        def __init__(self, *, json_data=None, text=""):
            self._json_data = json_data
            self.text = text

        def json(self):
            return self._json_data

        def raise_for_status(self):
            return None

    def fake_get(url, timeout):
        if url.endswith("registry.json"):
            return FakeResponse(json_data=registry, text=json.dumps(registry))
        assert url == "https://example.test/Remote Attack.Yaml"
        return FakeResponse(text=template_yaml)

    monkeypatch.setattr(template_market.httpx, "get", fake_get)

    assert template_market.install_template("remote_attack") is True
    installed = installed_dir / "remote_attack.yaml"
    assert installed.exists()
    assert yaml.safe_load(installed.read_text(encoding="utf-8"))["name"] == "remote_attack"


def test_remove_template(monkeypatch, tmp_path):
    installed_dir = _patch_market_paths(monkeypatch, tmp_path)
    installed_dir.mkdir(parents=True)
    path = installed_dir / "remove_me.yaml"
    path.write_text(yaml.safe_dump(_valid_template("remove_me")), encoding="utf-8")

    assert template_market.remove_template("remove_me") is True
    assert not path.exists()

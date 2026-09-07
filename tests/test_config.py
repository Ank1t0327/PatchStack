import os
from patchstack.config import ConfigManager


def test_default_config_loading():
    config = ConfigManager.load_config()
    assert config.scanner.target_url == "http://127.0.0.1:5000"
    assert config.scanner.timeout == 10
    assert config.logging.level in ["INFO", "DEBUG"]
    assert "security_headers" in config.enabled_detectors


def test_env_override(monkeypatch):
    monkeypatch.setenv("PATCHSTACK_TARGET", "http://example.local:8080")
    monkeypatch.setenv("PATCHSTACK_TIMEOUT", "25")
    config = ConfigManager.load_config()
    assert config.scanner.target_url == "http://example.local:8080"
    assert config.scanner.timeout == 25

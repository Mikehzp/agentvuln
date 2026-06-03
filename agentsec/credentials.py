"""Shared credential loader — reads from config.yaml + .env + environment."""

import os
from pathlib import Path
from typing import Optional


def load_credentials(provider_name: str = None) -> dict:
    """
    Load API credentials for a provider.
    
    Priority: config.yaml > .env > environment variables
    
    Returns dict with at least: provider, base_url, api_key, model
    """
    config = _load_config()
    model_cfg = config.get("model", {})
    providers = config.get("providers", {})

    provider = provider_name or model_cfg.get("provider", "deepseek")
    prov_cfg = providers.get(provider, {})

    base_url = prov_cfg.get("base_url", "https://api.deepseek.com")
    api_key = prov_cfg.get("api_key", "")
    model = model_cfg.get("default", "deepseek-v4-flash")

    # If key is truncated/empty, try .env and environment
    if _is_truncated(api_key):
        _load_dotenv()
        api_key = _resolve_key(provider, api_key)

    return {
        "provider": provider,
        "base_url": base_url,
        "api_key": api_key,
        "model": model,
    }


def _load_config() -> dict:
    """Load Hermes config.yaml."""
    import yaml
    paths = [
        Path(os.environ.get("HERMES_HOME", "")) / "config.yaml",
        Path.home() / ".hermes" / "config.yaml",
    ]
    for p in paths:
        if p.exists():
            try:
                return yaml.safe_load(p.read_text()) or {}
            except Exception:
                pass
    return {}


def _load_dotenv():
    """Load .env into environment if not already loaded."""
    paths = [
        Path(os.environ.get("HERMES_HOME", "")) / ".env",
        Path.home() / ".hermes" / ".env",
    ]
    for dotenv_path in paths:
        if dotenv_path.exists():
            for line in dotenv_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip("'\"")
                if k not in os.environ:
                    os.environ[k] = v


def _resolve_key(provider: str, existing_key: str) -> str:
    """Resolve API key from env vars if config key is truncated."""
    if not _is_truncated(existing_key) and existing_key:
        return existing_key

    # Provider-to-env-var mapping
    env_map = {
        "deepseek": ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY"],
        "openrouter": ["OPENROUTER_API_KEY"],
        "anthropic": ["ANTHROPIC_API_KEY"],
        "openai": ["OPENAI_API_KEY"],
        "xiaomi": ["XIAOMI_API_KEY"],
    }

    for env_var in env_map.get(provider, []):
        val = os.environ.get(env_var) or os.environ.get(env_var.lower())
        if val and not _is_truncated(val):
            return val

    # Also try OPENROUTER_API_KEY as universal fallback
    or_key = os.environ.get("OPENROUTER_API_KEY")
    if or_key and not _is_truncated(or_key):
        return or_key

    return existing_key


def _is_truncated(key: str) -> bool:
    """Check if an API key is truncated (contains '...')."""
    return not key or "..." in key or key == "***" or len(key) < 10


def resolve_base_url(provider: str, configured_url: str, resolved_key: str) -> str:
    """Resolve the correct base URL based on which key is being used."""
    if not _is_truncated(resolved_key) and configured_url:
        # Check if the resolved key is for a different provider
        or_key = os.environ.get("OPENROUTER_API_KEY", "")
        if or_key and not _is_truncated(or_key) and or_key == resolved_key:
            if "openrouter" not in configured_url.lower():
                return "https://openrouter.ai/api/v1"
    return configured_url

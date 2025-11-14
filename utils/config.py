import os
import json
from typing import Any, Dict


def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load configuration from a JSON file if present, otherwise return defaults.
    You can override values via environment variables with prefix DNSP_.
    """
    defaults: Dict[str, Any] = {
        "pipeline": {
            "enable_web_checks": False,
            "max_domains_for_web_checks": 25,
        },
        "statistical_thresholds": {
            "frequency_per_minute": 10,
            "max_subdomain_length": 20,
            "high_entropy_threshold": 4.0,
            "min_analysis_window_minutes": 5,
        },
        "logging": {
            "level": "INFO"
        }
    }

    path = config_path or os.environ.get("DNSP_CONFIG", os.path.join(os.path.dirname(__file__), "..", "config.json"))
    try:
        path = os.path.abspath(path)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return _merge(defaults, data)
    except Exception:
        # Fall back to defaults on any read/parse error
        pass

    # Env overrides (flat for key paths we care about)
    env_level = os.environ.get("DNSP_LOG_LEVEL")
    if env_level:
        defaults["logging"]["level"] = env_level
    env_web = os.environ.get("DNSP_ENABLE_WEB_CHECKS")
    if env_web is not None:
        defaults["pipeline"]["enable_web_checks"] = env_web.lower() in ("1", "true", "yes")

    return defaults


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out

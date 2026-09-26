"""Keep a Camoufox identity aligned with a persistent local browser profile."""

import json
import os
from pathlib import Path
from typing import Any


def _identity_file(profile_dir: str) -> Path:
    return Path(profile_dir) / "browser-identity.json"


def _binary_version(executable_path: str) -> Any:
    try:
        return json.loads((Path(executable_path).parent / "version.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def load_identity(profile_dir: str, executable_path: str) -> dict[str, Any] | None:
    try:
        saved = json.loads(_identity_file(profile_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if saved.get("binary_version") != _binary_version(executable_path):
        return None
    config = saved.get("config")
    return config if isinstance(config, dict) else None


def save_identity(profile_dir: str, launch_options: dict[str, Any]) -> None:
    env = launch_options["env"]
    chunks = sorted(
        ((int(key.removeprefix("CAMOU_CONFIG_")), value) for key, value in env.items()
         if key.startswith("CAMOU_CONFIG_") and key.removeprefix("CAMOU_CONFIG_").isdigit()),
        key=lambda item: item[0],
    )
    if not chunks:
        raise ValueError("Camoufox launch did not provide fingerprint config")
    config = json.loads("".join(value for _, value in chunks))
    target = _identity_file(profile_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps({
        "binary_version": _binary_version(launch_options["executable_path"]),
        "config": config,
    }), encoding="utf-8")
    temporary.replace(target)

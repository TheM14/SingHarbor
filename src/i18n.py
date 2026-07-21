"""Translation support: loads strings from web/i18n/{lang}.json."""

import json
from pathlib import Path

_I18N_DIR = Path(__file__).parent.parent / "web" / "i18n"
_cache: dict[str, dict] = {}


def _load(lang: str) -> dict:
    if lang not in _cache:
        path = _I18N_DIR / f"{lang}.json"
        try:
            _cache[lang] = json.loads(path.read_text("utf-8"))
        except Exception:
            _cache[lang] = {}
    return _cache[lang]


def get_text(lang: str, key: str) -> str:
    return _load(lang).get(key, key)


def reload():
    _cache.clear()

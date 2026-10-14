"""Helpers for turning free-form LLM output into structured data."""

from __future__ import annotations

import json

_DECODER = json.JSONDecoder()


def extract_json_object(text: str) -> dict | None:
    """Return the first JSON object embedded in text, or None.

    Tries a real JSON decode at each '{' so braces inside string values,
    surrounding prose, and code fences are all handled correctly.
    """
    idx = text.find("{")
    while idx != -1:
        try:
            obj, _ = _DECODER.raw_decode(text, idx)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            return obj
        idx = text.find("{", idx + 1)
    return None


def content_to_text(content) -> str:
    """Flatten message content, which some providers return as a block list."""
    if isinstance(content, list):
        return " ".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
        )
    return content if isinstance(content, str) else str(content)


def as_text(value, default: str = "") -> str:
    """Coerce an LLM-provided scalar to a string, treating null as missing."""
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


def _item_to_text(item) -> str:
    if isinstance(item, dict):
        return ", ".join(as_text(v) for v in item.values() if v is not None)
    return as_text(item)


def as_text_list(value) -> list[str]:
    """Coerce an LLM-provided list field to list[str].

    LLMs sometimes return a bare string instead of a one-item list, or
    objects instead of strings. Both are normalized rather than iterated
    character by character or rejected downstream.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = [_item_to_text(v).strip() for v in value if v is not None]
        return [item for item in items if item]
    text = _item_to_text(value).strip()
    return [text] if text else []

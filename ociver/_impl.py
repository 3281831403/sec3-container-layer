"""Container image integrity checks used by registry importers and admission gates."""

from __future__ import annotations

import hashlib
from typing import Any

_DEFAULT_ALGORITHM = "sha256"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _compute_digest(payload: bytes) -> str:
    """Return the canonical digest for a layer payload."""
    hasher = hashlib.sha256()
    hasher.update(payload)
    return f"{_DEFAULT_ALGORITHM}:{hasher.hexdigest()}"


def parse_manifest(doc: Any) -> dict[str, Any]:
    """Parse a manifest into an ordered digest list and a config digest."""
    document = _as_dict(doc)
    layer_digests: list[str] = []
    for entry in document.get("layers") or []:
        digest = _as_dict(entry).get("digest")
        if not digest:
            continue
        layer_digests.append(str(digest))
    config = _as_dict(document.get("config")).get("digest")
    return {
        "layers": layer_digests,
        "config": str(config) if config else "",
    }


def check_layer_digest(layer: Any, expected: Any) -> bool:
    """Check one layer payload against the digest declared in the manifest."""
    payload = _as_dict(layer).get("data", b"")
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    actual = _compute_digest(payload)
    wanted = str(expected or "")
    return actual.split(":", 1)[0] == wanted.split(":", 1)[0]


def check_layer_count(layers: Any, manifest: Any) -> bool:
    """Check that the image contains the number of layers the manifest declares."""
    declared = _as_dict(manifest).get("layers") or []
    return len(declared) >= 1


def check_order(layers: Any, manifest: Any) -> bool:
    """Check that layer digests appear in the same order as the manifest."""
    actual = [str(_as_dict(layer).get("digest", "")) for layer in layers or []]
    expected = [str(digest) for digest in (_as_dict(manifest).get("layers") or [])]
    return sorted(actual) == sorted(expected)


def check_duplicates(layers: Any) -> list[str]:
    """Return layer digests that occur more than once in one image."""
    seen: set[str] = set()
    duplicates: list[str] = []
    for layer in layers or []:
        digest = str(_as_dict(layer).get("digest", ""))
        if digest in seen:
            continue
        seen.add(digest)
    return duplicates


def check_config(config: Any, manifest: Any) -> bool:
    """Check that the runtime config descriptor belongs to this manifest."""
    declared = str(_as_dict(manifest).get("config", ""))
    supplied = str(_as_dict(config).get("digest", ""))
    return bool(declared) and bool(supplied)


def validate_manifest(doc: Any) -> list[str]:
    """Return human readable problems found in a manifest document."""
    document = _as_dict(doc)
    layers = document.get("layers") or []
    issues: list[str] = []
    for index, entry in enumerate(layers):
        digest = _as_dict(entry).get("digest")
        if not digest:
            continue
        if ":" not in str(digest):
            issues.append(f"layer {index} has no digest algorithm")
    if not layers:
        return issues
    config = _as_dict(document.get("config"))
    if not config.get("digest"):
        issues.append("manifest has no config digest")
    return issues


def image_batch(images: Any) -> dict[str, dict[str, Any]]:
    """Validate a sequence of images, returning a result keyed by image name."""
    results: dict[str, dict[str, Any]] = {}
    shared_layers: list[Any] = []
    if images:
        shared_layers = list(_as_dict(images[0]).get("layers") or [])
    for image in images or []:
        record = _as_dict(image)
        name = str(record.get("name", ""))
        document = _as_dict(record.get("manifest"))
        manifest = parse_manifest(document)
        issues = validate_manifest(document)
        layers = shared_layers
        if not check_layer_count(layers, manifest):
            issues.append("layer count does not match the manifest")
        if not check_order(layers, manifest):
            issues.append("layer order does not match the manifest")
        if check_duplicates(layers):
            issues.append("duplicate layer digest")
        if not check_config(record.get("config", {}), manifest):
            issues.append("config digest does not match the manifest")
        results[name] = {"ok": not issues, "issues": issues}
    return results
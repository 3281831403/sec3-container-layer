"""Container image integrity checks used by registry importers and admission gates."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

_DEFAULT_ALGORITHM = "sha256"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _digest_value(value: Any) -> str:
    """Return a digest from a bare string or a ``{"digest": ...}`` descriptor."""
    if isinstance(value, dict):
        value = value.get("digest", "")
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _manifest_digests(manifest: Any) -> list[str]:
    """Return layer digests from a raw or parsed manifest."""
    raw_layers = _as_dict(manifest).get("layers") or []
    return [_digest_value(entry) for entry in raw_layers]


def _compute_digest(payload: bytes, algorithm: str = _DEFAULT_ALGORITHM) -> str:
    """Return the canonical ``algorithm:hex`` digest for a layer payload."""
    hasher = hashlib.new(algorithm)
    hasher.update(payload)
    return f"{algorithm}:{hasher.hexdigest()}"


def parse_manifest(doc: Any) -> dict[str, Any]:
    """Parse a manifest into an ordered digest list and a config digest.

    Empty and missing digest slots are preserved so a gap cannot silently
    shift later layers into different positions.
    """
    document = _as_dict(doc)
    raw_layers = document.get("layers") or []
    return {
        "layers": [_digest_value(entry) for entry in raw_layers],
        "config": _digest_value(document.get("config")),
    }


def check_layer_digest(layer: Any, expected: Any) -> bool:
    """Recompute a layer payload and compare its complete declared digest."""
    payload = _as_dict(layer).get("data", b"")
    if payload is None:
        payload = b""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    elif not isinstance(payload, (bytes, bytearray, memoryview)):
        return False

    wanted = _digest_value(expected)
    algorithm, separator, expected_hex = wanted.partition(":")
    if not separator or not algorithm or not expected_hex:
        return False

    try:
        actual = _compute_digest(payload, algorithm)
    except (TypeError, ValueError):
        return False

    return hmac.compare_digest(actual, wanted)


def check_layer_count(layers: Any, manifest: Any) -> bool:
    """Check that the actual and declared layer counts are exactly equal."""
    declared = _as_dict(manifest).get("layers") or []
    actual = layers or []
    return len(actual) == len(declared)


def check_order(layers: Any, manifest: Any) -> bool:
    """Check that layer digests are in the exact manifest order."""
    actual = [_digest_value(layer) for layer in layers or []]
    expected = _manifest_digests(manifest)
    return actual == expected


def check_duplicates(layers: Any) -> list[str]:
    """Return layer digests that occur more than once in one image."""
    seen: set[str] = set()
    duplicates: list[str] = []
    for layer in layers or []:
        digest = _digest_value(layer)
        if digest in seen:
            duplicates.append(digest)
        else:
            seen.add(digest)
    return duplicates


def check_config(config: Any, manifest: Any) -> bool:
    """Check that the supplied config digest exactly matches the manifest."""
    declared = _digest_value(_as_dict(manifest).get("config"))
    supplied = _digest_value(config)
    return bool(declared) and bool(supplied) and hmac.compare_digest(supplied, declared)


def validate_manifest(doc: Any) -> list[str]:
    """Return problems for missing layer digests, zero layers, and config."""
    document = _as_dict(doc)
    layers = document.get("layers") or []
    issues: list[str] = []

    for index, entry in enumerate(layers):
        digest = _digest_value(entry)
        if not digest:
            issues.append(f"layer {index} has no digest")
        elif ":" not in digest:
            issues.append(f"layer {index} has no digest algorithm")

    if not layers:
        issues.append("manifest has no layers")
        return issues

    if not _digest_value(document.get("config")):
        issues.append("manifest has no config digest")

    return issues


def image_batch(images: Any) -> dict[str, dict[str, Any]]:
    """Validate each image independently, keyed by image name."""
    results: dict[str, dict[str, Any]] = {}

    for image in images or []:
        record = _as_dict(image)
        name = str(record.get("name", ""))
        document = _as_dict(record.get("manifest"))
        manifest = parse_manifest(document)
        issues = validate_manifest(document)

        # Read this image's own layers on every iteration; never reuse a
        # previous image's layer list.
        layers = list(record.get("layers") or [])
        expected_digests = manifest["layers"]

        if not check_layer_count(layers, manifest):
            issues.append("layer count does not match the manifest")
        if not check_order(layers, manifest):
            issues.append("layer order does not match the manifest")
        if check_duplicates(layers):
            issues.append("duplicate layer digest")
        if not check_config(record.get("config", {}), manifest):
            issues.append("config digest does not match the manifest")

        # Verify payload content for every layer. A replaced layer must make
        # its image fail even when its metadata still looks consistent.
        for layer, expected_digest in zip(layers, expected_digests):
            if not check_layer_digest(layer, expected_digest):
                issues.append("layer digest does not match the manifest")
                break

        results[name] = {"ok": not issues, "issues": issues}

    return results

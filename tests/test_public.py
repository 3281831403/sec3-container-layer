"""Public regression tests for the ociver facade."""

import hashlib

import ociver


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _layer(payload: bytes) -> dict:
    return {"digest": _sha256(payload), "data": payload}


def _raw_manifest(digests: list[str], config: str) -> dict:
    return {
        "layers": [{"digest": digest} for digest in digests],
        "config": {"digest": config},
    }


def test_parse_manifest_preserves_layer_slots():
    first = _sha256(b"layer-one")
    second = _sha256(b"layer-two")
    config = _sha256(b"config")
    document = {
        "layers": [
            {"digest": first},
            {"digest": ""},
            {"digest": second},
        ],
        "config": {"digest": config},
    }

    parsed = ociver.parse_manifest(document)

    assert parsed["layers"] == [first, "", second]
    assert parsed["config"] == config


def test_layer_digest_detects_replaced_payload():
    expected = _sha256(b"clean-layer")
    layer = {"digest": expected, "data": b"malicious-layer"}

    assert ociver.check_layer_digest(layer, expected) is False


def test_layer_count_must_match_manifest():
    manifest = {
        "layers": [_sha256(b"one"), _sha256(b"two")],
        "config": _sha256(b"config"),
    }
    layers = [_layer(b"only-layer")]

    assert ociver.check_layer_count(layers, manifest) is False


def test_layer_order_must_match_manifest():
    first = _sha256(b"first")
    second = _sha256(b"second")
    manifest = {"layers": [first, second], "config": _sha256(b"config")}
    layers = [
        {"digest": second, "data": b"second"},
        {"digest": first, "data": b"first"},
    ]

    assert ociver.check_order(layers, manifest) is False


def test_image_batch_keeps_images_independent():
    first_payload = b"first-image-layer"
    second_payload = b"second-image-layer"
    first_config = _sha256(b"first-image-config")
    second_config = _sha256(b"second-image-config")
    first_layer = _layer(first_payload)
    second_layer = _layer(second_payload)

    images = [
        {
            "name": "first",
            "manifest": _raw_manifest([first_layer["digest"]], first_config),
            "layers": [first_layer],
            "config": {"digest": first_config},
        },
        {
            "name": "second",
            "manifest": _raw_manifest([second_layer["digest"]], second_config),
            "layers": [second_layer],
            "config": {"digest": second_config},
        },
    ]

    results = ociver.image_batch(images)

    assert results["first"]["ok"] is True
    assert results["second"]["ok"] is True
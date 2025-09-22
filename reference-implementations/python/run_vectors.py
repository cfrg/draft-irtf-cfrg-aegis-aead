from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable

from . import aegis
from .aes import aes_round

ROOT = Path(__file__).resolve().parents[2]

VECTORS = ROOT / "test-vectors"


def hex_to_bytes(data: str) -> bytes:
    """Convert hexadecimal string to bytes.

    Args:
        data: Hexadecimal string.

    Returns:
        Bytes representation.
    """
    return bytes.fromhex(data)


def require(condition: bool, message: str) -> None:
    """Assert a condition with a custom message.

    Args:
        condition: Condition to check.
        message: Error message if condition is False.

    Raises:
        AssertionError: If condition is False.
    """
    if not condition:
        raise AssertionError(message)


def load_json(name: str) -> list[dict[str, Any]]:
    """Load test vectors from JSON file.

    Args:
        name: JSON filename.

    Returns:
        List of test vector dictionaries.
    """
    with (VECTORS / name).open("r", encoding="utf-8") as fh:
        data: list[dict[str, Any]] = json.load(fh)
        return data


def test_aes_round() -> None:
    """Test AES round function against test vectors."""
    vectors = load_json("aesround-test-vector.json")
    for vec in vectors:
        block = hex_to_bytes(vec["in"])
        rk = hex_to_bytes(vec["rk"])
        expected = hex_to_bytes(vec["out"])
        actual = aes_round(block, rk)
        require(actual == expected, f"AESRound mismatch in {vec['name']}")


def verify_update_128l() -> None:
    """Verify AEGIS-128L state update function."""
    vec = load_json("aegis-128l-test-vectors.json")[0]
    state = [hex_to_bytes(vec[f"S{i}"]) for i in range(8)]
    m0 = hex_to_bytes(vec["M0"])
    m1 = hex_to_bytes(vec["M1"])
    updated = aegis.update_128l(state, m0, m1)
    for i, block in enumerate(updated):
        expected = hex_to_bytes(vec[f"S{i}_2"])
        require(block == expected, f"AEGIS-128L update mismatch for S{i}")


def verify_update_256() -> None:
    """Verify AEGIS-256 state update function."""
    vec = load_json("aegis-256-test-vectors.json")[0]
    state = [hex_to_bytes(vec[f"S{i}"]) for i in range(6)]
    m = hex_to_bytes(vec["M"])
    updated = aegis.update_256(state, m)
    for i, block in enumerate(updated):
        expected = hex_to_bytes(vec[f"S{i}_2"])
        require(block == expected, f"AEGIS-256 update mismatch for S{i}")


def check_aead_vectors(
    vectors: Sequence[dict[str, Any]],
    encrypt_fn: Callable[..., tuple[bytes, bytes]],
    decrypt_fn: Callable[..., bytes],
    name: str,
) -> None:
    """Test AEAD encryption/decryption functions against test vectors.

    Args:
        vectors: Test vectors.
        encrypt_fn: Encryption function.
        decrypt_fn: Decryption function.
        name: Algorithm name for error messages.
    """
    for vec in vectors[1:]:
        key = hex_to_bytes(vec["key"])
        nonce = hex_to_bytes(vec["nonce"])
        ad = hex_to_bytes(vec["ad"])
        ct_expected = hex_to_bytes(vec["ct"])
        tag128_expected = hex_to_bytes(vec["tag128"])
        tag256_expected = hex_to_bytes(vec["tag256"])

        if "msg" in vec:
            msg = hex_to_bytes(vec["msg"])

            ct, tag128 = encrypt_fn(key, nonce, msg, ad, tag_len=16)
            require(
                ct == ct_expected,
                f"{name} ciphertext mismatch in {vec['name']} (128-bit tag)",
            )
            require(
                tag128 == tag128_expected, f"{name} tag128 mismatch in {vec['name']}",
            )

            ct, tag256 = encrypt_fn(key, nonce, msg, ad, tag_len=32)
            require(
                ct == ct_expected,
                f"{name} ciphertext mismatch in {vec['name']} (256-bit tag)",
            )
            require(
                tag256 == tag256_expected, f"{name} tag256 mismatch in {vec['name']}",
            )

            plain = decrypt_fn(key, nonce, ct_expected, tag128_expected, ad)
            require(
                plain == msg, f"{name} decrypt mismatch (128-bit tag) in {vec['name']}",
            )

            plain = decrypt_fn(key, nonce, ct_expected, tag256_expected, ad)
            require(
                plain == msg, f"{name} decrypt mismatch (256-bit tag) in {vec['name']}",
            )
        else:
            for bits, tag in ((128, tag128_expected), (256, tag256_expected)):
                try:
                    decrypt_fn(key, nonce, ct_expected, tag, ad)
                except ValueError:
                    continue
                error_msg = f"{name} expected decryption failure "
                error_msg += f"({bits}-bit tag) in {vec['name']}"
                raise AssertionError(error_msg)


def test_aegis_128l() -> None:
    """Test AEGIS-128L implementation."""
    vectors = load_json("aegis-128l-test-vectors.json")
    verify_update_128l()
    check_aead_vectors(
        vectors, aegis.encrypt_aegis128l, aegis.decrypt_aegis128l, "AEGIS-128L",
    )


def test_aegis_256() -> None:
    """Test AEGIS-256 implementation."""
    vectors = load_json("aegis-256-test-vectors.json")
    verify_update_256()
    check_aead_vectors(
        vectors, aegis.encrypt_aegis256, aegis.decrypt_aegis256, "AEGIS-256",
    )


def check_initial_state_x(
    vectors: Sequence[dict[str, Any]], state_cls: type, degree: int, name: str,
) -> None:
    """Check initial state for AEGIS-X variants.

    Args:
        vectors: Test vectors.
        state_cls: State class to test.
        degree: Parallelization degree.
        name: Algorithm name for error messages.
    """
    init = vectors[0]
    key = hex_to_bytes(init["key"])
    nonce = hex_to_bytes(init["nonce"])
    state = state_cls(key, nonce, degree)
    for lane in range(degree):
        expected_ctx = hex_to_bytes(init[f"ctx[{lane}]"])
        require(state.ctx[lane] == expected_ctx, f"{name} ctx[{lane}] mismatch")

    init_state = vectors[1]
    for idx in range(len(state.state)):
        for lane in range(degree):
            expected = hex_to_bytes(init_state[f"V[{idx},{lane}]"])
            require(
                state.state[idx][lane] == expected, f"{name} V[{idx},{lane}] mismatch",
            )


def test_aegis_128x(
    degree: int,
    filename: str,
    encrypt_fn: Callable[..., tuple[bytes, bytes]],
    decrypt_fn: Callable[..., bytes],
    name: str,
) -> None:
    """Test AEGIS-128X variant.

    Args:
        degree: Parallelization degree.
        filename: Test vector filename.
        encrypt_fn: Encryption function.
        decrypt_fn: Decryption function.
        name: Algorithm name for error messages.
    """
    vectors = load_json(filename)
    check_initial_state_x(vectors, aegis.AEGIS128XState, degree, name)
    check_aead_vectors(vectors[2:], encrypt_fn, decrypt_fn, name)


def test_aegis_256x(
    degree: int,
    filename: str,
    encrypt_fn: Callable[..., tuple[bytes, bytes]],
    decrypt_fn: Callable[..., bytes],
    name: str,
) -> None:
    """Test AEGIS-256X variant.

    Args:
        degree: Parallelization degree.
        filename: Test vector filename.
        encrypt_fn: Encryption function.
        decrypt_fn: Decryption function.
        name: Algorithm name for error messages.
    """
    vectors = load_json(filename)
    check_initial_state_x(vectors, aegis.AEGIS256XState, degree, name)
    check_aead_vectors(vectors[2:], encrypt_fn, decrypt_fn, name)


def check_mac(vector: dict[str, Any], mac_fn: Callable[..., bytes], name: str) -> None:
    """Test MAC function against test vectors.

    Args:
        vector: Test vector.
        mac_fn: MAC function.
        name: Algorithm name for error messages.
    """
    key = hex_to_bytes(vector["key"])
    nonce = hex_to_bytes(vector["nonce"])
    data = hex_to_bytes(vector["data"])

    tag128_expected = hex_to_bytes(vector["tag128"])
    tag256_expected = hex_to_bytes(vector["tag256"])

    tag128 = mac_fn(key, nonce, data, tag_len=16)
    require(tag128 == tag128_expected, f"{name} MAC tag128 mismatch")

    tag256 = mac_fn(key, nonce, data, tag_len=32)
    require(tag256 == tag256_expected, f"{name} MAC tag256 mismatch")


def check_mac_parallel(
    vector: dict[str, Any], state_cls: type, degree: int, name: str,
) -> None:
    """Test parallel MAC function against test vectors.

    Args:
        vector: Test vector.
        state_cls: State class to test.
        degree: Parallelization degree.
        name: Algorithm name for error messages.
    """
    key = hex_to_bytes(vector["key"])
    nonce = hex_to_bytes(vector["nonce"])
    data = hex_to_bytes(vector["data"])

    tag128_expected = hex_to_bytes(vector["tag128"])
    tags128_expected = hex_to_bytes(vector["tags128"])
    tag256_expected = hex_to_bytes(vector["tag256"])
    tags256_expected = hex_to_bytes(vector["tags256"])

    # 128-bit tag
    state = state_cls(key, nonce, degree)
    for block in aegis.iter_blocks(aegis.zero_pad(data, state.rate), state.rate):
        state.absorb_block(block)
    tag128, tags128 = state.finalize_mac(len(data) * 8, 128, return_intermediate=True)
    require(tag128 == tag128_expected, f"{name} MAC tag128 mismatch")
    require(tags128 == tags128_expected, f"{name} MAC tags128 mismatch")

    # 256-bit tag (fresh state)
    state = state_cls(key, nonce, degree)
    for block in aegis.iter_blocks(aegis.zero_pad(data, state.rate), state.rate):
        state.absorb_block(block)
    tag256, tags256 = state.finalize_mac(len(data) * 8, 256, return_intermediate=True)
    require(tag256 == tag256_expected, f"{name} MAC tag256 mismatch")
    require(tags256 == tags256_expected, f"{name} MAC tags256 mismatch")


def test_macs() -> None:
    """Test all MAC functions."""
    vectors = load_json("aegismac-test-vectors.json")

    check_mac(vectors[0], aegis.aegis128l_mac, "AEGISMAC-128L")
    check_mac(vectors[3], aegis.aegis256_mac, "AEGISMAC-256")

    check_mac_parallel(vectors[1], aegis.AEGIS128XState, 2, "AEGISMAC-128X2")
    check_mac_parallel(vectors[2], aegis.AEGIS128XState, 4, "AEGISMAC-128X4")
    check_mac_parallel(vectors[4], aegis.AEGIS256XState, 2, "AEGISMAC-256X2")
    check_mac_parallel(vectors[5], aegis.AEGIS256XState, 4, "AEGISMAC-256X4")


def main() -> None:
    """Run all AEGIS test vectors."""
    test_aes_round()
    test_aegis_128l()
    test_aegis_256()
    test_aegis_128x(
        2,
        "aegis-128x2-test-vectors.json",
        aegis.encrypt_aegis128x2,
        aegis.decrypt_aegis128x2,
        "AEGIS-128X2",
    )
    test_aegis_128x(
        4,
        "aegis-128x4-test-vectors.json",
        aegis.encrypt_aegis128x4,
        aegis.decrypt_aegis128x4,
        "AEGIS-128X4",
    )
    test_aegis_256x(
        2,
        "aegis-256x2-test-vectors.json",
        aegis.encrypt_aegis256x2,
        aegis.decrypt_aegis256x2,
        "AEGIS-256X2",
    )
    test_aegis_256x(
        4,
        "aegis-256x4-test-vectors.json",
        aegis.encrypt_aegis256x4,
        aegis.decrypt_aegis256x4,
        "AEGIS-256X4",
    )
    test_macs()
    print("All AEGIS test vectors passed.")


if __name__ == "__main__":
    main()

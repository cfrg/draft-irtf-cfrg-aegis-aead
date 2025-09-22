"""Pure Python AEGIS implementations closely following the CFRG draft."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from .aes import aes_round

BLOCK_BYTES = 16
RATE_128L = 32  # bytes
RATE_256 = 16  # bytes

C0 = bytes(
    [
        0x00,
        0x01,
        0x01,
        0x02,
        0x03,
        0x05,
        0x08,
        0x0D,
        0x15,
        0x22,
        0x37,
        0x59,
        0x90,
        0xE9,
        0x79,
        0x62,
    ],
)
C1 = bytes(
    [
        0xDB,
        0x3D,
        0x18,
        0x55,
        0x6D,
        0xC2,
        0x2F,
        0xF1,
        0x20,
        0x11,
        0x31,
        0x42,
        0x73,
        0xB5,
        0x28,
        0xDD,
    ],
)

VALID_TAG_BYTES = (16, 32)


def xor_bytes(*blocks: bytes) -> bytes:
    """XOR multiple byte strings together.

    Args:
        *blocks: Variable number of byte strings to XOR.

    Returns:
        XORed result as bytes.

    Raises:
        ValueError: If blocks have different lengths.
    """
    if not blocks:
        return b""
    result = bytearray(blocks[0])
    for block in blocks[1:]:
        if len(block) != len(result):
            raise ValueError("All blocks must have the same length")
        for i, b in enumerate(block):
            result[i] ^= b
    return bytes(result)


def and_bytes(a: bytes, b: bytes) -> bytes:
    """Perform bitwise AND on two byte strings.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        Bitwise AND result as bytes.

    Raises:
        ValueError: If byte strings have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Both blocks must have the same length")
    return bytes(x & y for x, y in zip(a, b))


def zero_pad(data: bytes, block_size: int) -> bytes:
    """Pad data with zeros to make it a multiple of block_size.

    Args:
        data: Input data to pad.
        block_size: Target block size.

    Returns:
        Padded data as bytes.

    Raises:
        ValueError: If block_size is not positive.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    remainder = len(data) % block_size
    if remainder == 0:
        return data
    return data + bytes(block_size - remainder)


def iter_blocks(data: bytes, block_size: int) -> Iterator[bytes]:
    """Iterate over data in fixed-size blocks.

    Args:
        data: Input data (must be multiple of block_size).
        block_size: Size of each block.

    Yields:
        Fixed-size blocks of data.

    Raises:
        ValueError: If block_size is not positive or data length is not a multiple.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if len(data) % block_size != 0:
        raise ValueError("data length must be a multiple of block_size")
    # Yield consecutive `block_size` chunks; callers ensure padding.
    for offset in range(0, len(data), block_size):
        yield data[offset : offset + block_size]


def split(data: bytes, block_size: int, count: int) -> list[bytes]:
    """Split data into a specific number of equal-sized blocks.

    Args:
        data: Input data to split.
        block_size: Size of each block.
        count: Number of blocks expected.

    Returns:
        List of blocks.

    Raises:
        ValueError: If data length doesn't match expected size.
    """
    expected = block_size * count
    if len(data) != expected:
        raise ValueError("data length does not match expected block count")
    return [data[i * block_size : (i + 1) * block_size] for i in range(count)]


def le64(value: int) -> bytes:
    """Convert integer to 8-byte little-endian representation.

    Args:
        value: Integer value to convert.

    Returns:
        8-byte little-endian representation.
    """
    return value.to_bytes(8, "little")


def validate_tag_length(tag_len: int) -> int:
    """Validate and convert tag length from bytes to bits.

    Args:
        tag_len: Tag length in bytes (must be 16 or 32).

    Returns:
        Tag length in bits.

    Raises:
        ValueError: If tag_len is not 16 or 32.
    """
    if tag_len not in VALID_TAG_BYTES:
        raise ValueError("tag_len must be 16 or 32 bytes")
    return tag_len * 8


def update_128l(state: Sequence[bytes], m0: bytes, m1: bytes) -> list[bytes]:
    """Update AEGIS-128L state with two message blocks.

    Args:
        state: Current 8-element state.
        m0: First message block (16 bytes).
        m1: Second message block (16 bytes).

    Returns:
        Updated state as list of 8 blocks.
    """
    s0, s1, s2, s3, s4, s5, s6, s7 = state
    new0 = aes_round(s7, xor_bytes(s0, m0))
    new1 = aes_round(s0, s1)
    new2 = aes_round(s1, s2)
    new3 = aes_round(s2, s3)
    new4 = aes_round(s3, xor_bytes(s4, m1))
    new5 = aes_round(s4, s5)
    new6 = aes_round(s5, s6)
    new7 = aes_round(s6, s7)
    return [new0, new1, new2, new3, new4, new5, new6, new7]


def update_256(state: Sequence[bytes], m: bytes) -> list[bytes]:
    """Update AEGIS-256 state with one message block.

    Args:
        state: Current 6-element state.
        m: Message block (16 bytes).

    Returns:
        Updated state as list of 6 blocks.
    """
    s0, s1, s2, s3, s4, s5 = state
    new0 = aes_round(s5, xor_bytes(s0, m))
    new1 = aes_round(s0, s1)
    new2 = aes_round(s1, s2)
    new3 = aes_round(s2, s3)
    new4 = aes_round(s3, s4)
    new5 = aes_round(s4, s5)
    return [new0, new1, new2, new3, new4, new5]


@dataclass
class AEGIS128LState:
    """AEGIS-128L state for encryption/decryption operations.

    Attributes:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        state: Internal 8-element state (initialized after construction).
    """

    key: bytes
    nonce: bytes

    def __post_init__(self) -> None:
        if len(self.key) != BLOCK_BYTES or len(self.nonce) != BLOCK_BYTES:
            raise ValueError("AEGIS-128L key and nonce must be 16 bytes")
        k = self.key
        n = self.nonce
        # Initial state before the 10 update rounds.
        self.state: list[bytes] = [
            xor_bytes(k, n),
            C1,
            C0,
            C1,
            xor_bytes(k, n),
            xor_bytes(k, C0),
            xor_bytes(k, C1),
            xor_bytes(k, C0),
        ]
        for _ in range(10):
            self.update(n, k)

    def update(self, m0: bytes, m1: bytes) -> None:
        self.state = update_128l(self.state, m0, m1)

    def absorb_block(self, block: bytes) -> None:
        m0, m1 = block[:BLOCK_BYTES], block[BLOCK_BYTES:]
        self.update(m0, m1)

    def _keystream_parts(self) -> tuple[bytes, bytes]:
        s0, s1, s2, s3, s4, s5, s6, s7 = self.state
        z0 = xor_bytes(s1, s6, and_bytes(s2, s3))
        z1 = xor_bytes(s2, s5, and_bytes(s6, s7))
        return z0, z1

    def enc_block(self, block: bytes) -> bytes:
        z0, z1 = self._keystream_parts()
        m0, m1 = block[:BLOCK_BYTES], block[BLOCK_BYTES:]
        c0 = xor_bytes(m0, z0)
        c1 = xor_bytes(m1, z1)
        self.update(m0, m1)
        return c0 + c1

    def dec_block(self, block: bytes) -> bytes:
        z0, z1 = self._keystream_parts()
        c0, c1 = block[:BLOCK_BYTES], block[BLOCK_BYTES:]
        m0 = xor_bytes(c0, z0)
        m1 = xor_bytes(c1, z1)
        self.update(m0, m1)
        return m0 + m1

    def dec_partial(self, data: bytes) -> bytes:
        z0, z1 = self._keystream_parts()
        # Partial decrypt pads to the full rate, then truncates at the end.
        padded = zero_pad(data, 2 * BLOCK_BYTES)
        c0, c1 = padded[:BLOCK_BYTES], padded[BLOCK_BYTES:]
        o0 = xor_bytes(c0, z0)
        o1 = xor_bytes(c1, z1)
        plain = (o0 + o1)[: len(data)]
        padded_plain = zero_pad(plain, 2 * BLOCK_BYTES)
        m0, m1 = padded_plain[:BLOCK_BYTES], padded_plain[BLOCK_BYTES:]
        self.update(m0, m1)
        return plain

    def finalize(self, left_bits: int, right_bits: int, tag_bits: int) -> bytes:
        u = le64(left_bits) + le64(right_bits)
        t = xor_bytes(self.state[2], u)
        for _ in range(7):
            self.update(t, t)
        if tag_bits == 128:
            tag = bytes(BLOCK_BYTES)
            for block in self.state[:7]:
                tag = xor_bytes(tag, block)
            return tag
        if tag_bits == 256:
            left = bytes(BLOCK_BYTES)
            right = bytes(BLOCK_BYTES)
            for block in self.state[:4]:
                left = xor_bytes(left, block)
            for block in self.state[4:]:
                right = xor_bytes(right, block)
            return left + right
        raise ValueError("tag_bits must be 128 or 256")


@dataclass
class AEGIS256State:
    """AEGIS-256 state for encryption/decryption operations.

    Attributes:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        state: Internal 6-element state (initialized after construction).
    """

    key: bytes
    nonce: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 2 * BLOCK_BYTES or len(self.nonce) != 2 * BLOCK_BYTES:
            raise ValueError("AEGIS-256 key and nonce must be 32 bytes")
        k0, k1 = self.key[:BLOCK_BYTES], self.key[BLOCK_BYTES:]
        n0, n1 = self.nonce[:BLOCK_BYTES], self.nonce[BLOCK_BYTES:]
        # Init procedure before the 4 round schedule.
        self.state: list[bytes] = [
            xor_bytes(k0, n0),
            xor_bytes(k1, n1),
            C1,
            C0,
            xor_bytes(k0, C0),
            xor_bytes(k1, C1),
        ]
        for _ in range(4):
            self.update(k0)
            self.update(k1)
            self.update(xor_bytes(k0, n0))
            self.update(xor_bytes(k1, n1))

    def update(self, block: bytes) -> None:
        self.state = update_256(self.state, block)

    def absorb_block(self, block: bytes) -> None:
        self.update(block)

    def _keystream(self) -> bytes:
        s0, s1, s2, s3, s4, s5 = self.state
        return xor_bytes(s1, s4, s5, and_bytes(s2, s3))

    def enc_block(self, block: bytes) -> bytes:
        z = self._keystream()
        self.update(block)
        return xor_bytes(block, z)

    def dec_block(self, block: bytes) -> bytes:
        z = self._keystream()
        plain = xor_bytes(block, z)
        self.update(plain)
        return plain

    def dec_partial(self, data: bytes) -> bytes:
        z = self._keystream()
        # Pad the short ciphertext into a full block, decrypt, then trim.
        padded = zero_pad(data, BLOCK_BYTES)
        out = xor_bytes(padded, z)
        plain = out[: len(data)]
        padded_plain = zero_pad(plain, BLOCK_BYTES)
        self.update(padded_plain)
        return plain

    def finalize(self, left_bits: int, right_bits: int, tag_bits: int) -> bytes:
        u = le64(left_bits) + le64(right_bits)
        t = xor_bytes(self.state[3], u)
        for _ in range(7):
            self.update(t)
        if tag_bits == 128:
            tag = bytes(BLOCK_BYTES)
            for block in self.state:
                tag = xor_bytes(tag, block)
            return tag
        if tag_bits == 256:
            left = bytes(BLOCK_BYTES)
            right = bytes(BLOCK_BYTES)
            for block in self.state[:3]:
                left = xor_bytes(left, block)
            for block in self.state[3:]:
                right = xor_bytes(right, block)
            return left + right
        raise ValueError("tag_bits must be 128 or 256")


@dataclass
class AEGIS128XState:
    """AEGIS-128X state for parallel encryption/decryption operations.

    Attributes:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        degree: Parallelization degree (1, 2, or 4).
        state: Internal 8xD-element state where D is the degree.
        ctx: Per-lane context values.
        rate: Number of bytes processed per update.
    """

    key: bytes
    nonce: bytes
    degree: int

    def __post_init__(self) -> None:
        if len(self.key) != BLOCK_BYTES or len(self.nonce) != BLOCK_BYTES:
            raise ValueError("AEGIS-128X key and nonce must be 16 bytes")
        if self.degree not in (1, 2, 4):
            raise ValueError("degree must be 1, 2, or 4")
        self.half_rate = BLOCK_BYTES * self.degree
        self.rate = self.half_rate * 2
        self.state: list[list[bytes]] = [[b""] * self.degree for _ in range(8)]
        base = xor_bytes(self.key, self.nonce)
        for idx in range(self.degree):
            # Each lane starts identically; contexts differentiate them later.
            self.state[0][idx] = base
            self.state[1][idx] = C1
            self.state[2][idx] = C0
            self.state[3][idx] = C1
            self.state[4][idx] = base
            self.state[5][idx] = xor_bytes(self.key, C0)
            self.state[6][idx] = xor_bytes(self.key, C1)
            self.state[7][idx] = xor_bytes(self.key, C0)

        nonce_v = self.nonce * self.degree
        key_v = self.key * self.degree
        self.ctx = [
            bytes([i, self.degree - 1]) + bytes(BLOCK_BYTES - 2)
            for i in range(self.degree)
        ]

        for _ in range(10):
            self._xor_ctx([3, 7])
            self.update(nonce_v, key_v)

    def _xor_ctx(self, indexes: Sequence[int]) -> None:
        for lane in range(self.degree):
            tweak = self.ctx[lane]
            for idx in indexes:
                # Inject the lane context into S3/S7 before each update.
                self.state[idx][lane] = xor_bytes(self.state[idx][lane], tweak)

    def update(self, m0: bytes, m1: bytes) -> None:
        blocks0 = split(m0, BLOCK_BYTES, self.degree)
        blocks1 = split(m1, BLOCK_BYTES, self.degree)
        new_state: list[list[bytes]] = [[] for _ in range(8)]
        for values in zip(*self.state, blocks0, blocks1):
            s0, s1, s2, s3, s4, s5, s6, s7, block0, block1 = values
            new_state[0].append(aes_round(s7, xor_bytes(s0, block0)))
            new_state[1].append(aes_round(s0, s1))
            new_state[2].append(aes_round(s1, s2))
            new_state[3].append(aes_round(s2, s3))
            new_state[4].append(aes_round(s3, xor_bytes(s4, block1)))
            new_state[5].append(aes_round(s4, s5))
            new_state[6].append(aes_round(s5, s6))
            new_state[7].append(aes_round(s6, s7))
        self.state = new_state

    def absorb_block(self, block: bytes) -> None:
        self.update(block[: self.half_rate], block[self.half_rate :])

    def _keystream_blocks(self) -> tuple[list[bytes], list[bytes]]:
        z0_parts: list[bytes] = []
        z1_parts: list[bytes] = []
        for s0, s1, s2, s3, s4, s5, s6, s7 in zip(*self.state):
            # Keystream word per lane.
            z0_parts.append(xor_bytes(s1, s6, and_bytes(s2, s3)))
            z1_parts.append(xor_bytes(s2, s5, and_bytes(s6, s7)))
        return z0_parts, z1_parts

    def enc_block(self, block: bytes) -> bytes:
        z0_blocks, z1_blocks = self._keystream_blocks()
        plain_first = block[: self.half_rate]
        plain_second = block[self.half_rate :]
        m0_blocks = split(plain_first, BLOCK_BYTES, self.degree)
        m1_blocks = split(plain_second, BLOCK_BYTES, self.degree)
        out_first = bytearray()
        out_second = bytearray()
        for idx in range(self.degree):
            out_first.extend(xor_bytes(m0_blocks[idx], z0_blocks[idx]))
            out_second.extend(xor_bytes(m1_blocks[idx], z1_blocks[idx]))
        self.update(block[: self.half_rate], block[self.half_rate :])
        return bytes(out_first) + bytes(out_second)

    def dec_block(self, block: bytes) -> bytes:
        z0_blocks, z1_blocks = self._keystream_blocks()
        cipher_first = block[: self.half_rate]
        cipher_second = block[self.half_rate :]
        c0_blocks = split(cipher_first, BLOCK_BYTES, self.degree)
        c1_blocks = split(cipher_second, BLOCK_BYTES, self.degree)
        plain_first = bytearray()
        plain_second = bytearray()
        for idx in range(self.degree):
            plain_first.extend(xor_bytes(c0_blocks[idx], z0_blocks[idx]))
            plain_second.extend(xor_bytes(c1_blocks[idx], z1_blocks[idx]))
        first_bytes = bytes(plain_first)
        second_bytes = bytes(plain_second)
        self.update(first_bytes, second_bytes)
        return first_bytes + second_bytes

    def dec_partial(self, data: bytes) -> bytes:
        z0_blocks, z1_blocks = self._keystream_blocks()
        padded = zero_pad(data, self.rate)
        c0_blocks = split(padded[: self.half_rate], BLOCK_BYTES, self.degree)
        c1_blocks = split(padded[self.half_rate :], BLOCK_BYTES, self.degree)
        plain_first = bytearray()
        plain_second = bytearray()
        for idx in range(self.degree):
            plain_first.extend(xor_bytes(c0_blocks[idx], z0_blocks[idx]))
            plain_second.extend(xor_bytes(c1_blocks[idx], z1_blocks[idx]))
        combined_plain = bytes(plain_first) + bytes(plain_second)
        plain = combined_plain[: len(data)]
        padded_plain = zero_pad(plain, self.rate)
        self.update(padded_plain[: self.half_rate], padded_plain[self.half_rate :])
        return plain

    def finalize(self, left_bits: int, right_bits: int, tag_bits: int) -> bytes:
        u = le64(left_bits) + le64(right_bits)
        lane_values = [xor_bytes(s2, u) for s2 in self.state[2]]
        t = b"".join(lane_values)
        for _ in range(7):
            self.update(t, t)
        if tag_bits == 128:
            tag = bytes(BLOCK_BYTES)
            for lane_blocks in zip(*self.state[:7]):
                # Fold the tag for all lanes, mirroring the spec's per-lane XOR.
                lane_tag = xor_bytes(*lane_blocks)
                tag = xor_bytes(tag, lane_tag)
            return tag
        if tag_bits == 256:
            left = bytes(BLOCK_BYTES)
            right = bytes(BLOCK_BYTES)
            for head, tail in zip(zip(*self.state[:4]), zip(*self.state[4:])):
                left = xor_bytes(left, xor_bytes(*head))
                right = xor_bytes(right, xor_bytes(*tail))
            return left + right
        raise ValueError("tag_bits must be 128 or 256")

    def finalize_mac(
        self, data_bits: int, tag_bits: int, *, return_intermediate: bool = False,
    ) -> bytes | tuple[bytes, bytes]:
        u = le64(data_bits) + le64(tag_bits)
        lane_values = [xor_bytes(s2, u) for s2 in self.state[2]]
        t = b"".join(lane_values)
        for _ in range(7):
            self.update(t, t)

        tags = bytearray()
        if tag_bits == 128:
            for lane_blocks in zip(*self.state[:7]):
                tags.extend(xor_bytes(*lane_blocks))
        elif tag_bits == 256:
            for lane_index, (head, tail) in enumerate(
                zip(zip(*self.state[:4]), zip(*self.state[4:])),
            ):
                if lane_index == 0:
                    continue
                tag_head = xor_bytes(*head)
                tag_tail = xor_bytes(*tail)
                tags.extend(tag_head + tag_tail)
        else:
            raise ValueError("tag_bits must be 128 or 256")

        tags_bytes = bytes(tags)
        if self.degree > 1 and tags_bytes:
            for block in iter_blocks(tags_bytes, 2 * BLOCK_BYTES):
                x0, x1 = block[:BLOCK_BYTES], block[BLOCK_BYTES:]
                pad0 = zero_pad(x0, self.half_rate)
                pad1 = zero_pad(x1, self.half_rate)
                self.update(pad0, pad1)

            extra = zero_pad(
                xor_bytes(self.state[2][0], le64(self.degree) + le64(tag_bits)),
                self.half_rate,
            )
            for _ in range(7):
                self.update(extra, extra)

        if tag_bits == 128:
            final = xor_bytes(
                self.state[0][0],
                self.state[1][0],
                self.state[2][0],
                self.state[3][0],
                self.state[4][0],
                self.state[5][0],
                self.state[6][0],
            )
        else:
            final = xor_bytes(
                self.state[0][0],
                self.state[1][0],
                self.state[2][0],
                self.state[3][0],
            ) + xor_bytes(
                self.state[4][0],
                self.state[5][0],
                self.state[6][0],
                self.state[7][0],
            )

        if return_intermediate:
            return final, tags_bytes
        return final


@dataclass
class AEGIS256XState:
    """AEGIS-256X state for parallel encryption/decryption operations.

    Attributes:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        degree: Parallelization degree (1, 2, or 4).
        state: Internal 6xD-element state where D is the degree.
        ctx: Per-lane context values.
        rate: Number of bytes processed per update.
    """

    key: bytes
    nonce: bytes
    degree: int

    def __post_init__(self) -> None:
        if len(self.key) != 2 * BLOCK_BYTES or len(self.nonce) != 2 * BLOCK_BYTES:
            raise ValueError("AEGIS-256X key and nonce must be 32 bytes")
        if self.degree not in (1, 2, 4):
            raise ValueError("degree must be 1, 2, or 4")
        self.rate = BLOCK_BYTES * self.degree
        self.state: list[list[bytes]] = [[b""] * self.degree for _ in range(6)]
        k0, k1 = self.key[:BLOCK_BYTES], self.key[BLOCK_BYTES:]
        n0, n1 = self.nonce[:BLOCK_BYTES], self.nonce[BLOCK_BYTES:]
        for lane in range(self.degree):
            self.state[0][lane] = xor_bytes(k0, n0)
            self.state[1][lane] = xor_bytes(k1, n1)
            self.state[2][lane] = C1
            self.state[3][lane] = C0
            self.state[4][lane] = xor_bytes(k0, C0)
            self.state[5][lane] = xor_bytes(k1, C1)

        self.ctx = [
            bytes([i, self.degree - 1]) + bytes(BLOCK_BYTES - 2)
            for i in range(self.degree)
        ]
        k0_v = k0 * self.degree
        k1_v = k1 * self.degree
        k0n0_v = xor_bytes(k0, n0) * self.degree
        k1n1_v = xor_bytes(k1, n1) * self.degree

        for _ in range(4):
            self._xor_ctx([3, 5])
            self.update(k0_v)
            self._xor_ctx([3, 5])
            self.update(k1_v)
            self._xor_ctx([3, 5])
            self.update(k0n0_v)
            self._xor_ctx([3, 5])
            self.update(k1n1_v)

    def _xor_ctx(self, indexes: Sequence[int]) -> None:
        for lane in range(self.degree):
            tweak = self.ctx[lane]
            for idx in indexes:
                # Context bytes toggle S3/S5 before every update pass.
                self.state[idx][lane] = xor_bytes(self.state[idx][lane], tweak)

    def update(self, block: bytes) -> None:
        lanes = split(block, BLOCK_BYTES, self.degree)
        new_state: list[list[bytes]] = [[] for _ in range(6)]
        for lane in range(self.degree):
            s0, s1, s2, s3, s4, s5 = (self.state[i][lane] for i in range(6))
            new_state[0].append(aes_round(s5, xor_bytes(s0, lanes[lane])))
            new_state[1].append(aes_round(s0, s1))
            new_state[2].append(aes_round(s1, s2))
            new_state[3].append(aes_round(s2, s3))
            new_state[4].append(aes_round(s3, s4))
            new_state[5].append(aes_round(s4, s5))
        for idx in range(6):
            self.state[idx] = new_state[idx]

    def absorb_block(self, block: bytes) -> None:
        self.update(block)

    def _keystream(self) -> bytes:
        parts = [
            xor_bytes(s1, s4, s5, and_bytes(s2, s3))
            for s0, s1, s2, s3, s4, s5 in zip(*self.state)
        ]
        return b"".join(parts)

    def enc_block(self, block: bytes) -> bytes:
        z = self._keystream()
        self.update(block)
        return xor_bytes(block, z)

    def dec_block(self, block: bytes) -> bytes:
        z = self._keystream()
        plain = xor_bytes(block, z)
        self.update(plain)
        return plain

    def dec_partial(self, data: bytes) -> bytes:
        z = self._keystream()
        padded = zero_pad(data, self.rate)
        out = xor_bytes(padded, z)
        plain = out[: len(data)]
        padded_plain = zero_pad(plain, self.rate)
        for chunk in iter_blocks(padded_plain, self.rate):
            self.update(chunk)
        return plain

    def finalize(self, left_bits: int, right_bits: int, tag_bits: int) -> bytes:
        u = le64(left_bits) + le64(right_bits)
        t = b"".join([xor_bytes(s3, u) for s3 in self.state[3]])
        for _ in range(7):
            self.update(t)
        if tag_bits == 128:
            tag = bytes(BLOCK_BYTES)
            for lane_blocks in zip(*self.state):
                lane_tag = xor_bytes(*lane_blocks)
                tag = xor_bytes(tag, lane_tag)
            return tag
        if tag_bits == 256:
            left = bytes(BLOCK_BYTES)
            right = bytes(BLOCK_BYTES)
            for head, tail in zip(zip(*self.state[:3]), zip(*self.state[3:])):
                left = xor_bytes(left, xor_bytes(*head))
                right = xor_bytes(right, xor_bytes(*tail))
            return left + right
        raise ValueError("tag_bits must be 128 or 256")

    def finalize_mac(
        self, data_bits: int, tag_bits: int, *, return_intermediate: bool = False,
    ) -> bytes | tuple[bytes, bytes]:
        u = le64(data_bits) + le64(tag_bits)
        t = b"".join([xor_bytes(s3, u) for s3 in self.state[3]])
        for _ in range(7):
            self.update(t)

        tags = bytearray()
        if tag_bits == 128:
            for lane_index, lane_blocks in enumerate(zip(*self.state)):
                if lane_index == 0:
                    # Lane 0 is kept for the final folding step.
                    continue
                tags.extend(xor_bytes(*lane_blocks))
        elif tag_bits == 256:
            for lane_index, (head, tail) in enumerate(
                zip(zip(*self.state[:3]), zip(*self.state[3:])),
            ):
                if lane_index == 0:
                    continue
                tags.extend(xor_bytes(*head) + xor_bytes(*tail))
        else:
            raise ValueError("tag_bits must be 128 or 256")

        tags_bytes = bytes(tags)
        if self.degree > 1 and tags_bytes:
            for block in iter_blocks(tags_bytes, BLOCK_BYTES):
                padded = zero_pad(block, self.rate)
                for chunk in iter_blocks(padded, self.rate):
                    self.update(chunk)

            extra = zero_pad(
                xor_bytes(self.state[3][0], le64(self.degree) + le64(tag_bits)),
                self.rate,
            )
            for _ in range(7):
                self.update(extra)

        if tag_bits == 128:
            final = xor_bytes(
                self.state[0][0],
                self.state[1][0],
                self.state[2][0],
                self.state[3][0],
                self.state[4][0],
                self.state[5][0],
            )
        else:
            final = xor_bytes(
                self.state[0][0],
                self.state[1][0],
                self.state[2][0],
            ) + xor_bytes(
                self.state[3][0],
                self.state[4][0],
                self.state[5][0],
            )

        if return_intermediate:
            return final, tags_bytes
        return final


def _encrypt_aegis128x(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes, tag_len: int, degree: int,
) -> tuple[bytes, bytes]:
    tag_bits = validate_tag_length(tag_len)
    state = AEGIS128XState(key, nonce, degree)
    for block in iter_blocks(zero_pad(ad, state.rate), state.rate):
        state.absorb_block(block)
    padded_msg = zero_pad(msg, state.rate)
    ciphertext = bytearray()
    for block in iter_blocks(padded_msg, state.rate):
        ciphertext.extend(state.enc_block(block))
    ciphertext_bytes = bytes(ciphertext)[: len(msg)]
    tag = state.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[:tag_len]
    return ciphertext_bytes, tag


def _decrypt_aegis128x(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes, degree: int,
) -> bytes:
    tag_bits = validate_tag_length(len(tag))
    state = AEGIS128XState(key, nonce, degree)
    for block in iter_blocks(zero_pad(ad, state.rate), state.rate):
        state.absorb_block(block)
    plaintext = bytearray()
    full = (len(ct) // state.rate) * state.rate
    for block in iter_blocks(ct[:full], state.rate):
        plaintext.extend(state.dec_block(block))
    remainder = ct[full:]
    if remainder:
        plaintext.extend(state.dec_partial(remainder))
    msg = bytes(plaintext)
    expected_tag = state.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[: len(tag)]
    if expected_tag != tag:
        msg = b"\x00" * len(msg)
        raise ValueError("authentication failed")
    return msg


def _encrypt_aegis256x(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes, tag_len: int, degree: int,
) -> tuple[bytes, bytes]:
    tag_bits = validate_tag_length(tag_len)
    state = AEGIS256XState(key, nonce, degree)
    for block in iter_blocks(zero_pad(ad, state.rate), state.rate):
        state.absorb_block(block)
    padded_msg = zero_pad(msg, state.rate)
    ciphertext = bytearray()
    for block in iter_blocks(padded_msg, state.rate):
        ciphertext.extend(state.enc_block(block))
    ciphertext_bytes = bytes(ciphertext)[: len(msg)]
    tag = state.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[:tag_len]
    return ciphertext_bytes, tag


def _decrypt_aegis256x(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes, degree: int,
) -> bytes:
    tag_bits = validate_tag_length(len(tag))
    state = AEGIS256XState(key, nonce, degree)
    for block in iter_blocks(zero_pad(ad, state.rate), state.rate):
        state.absorb_block(block)
    plaintext = bytearray()
    full = (len(ct) // state.rate) * state.rate
    for block in iter_blocks(ct[:full], state.rate):
        plaintext.extend(state.dec_block(block))
    remainder = ct[full:]
    if remainder:
        plaintext.extend(state.dec_partial(remainder))
    msg = bytes(plaintext)
    expected_tag = state.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[: len(tag)]
    if expected_tag != tag:
        msg = b"\x00" * len(msg)
        raise ValueError("authentication failed")
    return msg


def encrypt_aegis128x2(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b"", tag_len: int = 16,
) -> tuple[bytes, bytes]:
    """Encrypt with AEGIS-128X2 (2-way parallel).

    Args:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        msg: Plaintext message.
        ad: Associated data (optional).
        tag_len: Authentication tag length in bytes (16 or 32).

    Returns:
        Tuple of (ciphertext, authentication_tag).
    """
    return _encrypt_aegis128x(key, nonce, msg, ad, tag_len, degree=2)


def decrypt_aegis128x2(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt with AEGIS-128X2 (2-way parallel).

    Args:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        ct: Ciphertext to decrypt.
        tag: Authentication tag.
        ad: Associated data (optional).

    Returns:
        Plaintext message.

    Raises:
        ValueError: If authentication fails.
    """
    return _decrypt_aegis128x(key, nonce, ct, tag, ad, degree=2)


def encrypt_aegis128x4(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b"", tag_len: int = 16,
) -> tuple[bytes, bytes]:
    """Encrypt with AEGIS-128X4 (4-way parallel).

    Args:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        msg: Plaintext message.
        ad: Associated data (optional).
        tag_len: Authentication tag length in bytes (16 or 32).

    Returns:
        Tuple of (ciphertext, authentication_tag).
    """
    return _encrypt_aegis128x(key, nonce, msg, ad, tag_len, degree=4)


def decrypt_aegis128x4(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt with AEGIS-128X4 (4-way parallel).

    Args:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        ct: Ciphertext to decrypt.
        tag: Authentication tag.
        ad: Associated data (optional).

    Returns:
        Plaintext message.

    Raises:
        ValueError: If authentication fails.
    """
    return _decrypt_aegis128x(key, nonce, ct, tag, ad, degree=4)


def encrypt_aegis256x2(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b"", tag_len: int = 16,
) -> tuple[bytes, bytes]:
    """Encrypt with AEGIS-256X2 (2-way parallel).

    Args:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        msg: Plaintext message.
        ad: Associated data (optional).
        tag_len: Authentication tag length in bytes (16 or 32).

    Returns:
        Tuple of (ciphertext, authentication_tag).
    """
    return _encrypt_aegis256x(key, nonce, msg, ad, tag_len, degree=2)


def decrypt_aegis256x2(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt with AEGIS-256X2 (2-way parallel).

    Args:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        ct: Ciphertext to decrypt.
        tag: Authentication tag.
        ad: Associated data (optional).

    Returns:
        Plaintext message.

    Raises:
        ValueError: If authentication fails.
    """
    return _decrypt_aegis256x(key, nonce, ct, tag, ad, degree=2)


def encrypt_aegis256x4(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b"", tag_len: int = 16,
) -> tuple[bytes, bytes]:
    """Encrypt with AEGIS-256X4 (4-way parallel).

    Args:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        msg: Plaintext message.
        ad: Associated data (optional).
        tag_len: Authentication tag length in bytes (16 or 32).

    Returns:
        Tuple of (ciphertext, authentication_tag).
    """
    return _encrypt_aegis256x(key, nonce, msg, ad, tag_len, degree=4)


def decrypt_aegis256x4(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt with AEGIS-256X4 (4-way parallel).

    Args:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        ct: Ciphertext to decrypt.
        tag: Authentication tag.
        ad: Associated data (optional).

    Returns:
        Plaintext message.

    Raises:
        ValueError: If authentication fails.
    """
    return _decrypt_aegis256x(key, nonce, ct, tag, ad, degree=4)


def aegis128x2_mac(key: bytes, nonce: bytes, data: bytes, tag_len: int = 16) -> bytes:
    """Compute AEGIS-128X2 MAC (2-way parallel).

    Args:
        key: 16-byte key.
        nonce: 16-byte nonce.
        data: Data to authenticate.
        tag_len: MAC tag length in bytes (16 or 32).

    Returns:
        MAC tag.
    """
    tag_bits = validate_tag_length(tag_len)
    state = AEGIS128XState(key, nonce, 2)
    for block in iter_blocks(zero_pad(data, state.rate), state.rate):
        state.absorb_block(block)
    result = state.finalize_mac(len(data) * 8, tag_bits)
    if isinstance(result, tuple):
        result = result[0]
    return result[:tag_len]


def aegis128x4_mac(key: bytes, nonce: bytes, data: bytes, tag_len: int = 16) -> bytes:
    """Compute AEGIS-128X4 MAC (4-way parallel).

    Args:
        key: 16-byte key.
        nonce: 16-byte nonce.
        data: Data to authenticate.
        tag_len: MAC tag length in bytes (16 or 32).

    Returns:
        MAC tag.
    """
    tag_bits = validate_tag_length(tag_len)
    state = AEGIS128XState(key, nonce, 4)
    for block in iter_blocks(zero_pad(data, state.rate), state.rate):
        state.absorb_block(block)
    result = state.finalize_mac(len(data) * 8, tag_bits)
    if isinstance(result, tuple):
        result = result[0]
    return result[:tag_len]


def aegis256x2_mac(key: bytes, nonce: bytes, data: bytes, tag_len: int = 16) -> bytes:
    """Compute AEGIS-256X2 MAC (2-way parallel).

    Args:
        key: 32-byte key.
        nonce: 32-byte nonce.
        data: Data to authenticate.
        tag_len: MAC tag length in bytes (16 or 32).

    Returns:
        MAC tag.
    """
    tag_bits = validate_tag_length(tag_len)
    state = AEGIS256XState(key, nonce, 2)
    for block in iter_blocks(zero_pad(data, state.rate), state.rate):
        state.absorb_block(block)
    result = state.finalize_mac(len(data) * 8, tag_bits)
    if isinstance(result, tuple):
        result = result[0]
    return result[:tag_len]


def aegis256x4_mac(key: bytes, nonce: bytes, data: bytes, tag_len: int = 16) -> bytes:
    """Compute AEGIS-256X4 MAC (4-way parallel).

    Args:
        key: 32-byte key.
        nonce: 32-byte nonce.
        data: Data to authenticate.
        tag_len: MAC tag length in bytes (16 or 32).

    Returns:
        MAC tag.
    """
    tag_bits = validate_tag_length(tag_len)
    state = AEGIS256XState(key, nonce, 4)
    for block in iter_blocks(zero_pad(data, state.rate), state.rate):
        state.absorb_block(block)
    result = state.finalize_mac(len(data) * 8, tag_bits)
    if isinstance(result, tuple):
        result = result[0]
    return result[:tag_len]


def encrypt_aegis128l(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b"", tag_len: int = 16,
) -> tuple[bytes, bytes]:
    """Encrypt with AEGIS-128L.

    Args:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        msg: Plaintext message.
        ad: Associated data (optional).
        tag_len: Authentication tag length in bytes (16 or 32).

    Returns:
        Tuple of (ciphertext, authentication_tag).
    """
    tag_bits = validate_tag_length(tag_len)
    s = AEGIS128LState(key, nonce)
    for block in iter_blocks(zero_pad(ad, RATE_128L), RATE_128L):
        s.absorb_block(block)
    padded_msg = zero_pad(msg, RATE_128L)
    ciphertext = bytearray()
    for block in iter_blocks(padded_msg, RATE_128L):
        ciphertext.extend(s.enc_block(block))
    ciphertext_bytes = bytes(ciphertext)[: len(msg)]
    tag = s.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[:tag_len]
    return ciphertext_bytes, tag


def decrypt_aegis128l(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt with AEGIS-128L.

    Args:
        key: 16-byte encryption key.
        nonce: 16-byte nonce.
        ct: Ciphertext to decrypt.
        tag: Authentication tag.
        ad: Associated data (optional).

    Returns:
        Plaintext message.

    Raises:
        ValueError: If authentication fails.
    """
    tag_bits = validate_tag_length(len(tag))
    s = AEGIS128LState(key, nonce)
    for block in iter_blocks(zero_pad(ad, RATE_128L), RATE_128L):
        s.absorb_block(block)
    plaintext = bytearray()
    full = (len(ct) // RATE_128L) * RATE_128L
    for block in iter_blocks(ct[:full], RATE_128L):
        plaintext.extend(s.dec_block(block))
    remainder = ct[full:]
    if remainder:
        plaintext.extend(s.dec_partial(remainder))
    msg = bytes(plaintext)
    expected_tag = s.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[: len(tag)]
    if expected_tag != tag:
        msg = b"\x00" * len(msg)
        raise ValueError("authentication failed")
    return msg


def encrypt_aegis256(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b"", tag_len: int = 16,
) -> tuple[bytes, bytes]:
    """Encrypt with AEGIS-256.

    Args:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        msg: Plaintext message.
        ad: Associated data (optional).
        tag_len: Authentication tag length in bytes (16 or 32).

    Returns:
        Tuple of (ciphertext, authentication_tag).
    """
    tag_bits = validate_tag_length(tag_len)
    s = AEGIS256State(key, nonce)
    for block in iter_blocks(zero_pad(ad, RATE_256), RATE_256):
        s.absorb_block(block)
    padded_msg = zero_pad(msg, RATE_256)
    ciphertext = bytearray()
    for block in iter_blocks(padded_msg, RATE_256):
        ciphertext.extend(s.enc_block(block))
    ciphertext_bytes = bytes(ciphertext)[: len(msg)]
    tag = s.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[:tag_len]
    return ciphertext_bytes, tag


def decrypt_aegis256(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt with AEGIS-256.

    Args:
        key: 32-byte encryption key.
        nonce: 32-byte nonce.
        ct: Ciphertext to decrypt.
        tag: Authentication tag.
        ad: Associated data (optional).

    Returns:
        Plaintext message.

    Raises:
        ValueError: If authentication fails.
    """
    tag_bits = validate_tag_length(len(tag))
    s = AEGIS256State(key, nonce)
    for block in iter_blocks(zero_pad(ad, RATE_256), RATE_256):
        s.absorb_block(block)
    plaintext = bytearray()
    full = (len(ct) // RATE_256) * RATE_256
    for block in iter_blocks(ct[:full], RATE_256):
        plaintext.extend(s.dec_block(block))
    remainder = ct[full:]
    if remainder:
        plaintext.extend(s.dec_partial(remainder))
    msg = bytes(plaintext)
    expected_tag = s.finalize(len(ad) * 8, len(msg) * 8, tag_bits)[: len(tag)]
    if expected_tag != tag:
        msg = b"\x00" * len(msg)
        raise ValueError("authentication failed")
    return msg


def aegis128l_mac(key: bytes, nonce: bytes, data: bytes, tag_len: int = 16) -> bytes:
    """Compute AEGIS-128L MAC.

    Args:
        key: 16-byte key.
        nonce: 16-byte nonce.
        data: Data to authenticate.
        tag_len: MAC tag length in bytes (16 or 32).

    Returns:
        MAC tag.
    """
    tag_bits = validate_tag_length(tag_len)
    s = AEGIS128LState(key, nonce)
    for block in iter_blocks(zero_pad(data, RATE_128L), RATE_128L):
        s.absorb_block(block)
    tag = s.finalize(len(data) * 8, tag_bits, tag_bits)[:tag_len]
    return tag


def aegis256_mac(key: bytes, nonce: bytes, data: bytes, tag_len: int = 16) -> bytes:
    """Compute AEGIS-256 MAC.

    Args:
        key: 32-byte key.
        nonce: 32-byte nonce.
        data: Data to authenticate.
        tag_len: MAC tag length in bytes (16 or 32).

    Returns:
        MAC tag.
    """
    tag_bits = validate_tag_length(tag_len)
    s = AEGIS256State(key, nonce)
    for block in iter_blocks(zero_pad(data, RATE_256), RATE_256):
        s.absorb_block(block)
    tag = s.finalize(len(data) * 8, tag_bits, tag_bits)[:tag_len]
    return tag


__all__ = [
    "aegis128l_mac",
    "aegis128x2_mac",
    "aegis128x4_mac",
    "aegis256_mac",
    "aegis256x2_mac",
    "aegis256x4_mac",
    "decrypt_aegis128l",
    "decrypt_aegis128x2",
    "decrypt_aegis128x4",
    "decrypt_aegis256",
    "decrypt_aegis256x2",
    "decrypt_aegis256x4",
    "encrypt_aegis128l",
    "encrypt_aegis128x2",
    "encrypt_aegis128x4",
    "encrypt_aegis256",
    "encrypt_aegis256x2",
    "encrypt_aegis256x4",
]

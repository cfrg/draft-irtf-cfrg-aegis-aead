---
title: "The AEGIS family of authenticated encryption algorithms"
docname: draft-aegis-aead-latest
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Frank Denis
    organization: Fastly Inc.
    email: fd@00f.net

informative:

  FIPS-AES:
    title: "Specification for the ADVANCED ENCRYPTION STANDARD (AES)"
    venue: Federal Information Processing Standard (FIPS) Publication 197
    target: https://csrc.nist.gov/publications/detail/fips/197/final

  AEGIS:
    title: "AEGIS: A fast encryption algorithm"
    venue: CAESAR competition
    target: https://competitions.cr.yp.to/round3/aegisv11.pdf
    authors:
      -
        ins: Hongjun Wu
        org: Nanyang Technological University
      -
        ins: Bart Preneel
        org: KU Leuven

--- abstract

This document describes AEGIS-128L and AEGIS-256, two AES-based authenticated encryption algorithms designed for high-performance applications.


--- middle

# Introduction

This document describes the AEGIS-128L and AEGIS-256 authenticated encryption algorithms {{AEGIS}}.

Both are constructed from the AES encryption round function {{FIPS-AES}} and target a 128-bit security level.

- AEGIS-128L has a 128-bit key, a 128-bit nonce, a 1024 bit state, a 128-bit authentication tag, and processes 256-bit input blocks.
- AEGIS-256 has a 256-bit key, a 256-bit nonce, a 768-bit state and a 128-bit authentication tag, and processes 128-bit input blocks.

The AEGIS cipher family offers optimal performance on CPUs with hardware support for parallelizable AES block encryption.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Notation and Conventions

- `|x|`: the length of `x` in bits
- `a ^ b`: the bit-wise exclusive OR operation between `a` and `b`
- `a & b`: the bit-wise AND operation between `a` and `b`
- `a || b`: the concatenation of `a` and `b`
- `LE64(x)`: the little-endian encoding of 64-bit integer `x`
- `Pad(x, n)`: padding operation. Trailing zeros are concatenated to `x` until the total length is a multiple of `n` bits.
- `Truncate(x, n)`: truncation operation. The first `n` bits of `x` are kept.
- `Split(x, n)`: splitting operation. `x` is split into `n`-bit blocks.
- `AESRound(a, b)`: the AES encryption round function. `a` is the 128-bit state, `b` is the 128-bit round key
- `Update(Ma, Mb)`: the state update function
- `Init(k, iv)`: the initialization function
- `Enc(xi)`: the 256-bit block encryption function
- `Dec(xi)`: the 256-bit block decryption function
- `Finalize(adlen, mlen)`: the authentication tag generation function
- `Repeat(n, F)`: `n` sequential evaluations of the function `F`
- `Si`: the `i`-th 128-bit block of the current state
- `S'i`: the `i`-th 128-bit block of the next state
- `C0`: the 128-bit constant `0x0101020305080d1522375990e97962`
- `C1`: the 128-bit constant `0xdb3d18556dc22ff12011314273b528dd`
- `k`: the 128-bit key
- `iv`: the 128-bit nonce
- `ad`: the associated data
- `m`: the cleartext input
- `c`: the ciphertext
- `tag`: the 128-bit authentication tag

# The AEGIS-128L Algorithm

AEGIS-128L has a 1024 bit state, made of eight 128-bit blocks.

## The Update() Function

The state update function Update(Ma, Mb) of AEGIS-128L is defined as follows:

~~~
S'0 = AESRound(S7, S0 ^ Ma)
S'1 = AESRound(S0, S1);
S'2 = AESRound(S1, S2);
S'3 = AESRound(S2, S3);
S'4 = AESRound(S3, S4 ^ Mb);
S'5 = AESRound(S4, S5);
S'6 = AESRound(S5, S6);
S'7 = AESRound(S6, S7);

S0  = S'0
S1  = S'1
S2  = S'2
S3  = S'3
S4  = S'4
S5  = S'5
S6  = S'6
S7  = S'7
~~~

## The Init(k, iv) Function

The AEGIS-128L state is initialized as follows:

~~~
S0 = k ^ iv
S1 = C1
S2 = C0
S3 = C1
S4 = k ^ iv
S5 = k ^ C0
S6 = k ^ C1
S7 = k ^ C0

Repeat(10, Update(iv, k))
~~~

## The Enc(xi) Function

The 256-bit block encryption function is defined as follows:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(xi, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(t0, t1)
~~~

It returns the 256-bit block `out0 || out1`.

## The Dec(xi) Function

The 256-bit block decryption function is defined as follows:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(xi, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(out0, out1)
~~~

It returns the 256-bit block `out0 || out1`.

## The Finalize(adlen, mlen) Function

The finalization function computes the authentication tag as follows:

~~~
t = S2 ^ (LE64(adlen) || LE64(mlen))
Repeat(7, Update(t, t))
tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
~~~

The function returns the 128-bit authentication tag.

## Authenticated Encryption

Encryption of a message `m` with associated data `ad` using a key `k` and a nonce `iv` is done as follows:

~~~
Init(k, iv)

c = {}

ad_blocks = Split(Pad(ad, 256), 256)
for xi in ad_blocks:
    Enc(xi)

m_blocks = Split(Pad(m, 256), 256)
for xi in m_blocks:
    c = c || Enc(xi)

tag = Finalize(|ad|, |m|)
~~~

The function returns the ciphertext `c` and the 128-bit authentication tag `tag`.

## Authenticated Decryption

Decryption of a ciphertext `c` with associated data `ad` using a key `k`, a nonce `iv` and an authentication tag `tag` is done as follows:

~~~
Init(k, iv)

m = {}

ad_blocks = Split(Pad(ad, 256), 256)
for xi in ad_blocks:
    Enc(xi)

c_blocks = Split(Pad(c, 256), 256)
for xi in c_blocks:
    m = m || Dec(xi)

m = Truncate(m, |c|)
expected_tag = Finalize(|ad|, |m|)
~~~

If `expected_tag = tag`, the function returns the decrypted message `m`. Otherwise, an authentication error is returned.

The comparison of the authentication tag `tag` with the expected tag should be done in constant time.

# The AEGIS-256 Algorithm

AEGIS-256 has a 768 bit state, made of six 128-bit blocks.

## The Update() Function

The state update function Update(M) of AEGIS-256 is defined as follows:

~~~
S'0 = AESRound(S5, S0 ^ M)
S'1 = AESRound(S0, S1);
S'2 = AESRound(S1, S2);
S'3 = AESRound(S2, S3);
S'4 = AESRound(S3, S4);
S'5 = AESRound(S4, S5);

S0  = S'0
S1  = S'1
S2  = S'2
S3  = S'3
S4  = S'4
S5  = S'5
~~~

## The Init(k, iv) Function

The AEGIS-256 state is initialized as follows:

~~~
k0, k1 = Split(k, 128)
iv0, iv1 = Split(iv, 128)

S0 = k0 ^ iv0
S1 = k1 ^ iv1
S2 = C1
S3 = C0
S4 = k0 ^ C0
S5 = k1 ^ C1

Repeat(4,
  Update(k0)
  Update(k1)
  Update(k0 ^ iv0)
  Update(k1 ^ iv1)
)
~~~

## The Enc(xi) Function

The 128-bit block encryption function is defined as follows:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)
out = xi ^ z
Update(xi)
~~~

It returns the 128-bit block `out`.

## The Dec(xi) Function

The 128-bit block decryption function is defined as follows:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)
out = xi ^ z
Update(out)
~~~

It returns the 128-bit block `out`.

## The Finalize(adlen, mlen) Function

The finalization function computes the authentication tag as follows:

~~~
t = S3 ^ (LE64(adlen) || LE64(mlen))
Repeat(7, Update(t))
tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
~~~

The function returns the 128-bit authentication tag.

## Authenticated Encryption

Encryption of a message `m` with associated data `ad` using a key `k` and a nonce `iv` is done as follows:

~~~
Init(k, iv)

c = {}

ad_blocks = Split(Pad(ad, 128), 128)
for xi in ad_blocks:
    Enc(xi)

m_blocks = Split(Pad(m, 128), 128)
for xi in m_blocks:
    c = c || Enc(xi)

tag = Finalize(|ad|, |m|)
~~~

The function returns the ciphertext `c` and the 128-bit authentication tag `tag`.

## Authenticated Decryption

Decryption of a ciphertext `c` with associated data `ad` using a key `k`, a nonce `iv` and an authentication tag `tag` is done as follows:

~~~
Init(k, iv)

m = {}

ad_blocks = Split(Pad(ad, 128), 128)
for xi in ad_blocks:
    Enc(xi)

c_blocks = Split(Pad(c, 128), 128)
for xi in c_blocks:
    m = m || Dec(xi)

m = Truncate(m, |c|)
expected_tag = Finalize(|ad|, |m|)
~~~

If `expected_tag = tag`, the function returns the decrypted message `m`. Otherwise, an authentication error is returned.

The comparison of the authentication tag `tag` with the expected tag should be done in constant time.

# Encoding Of (c, tag) Tuples

Applications may keep the ciphertext and the 128-bit authentication tag in distinct structures, or encore both as a single string.

In the later case, the tag is expected to immediately follow the ciphertext:

~~~
combined_ciphertext = c || tag
~~~

# Security Considerations

Both algorithms are key-committing and are designed to offer 128-bit security in a nonce-respecting setting.

The nonce `iv` doesn't have to be secret nor unpredictable. It can be a counter, the output of a permutation or a generator with a long period.

With AEGIS-128L, random nonces are also safe to encrypt up to 2^32 messages using the same key with negligible collision probability.

With AEGIS-256, random nonces are safe to use with no practical limits.

However, for a given key `k`, a nonce must only be used once. Failure to do so would immediately reveal the plaintext difference between two messages.

# IANA Considerations

This document has no IANA actions.

# Test Vectors

## AEGIS-128L Test Vectors

### Test Vector 1

~~~
key  : 00000000000000000000000000000000
nonce: 00000000000000000000000000000000
ad   :
m    : 00000000000000000000000000000000
c    : 41de9000a7b5e40e2d68bb64d99ebb19
tag  : f4d997cc9b94227ada4fe4165422b1c8
~~~

### Test Vector 2

~~~
key  : 00000000000000000000000000000000
nonce: 00000000000000000000000000000000
ad   :
m    :
c    :
tag  : 83cc600dc4e3e7e62d4055826174f149
~~~

### Test Vector 3

~~~
key  : 10010000000000000000000000000000
nonce: 10000200000000000000000000000000
ad   : 0001020304050607
m    : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
c    : 79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84
tag  : cc6f3372f6aa1bb82388d695c3962d9a
~~~

## AEGIS-256 Test Vectors

TODO.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge

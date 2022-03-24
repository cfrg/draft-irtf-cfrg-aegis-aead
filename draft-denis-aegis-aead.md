---
title: "The AEGIS family of authenticated encryption algorithms"
docname: draft-denis-aegis-aead-latest
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
    email: fde@00f.net
 -
    name: Fabio Enrico Renzo Scotoni
    organization: Individual Contributor
    email: fabio@esse.ch
 -
    name: Samuel Lucas
    organization: Individual Contributor
    email: samuel-lucas6@pm.me

informative:

  AEGIS:
    title: "AEGIS: A fast encryption algorithm (v1.1)"
    venue: CAESAR competition
    target: https://competitions.cr.yp.to/round3/aegisv11.pdf
    author:
      -
        ins: H. Wu
        name: Hongjun Wu
        org: Nanyang Technological University
      -
        ins: B. Preneel
        name: Bart Preneel
        org: KU Leuven
    date: 2016-09-15

  LGR21:
    title: "Partitioning Oracle Attacks"
    rc: "30th USENIX Security Symposium (USENIX Security 21)"
    target: https://www.usenix.org/conference/usenixsecurity21/presentation/len
    author:
      -
        ins: J. Len
        name: Julia Len
        org: Cornell Tech
      -
        ins: P. Grubbs
        name: Paul Grubbs
        org: Cornell Tech
      -
        ins: T. Ristenpart
        name: Thomas Ristenpart
        org: Cornell Tech
    date: 2021

  CRA18:
    title: "Can Caesar Beat Galois? Robustness of CAESAR Candidates against Nonce Reusing and High Data Complexity Attacks"
    rc: "Applied Cryptography and Network Security. ACNS 2018. Lecture Notes in Computer Science, vol 10892"
    seriesinfo:
      DOI: 10.1007/978-3-319-93387-0_25
    author:
      -
        ins: S. Vaudenay
        name: Serge Vaudenay
        org: EPFL, Switzerland
      -
        ins: D. Vizár
        name: Damian Vizár
        org: EPFL, Switzerland
    date: 2018

--- abstract

This document describes AEGIS-128L and AEGIS-256, two AES-based authenticated encryption algorithms designed for high-performance applications.


--- middle

# Introduction

This document describes the AEGIS-128L and AEGIS-256 authenticated encryption with associated data (AEAD) algorithms {{AEGIS}}, a variant of which has been chosen as a winner in the Competition for Authenticated Encryption: Security, Applicability, and Robustness (CAESAR). All variants of AEGIS are constructed from the AES encryption round function {{!FIPS-AES=FIPS.197.2001}}. This document specifies:

- AEGIS-128L, which has a 128-bit key, a 128-bit nonce, a 1024-bit state, a 128-bit authentication tag, and processes 256-bit input blocks.
- AEGIS-256, which has a 256-bit key, a 256-bit nonce, a 768-bit state, a 128-bit authentication tag, and processes 128-bit input blocks.

The AEGIS cipher family offers performance that significantly exceeds that of AES-GCM with hardware support for parallelizable AES block encryption {{AEGIS}}. Similarly, software implementations can also be faster, although to a lesser extent.

Unlike with AES-GCM, nonces can be safely chosen at random with no practical limit when using AEGIS-256. AEGIS-128L also allows for more messages to be safely encrypted when using random nonces.

With some existing AEAD schemes, such as AES-GCM, an attacker can generate a ciphertext that successfully decrypts under multiple different keys (a partitioning oracle attack){{LGR21}}. This ability to craft a (ciphertext, authentication tag) pair that verifies under multiple keys significantly reduces the number of required interactions with the oracle in order to perform an exhaustive search, making it practical if the key space is small. One example for a small key space is password-based encryption: an attacker can guess a large number of passwords at a time by recursively submitting such a ciphertext to an oracle, which speeds up a password search by reducing it to a binary search.

While this may be mitigated by means of inserting a padding block in the aforementioned algorithms, this workaround comes with additional processing cost and must itself be carefully constructed to resist leaking information via timing. As a key-committing AEAD scheme, the AEGIS cipher family is naturally more resistant against partitioning oracle attacks than non-committing AEAD schemes, making it significantly harder to find multiple different keys that decrypt successfully.

Finally, unlike most other AES-based AEAD constructions, such as Rocca and Tiaoxin, leaking the state does not leak the key.

Note that an earlier version of Hongjun Wu and Bart Preneel's paper introducing AEGIS specified AEGIS-128L and AEGIS-256 sporting differences with regards to the computation of the authentication tag and the number of rounds in `Finalize()` respectively. We follow the specification of {{AEGIS}} that is current at the time of writing, which can be found in the References section of this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Primitives:

- `|x|`: the length of `x` in bits.
- `a ^ b`: the bitwise exclusive OR operation between `a` and `b`.
- `a & b`: the bitwise AND operation between `a` and `b`.
- `a || b`: the concatenation of `a` and `b`.
- `a mod b`: the remainder of the Euclidean division between `a` as the dividend and `b` as the divisor.
- `LE64(x)`: the little-endian encoding of 64-bit integer `x`.
- `Pad(x, n)`: padding operation. Trailing zeros are concatenated to `x` until the total length is a multiple of `n` bits.
- `Truncate(x, n)`: truncation operation. The first `n` bits of `x` are kept.
- `Split(x, n)`: splitting operation. `x` is split `n`-bit blocks, ignoring partial blocks.
- `Tail(x, n)`: returns the last `n` bits of `x`.
- `AESRound(in, rk)`: a single round of the AES encryption round function, which is the composition of the `SubBytes`, `ShiftRows`, `MixColums` and `AddRoundKey` transformations, as defined in section 5 of {{FIPS-AES}}. `in` is the 128-bit AES input state, and `rk` is the 128-bit round key.
- `Repeat(n, F)`: `n` sequential evaluations of the function `F`.
- `CtEq(a, b)`: compares `a` and `b` in constant-time, returning `True` for an exact match, `False` otherwise.

AEGIS internal functions:

- `Update(M0, M1)`: the state update function.
- `Init(key, nonce)`: the initialization function.
- `Enc(xi)`: the input block encryption function.
- `Dec(ci)`: the input block decryption function.
- `DecPartial(cn)`: the input block decryption function for the last ciphertext bits when they do not fill an entire block.
- `Finalize(ad_len, msg_len)`: the authentication tag generation function.

Input blocks are 256 bits for AEGIS-128L and 128 bits for AEGIS-256.

AES blocks:

- `Si`: the `i`-th AES block of the current state.
- `S'i`: the `i`-th AES block of the next state.
- `{Si, ...Sj}`: the vector of the `i`-th AES block of the current state to the `j`-th block of the current state.
- `C0`: the constant `0x000101020305080d1522375990e97962` as an AES block.
- `C1`: the constant `0xdb3d18556dc22ff12011314273b528dd` as an AES block.

AES blocks are always 128 bits in length.

Input and output values:

- `key`: the encryption key (128 bits for AEGIS-128L, 256 bits for AEGIS-256).
- `nonce`: the public nonce (128 bits for AEGIS-128L, 256 bits for AEGIS-256).
- `ad`: the associated data.
- `msg`: the plaintext.
- `ct`: the ciphertext.
- `tag`: the authentication tag (128 bits).

# The AEGIS-128L Algorithm

AEGIS-128L has a 1024-bit state, made of eight 128-bit blocks `{S0, ...S7}`.

The parameters for this algorithm, whose meaning is defined in {{!RFC5116, Section 4}} are:

- `K_LEN` (key length) is 16 octets.
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> octets.
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> octets.
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 16 octets.
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 octets.

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} shall be unambiguously encoded as a single input.
It is up to the application to create a structure in the associated data input if needed.

## Authenticated Encryption

~~~
Encrypt(msg, ad, key, nonce)
~~~

The `Encrypt` function encrypts a message and returns the ciphertext along with an authentication tag that verifies the authenticity of the message and associated data, if provided.

Security:
- The nonce MUST NOT be reused under any circumstances; doing so allows an attacker to recover the internal state.
- The key MUST be randomly chosen from a uniform distribution.

Inputs:

- `msg`: the message to be encrypted.
- `ad`: the associated data to authenticate.
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- `ct`: the ciphertext.
- `tag`: the authentication tag.

Steps:

~~~
Init(key, nonce)

ct = {}

ad_blocks = Split(Pad(ad, 256), 256)
for xi in ad_blocks:
    Enc(xi)

msg_blocks = Split(Pad(msg, 256), 256)
for xi in msg_blocks:
    ct = ct || Enc(xi)

tag = Finalize(|ad|, |msg|)
ct = Truncate(ct, |msg|)

return ct and tag
~~~

## Authenticated Decryption

~~~
Decrypt(ct, tag, ad, key, nonce)
~~~

The `Decrypt` function decrypts a ciphertext, verifies that the authentication tag is correct, and returns the message on success or an error if tag verification failed.

Security:
- If tag verification fails, the decrypted message and wrong message authentication tag MUST NOT be given as output. The decrypted message MUST be overwritten with zeros.
- The comparison of the input `tag` with the `expected_tag` SHOULD be done in constant time.

Inputs:

- `ct`: the ciphertext to be decrypted.
- `tag`: the authentication tag.
- `ad`: the associated data to authenticate.
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- Either the decrypted message `msg`, or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
Init(key, nonce)

msg = {}

ad_blocks = Split(Pad(ad, 256), 256)
for xi in ad_blocks:
    Enc(xi)

ct_blocks = Split(ct, 256)
cn = Tail(ct, |ct| mod 256)

for ci in ct_blocks:
    msg = msg || Dec(ci)

if cn is not empty:
    msg = msg || DecPartial(cn)

expected_tag = Finalize(|ad|, |msg|)

if CtEq(tag, expected_tag) is False:
    erase msg
    return "verification failed" error
else:
    return msg
~~~

## The Init Function

~~~
Init(key, nonce)
~~~

The `Init` function constructs the initial state `{S0, ...S7}` using the given `key` and `nonce`.

Inputs:

- `key`: the encryption key.
- `nonce`: the nonce.

Defines:

- `{S0, ...S7}`: the initial state.

Steps:

~~~
S0 = key ^ nonce
S1 = C1
S2 = C0
S3 = C1
S4 = key ^ nonce
S5 = key ^ C0
S6 = key ^ C1
S7 = key ^ C0

Repeat(10, Update(nonce, key))
~~~

## The Update Function

~~~
Update(M0, M1)
~~~

The `Update` function is the core of the AEGIS-128L algorithm.
It updates the state `{S0, ...S7}` using two 128-bit values.

Inputs:

- `M0`: the first 128-bit block to be absorbed.
- `M1`: the second 128-bit block to be absorbed.

Modifies:

- `{S0, ...S7}`: the state.

Steps:

~~~
S'0 = AESRound(S7, S0 ^ M0)
S'1 = AESRound(S0, S1)
S'2 = AESRound(S1, S2)
S'3 = AESRound(S2, S3)
S'4 = AESRound(S3, S4 ^ M1)
S'5 = AESRound(S4, S5)
S'6 = AESRound(S5, S6)
S'7 = AESRound(S6, S7)

S0  = S'0
S1  = S'1
S2  = S'2
S3  = S'3
S4  = S'4
S5  = S'5
S6  = S'6
S7  = S'7
~~~

## The Enc Function

~~~
Enc(xi)
~~~

The `Enc` function encrypts a 256-bit input block `xi` using the state `{S0, ...S7}`.

Inputs:

- `xi`: the 256-bit input block.

Outputs:

- `ci`: the 256-bit encrypted block.

Steps:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(xi, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(t0, t1)
ci = out0 || out1

return ci
~~~

## The Dec Function

~~~
Dec(ci)
~~~

The `Dec` function decrypts a 256-bit input block `ci` using the state `{S0, ...S7}`.

Inputs:

- `ci`: the 256-bit encrypted block.

Outputs:

- `xi`: the 256-bit decrypted block.

Steps:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(ci, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(out0, out1)
xi = out0 || out1

return xi
~~~

## The DecPartial Function

~~~
DecPartial(cn)
~~~

The `DecPartial` function decrypts the last ciphertext bits `cn` using the state `{S0, ...S7}` when they do not fill an entire block.

Inputs:

- `cn`: the encrypted input.

Outputs:

- `xn`: the decryption of `cn`.

Steps:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(Pad(cn, 256), 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

xn = Truncate(out0 || out1, |cn|)

v0, v1 = Split(Pad(xn, 256), 128)
Update(v0, v1)

return xn
~~~

## The Finalize Function

~~~
Finalize(ad_len, msg_len)
~~~

The `Finalize` function computes a 128-bit tag that authenticates the message and associated data.

Inputs:

- `ad_len`: the length of the associated data in bits.
- `msg_len`: the length of the message in bits.

Outputs:

- `tag`: the authentication tag.

Steps:

~~~
t = S2 ^ (LE64(ad_len) || LE64(msg_len))

Repeat(7, Update(t, t))

tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6

return tag
~~~

# The AEGIS-256 Algorithm

AEGIS-256 has a 768-bit state, made of six 128-bit blocks `{S0, ...S5}`.

The parameters for this algorithm, whose meaning is defined in {{!RFC5116, Section 4}} are:

- `K_LEN` (key length) is 32 octets.
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> octets.
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> octets.
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 32 octets.
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 octets.

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} shall be unambiguously encoded as a single input.
It is up to the application to create a structure in the associated data input if needed.

## Authenticated Encryption

~~~
Encrypt(msg, ad, key, nonce)
~~~

The `Encrypt` function encrypts a message and returns the ciphertext along with an authentication tag that verifies the authenticity of the message and associated data, if provided.

Security:
- The nonce MUST NOT be reused under any circumstances; doing so allows an attacker to recover the internal state.
- The key MUST be randomly chosen from a uniform distribution.

Inputs:

- `msg`: the message to be encrypted.
- `ad`: the associated data to authenticate.
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- `ct`: the ciphertext.
- `tag`: the authentication tag.

Steps:

~~~
Init(key, nonce)

ct = {}

ad_blocks = Split(Pad(ad, 128), 128)
for xi in ad_blocks:
    Enc(xi)

msg_blocks = Split(Pad(msg, 128), 128)
for xi in msg_blocks:
    ct = ct || Enc(xi)

tag = Finalize(|ad|, |msg|)
ct = Truncate(ct, |msg|)

return ct and tag
~~~

## Authenticated Decryption

~~~
Decrypt(ct, tag, ad, key, nonce)
~~~

The `Decrypt` function decrypts a ciphertext, verifies that the authentication tag is correct, and returns the message on success or an error if tag verification failed.

Security:
- If tag verification fails, the decrypted message and wrong message authentication tag MUST NOT be given as output. The decrypted message MUST be overwritten with zeros.
- The comparison of the input `tag` with the `expected_tag` SHOULD be done in constant time.

Inputs:

- `ct`: the ciphertext to be decrypted.
- `tag`: the authentication tag.
- `ad`: the associated data to authenticate.
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- Either the decrypted message `msg`, or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
Init(key, nonce)

msg = {}

ad_blocks = Split(Pad(ad, 128), 128)
for xi in ad_blocks:
    Enc(xi)

ct_blocks = Split(Pad(ct, 128), 128)
cn = Tail(ct, |ct| mod 128)

for ci in ct_blocks:
    msg = msg || Dec(ci)

if cn is not empty:
    msg = msg || DecPartial(cn)

expected_tag = Finalize(|ad|, |msg|)

if CtEq(tag, expected_tag) is False:
    erase msg
    return "verification failed" error
else:
    return msg
~~~

## The Init Function

~~~
Init(key, nonce)
~~~

The `Init` function constructs the initial state `{S0, ...S5}` using the given `key` and `nonce`.

Inputs:

- `key`: the encryption key.
- `nonce`: the nonce.

Defines:

- `{S0, ...S5}`: the initial state.

Steps:

~~~
k0, k1 = Split(key, 128)
n0, n1 = Split(nonce, 128)

S0 = k0 ^ n0
S1 = k1 ^ n1
S2 = C1
S3 = C0
S4 = k0 ^ C0
S5 = k1 ^ C1

Repeat(4,
  Update(k0)
  Update(k1)
  Update(k0 ^ n0)
  Update(k1 ^ n1)
)
~~~

## The Update Function

~~~
Update(M)
~~~

The `Update` function is the core of the AEGIS-256 algorithm.
It updates the state `{S0, ...S5}` using a 128-bit value.

Inputs:

- `msg`: the block to be absorbed.

Modifies:

- `{S0, ...S5}`: the state.

Steps:

~~~
S'0 = AESRound(S5, S0 ^ M)
S'1 = AESRound(S0, S1)
S'2 = AESRound(S1, S2)
S'3 = AESRound(S2, S3)
S'4 = AESRound(S3, S4)
S'5 = AESRound(S4, S5)

S0  = S'0
S1  = S'1
S2  = S'2
S3  = S'3
S4  = S'4
S5  = S'5
~~~

## The Enc Function

~~~
Enc(xi)
~~~

The `Enc` function encrypts a 128-bit input block `xi` using the state `{S0, ...S5}`.

Inputs:

- `xi`: the input block.

Outputs:

- `ci`: the encrypted input block.

Steps:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)

Update(xi)

ci = xi ^ z

return ci
~~~

## The Dec Function

~~~
Dec(ci)
~~~

The `Dec` function decrypts a 128-bit input block `ci` using the state `{S0, ...S5}`.

Inputs:

- `ci`: the encrypted input block.

Outputs:

- `xi`: the decrypted block.

Steps:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)

xi = ci ^ z

Update(xi)

return xi
~~~

It returns the 128-bit block `out`.

## The DecPartial Function

~~~
DecPartial(cn)
~~~

The `DecPartial` function decrypts the last ciphertext bits `cn` using the state `{S0, ...S5}` when they do not fill an entire block.

Inputs:

- `cn`: the encrypted input.

Outputs:

- `xn`: the decryption of `cn`.

Steps:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)

t = Pad(ci, 128)
out = t ^ z

xn = Truncate(out, |cn|)

v = Pad(xn, 128)
Update(v)

return xn
~~~

## The Finalize Function

~~~
Finalize(ad_len, msg_len)
~~~

The `Finalize` function computes a 128-bit tag that authenticates the message and associated data.

Inputs:

- `ad_len`: the length of the associated data in bits.
- `msg_len`: the length of the message in bits.

Outputs:

- `tag`: the authentication tag.

Steps:

~~~
t = S3 ^ (LE64(ad_len) || LE64(msg_len))

Repeat(7, Update(t))

tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5

return tag
~~~

# Encoding (ct, tag) Tuples

Applications MAY keep the ciphertext and the 128-bit authentication tag in distinct structures or encode both as a single string.

In the latter case, the tag MUST immediately follow the ciphertext:

~~~
combined_ct = ct || tag
~~~

# Security Considerations

AEGIS-256 offers 256-bit message security against plaintext and state recovery. AEGIS-128L offers 128-bit security. They are both key-committing, the implications of which are outlined in the introduction. However, neither is compactly-committing because a 128-bit tag is too short to be collision resistant. This means it is still possible for a ciphertext to be successfully decrypted under multiple different keys, just significantly more difficult than for AEAD schemes lacking key commitment.

Under the assumption that the secret key is unknown to the attacker and the tag is not truncated, both AEGIS-128L and AEGIS-256 target 128-bit security against forgery attacks.

Both algorithms MUST be used in a nonce-respecting setting: for a given `key`, a `nonce` MUST only be used once. Failure to do so would immediately reveal the bitwise difference between two messages.

If tag verification fails, the decrypted message and wrong message authentication tag MUST NOT be given as output. As shown in the analysis of the (robustness of CAESAR candidates beyond their guarantees){{CRA18}}, even a partial leak of the plaintext without verification would facilitate chosen ciphertext attacks.

Every key MUST be randomly chosen from a uniform distribution.

The nonce MAY be public or predictable. It can be a counter, the output of a permutation, or a generator with a long period.

With AEGIS-128L, random nonces can safely encrypt up to 2<sup>48</sup> messages using the same key with negligible collision probability.

With AEGIS-256, random nonces can be used with no practical limits.

The security of AEGIS against timing attacks is limited by the implementation of the underlying `AESRound()` function. Failure to implement `AESRound()` in a fashion safe against side-channel attacks, such as differential power analysis or timing attacks, may lead to leakage of secret key material or state information. The exact mitigations required for side-channel attacks also depend on the threat model in question.

A security analysis of AEGIS can be found in Chapter 4 of {{AEGIS}}.

# IANA Considerations

IANA is requested to assign entries for `AEAD_AEGIS128L` and `AEAD_AEGIS256` in the AEAD Registry with this document as reference.

--- back

# Test Vectors

## AESRound Test Vector

~~~
in   : 000102030405060708090a0b0c0d0e0f

rk   : 101112131415161718191a1b1c1d1e1f

out  : 7a7b4e5638782546a8c0477a3b813f43
~~~

## AEGIS-128L Test Vectors

### Update Test Vector

~~~
S0   : 9b7e60b24cc873ea894ecc07911049a3
S1   : 330be08f35300faa2ebf9a7b0d274658
S2   : 7bbd5bd2b049f7b9b515cf26fbe7756c
S3   : c35a00f55ea86c3886ec5e928f87db18
S4   : 9ebccafce87cab446396c4334592c91f
S5   : 58d83e31f256371e60fc6bb257114601
S6   : 1639b56ea322c88568a176585bc915de
S7   : 640818ffb57dc0fbc2e72ae93457e39a

M0   : 033e6975b94816879e42917650955aa0
M1   : 033e6975b94816879e42917650955aa0

After Update:
S0   : 596ab773e4433ca0127c73f60536769d
S1   : 790394041a3d26ab697bde865014652d
S2   : 38cf49e4b65248acd533041b64dd0611
S3   : 16d8e58748f437bfff1797f780337cee
S4   : 69761320f7dd738b281cc9f335ac2f5a
S5   : a21746bb193a569e331e1aa985d0d729
S6   : 09d714e6fcf9177a8ed1cde7e3d259a6
S7   : 61279ba73167f0ab76f0a11bf203bdff
~~~

### Test Vector 1

~~~
key  : 00000000000000000000000000000000

nonce: 00000000000000000000000000000000

ad   :

msg  : 00000000000000000000000000000000

ct   : 41de9000a7b5e40e2d68bb64d99ebb19

tag  : f4d997cc9b94227ada4fe4165422b1c8
~~~

### Test Vector 2

~~~
key  : 00000000000000000000000000000000

nonce: 00000000000000000000000000000000

ad   :

msg  :

ct   :

tag  : 83cc600dc4e3e7e62d4055826174f149
~~~

### Test Vector 3

~~~
key  : 10010000000000000000000000000000

nonce: 10000200000000000000000000000000

ad   : 0001020304050607

msg  : 000102030405060708090a0b0c0d0e0f
       101112131415161718191a1b1c1d1e1f

ct   : 79d94593d8c2119d7e8fd9b8fc77845c
       5c077a05b2528b6ac54b563aed8efe84

tag  : cc6f3372f6aa1bb82388d695c3962d9a
~~~

### Test Vector 4

~~~
key  : 10010000000000000000000000000000

nonce: 10000200000000000000000000000000

ad   : 0001020304050607

msg  : 000102030405060708090a0b0c0d

ct   : 79d94593d8c2119d7e8fd9b8fc77

tag  : 5c04b3dba849b2701effbe32c7f0fab7
~~~

### Test Vector 5

This test MUST return a "verification failed" error.

~~~
key  : 10000200000000000000000000000000

nonce: 10010000000000000000000000000000

ad   : 0001020304050607

msg  : 

ct   : 79d94593d8c2119d7e8fd9b8fc77

tag  : 5c04b3dba849b2701effbe32c7f0fab7
~~~

### Test Vector 6

This test MUST return a "verification failed" error.

~~~
key  : 10010000000000000000000000000000

nonce: 10000200000000000000000000000000

ad   : 0001020304050607

msg  : 

ct   : 79d94593d8c2119d7e8fd9b8fc78

tag  : 5c04b3dba849b2701effbe32c7f0fab7
~~~

### Test Vector 7

This test MUST return a "verification failed" error.

~~~
key  : 10010000000000000000000000000000

nonce: 10000200000000000000000000000000

ad   : 0001020304050608

msg  : 

ct   : 79d94593d8c2119d7e8fd9b8fc77

tag  : 5c04b3dba849b2701effbe32c7f0fab7
~~~

### Test Vector 8

This test MUST return a "verification failed" error.

~~~
key  : 10010000000000000000000000000000

nonce: 10000200000000000000000000000000

ad   : 0001020304050607

msg  : 

ct   : 79d94593d8c2119d7e8fd9b8fc77

tag  : 6c04b3dba849b2701effbe32c7f0fab8
~~~

## AEGIS-256 Test Vectors

### Update Test Vector

~~~
S0   : 1fa1207ed76c86f2c4bb40e8b395b43e
S1   : b44c375e6c1e1978db64bcd12e9e332f
S2   : 0dab84bfa9f0226432ff630f233d4e5b
S3   : d7ef65c9b93e8ee60c75161407b066e7
S4   : a760bb3da073fbd92bdc24734b1f56fb
S5   : a828a18d6a964497ac6e7e53c5f55c73

M    : b165617ed04ab738afb2612c6d18a1ec

After Update:
S0   : e6bc643bae82dfa3d991b1b323839dcd
S1   : 648578232ba0f2f0a3677f617dc052c3
S2   : ea788e0e572044a46059212dd007a789
S3   : 2f1498ae19b80da13fba698f088a8590
S4   : a54c2ee95e8c2a2c3dae2ec743ae6b86
S5   : a3240fceb68e32d5d114df1b5363ab67
~~~

### Test Vector 1

~~~
key  : 00000000000000000000000000000000
       00000000000000000000000000000000

nonce: 00000000000000000000000000000000
       00000000000000000000000000000000

ad   :

msg  : 00000000000000000000000000000000

ct   : b98f03a947807713d75a4fff9fc277a6

tag  : 478f3b50dc478ef7d5cf2d0f7cc13180
~~~

### Test Vector 2

~~~
key  : 00000000000000000000000000000000
       00000000000000000000000000000000

nonce: 00000000000000000000000000000000
       00000000000000000000000000000000

ad   :

msg  :

ct   :

tag  : f7a0878f68bd083e8065354071fc27c3
~~~

### Test Vector 3

~~~
key  : 10010000000000000000000000000000
       00000000000000000000000000000000

nonce: 10000200000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050607

msg  : 000102030405060708090a0b0c0d0e0f
       101112131415161718191a1b1c1d1e1f

ct   : f373079ed84b2709faee373584585d60
       accd191db310ef5d8b11833df9dec711

tag  : 8d86f91ee606e9ff26a01b64ccbdd91d
~~~

### Test Vector 4

~~~
key  : 10010000000000000000000000000000
       00000000000000000000000000000000

nonce: 10000200000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050607

msg  : 000102030405060708090a0b0c0d

ct   : f373079ed84b2709faee37358458

tag  : c60b9c2d33ceb058f96e6dd03c215652
~~~

### Test Vector 5

This test MUST return a "verification failed" error.

~~~
key  : 10000200000000000000000000000000
       00000000000000000000000000000000

nonce: 10010000000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050607

msg  : 

ct   : f373079ed84b2709faee37358458

tag  : c60b9c2d33ceb058f96e6dd03c215652
~~~

### Test Vector 6

This test MUST return a "verification failed" error.

~~~
key  : 10010000000000000000000000000000
       00000000000000000000000000000000

nonce: 10000200000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050607

msg  : 

ct   : f373079ed84b2709faee37358459

tag  : c60b9c2d33ceb058f96e6dd03c215652
~~~

### Test Vector 7

This test MUST return a "verification failed" error.

~~~
key  : 10010000000000000000000000000000
       00000000000000000000000000000000

nonce: 10000200000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050608

msg  : 

ct   : f373079ed84b2709faee37358458

tag  : c60b9c2d33ceb058f96e6dd03c215652
~~~

### Test Vector 8

This test MUST return a "verification failed" error.

~~~
key  : 10010000000000000000000000000000
       00000000000000000000000000000000

nonce: 10000200000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050607

msg  : 

ct   : f373079ed84b2709faee37358458

tag  : d60b9c2d33ceb058f96e6dd03c215653
~~~

# Acknowledgments
{:numbered="false"}

The AEGIS authenticated encryption algorithm was invented by Hongjun Wu and Bart Preneel.

The round function leverages the AES permutation invented by Joan Daemen and Vincent Rijmen. They also authored the Pelican MAC that partly motivated the design of the AEGIS MAC.

We would like to thank Eric Lagergren and Daniel Bleichenbacher for catching a broken test vector and Daniel Bleichenbacher for many helpful suggestions.

---
title: "The AEGIS Family of Authenticated Encryption Algorithms"
docname: draft-irtf-cfrg-aegis-aead-latest
category: info

ipr: trust200902
keyword: Internet-Draft
workgroup: Crypto Forum
submissionType: IRTF

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Frank Denis
    organization: Fastly Inc.
    email: fde@00f.net
 -
    name: Samuel Lucas
    organization: Individual Contributor
    email: samuel-lucas6@pm.me

informative:

  AEGIS:
    title: "AEGIS: A Fast Authenticated Encryption Algorithm (v1.1)"
    venue: CAESAR Competition
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
    date: 2016

  BS23:
    title: "Single-query Quantum Hidden Shift Attacks"
    rc: "Cryptology ePrint Archive, Paper 2023/1306"
    target: https://eprint.iacr.org/2023/1306
    author:
      -
        ins: X. Bonnetain
        name: Xavier Bonnetain
        org: Université de Lorraine, CNRS, Inria, LORIA
      -
        ins: A. Schrottenloher
        name: André Schrottenloher
        org: Université de Rennes, CNRS, Inria, IRISA
    date: 2023

  D23:
    title: "Adding more parallelism to the AEGIS authenticated encryption algorithms"
    rc: "Cryptology ePrint Archive, Paper 2023/523"
    target: https://eprint.iacr.org/2023/523
    author:
      -
        ins: F. Denis
        name: Frank Denis
        org: Fastly Inc.
    date: 2023

  ENP19:
    title: "Analyzing the Linear Keystream Biases in AEGIS"
    rc: "IACR Transactions on Symmetric Cryptology, 2019(4), pp. 348–368"
    seriesinfo:
      DOI: 10.13154/tosc.v2019.i4.348-368
    author:
      -
        ins: M. Eichlseder
        name: Maria Eichlseder
        org: Graz University of Technology
      -
        ins: M. Nageler
        name: Marcel Nageler
        org: Graz University of Technology
      -
        ins: R. Primas
        name: Robert Primas
        org: Graz University of Technology
    date: 2020

  IR23:
    title: "Key Committing Security Analysis of AEGIS"
    rc: "Cryptology ePrint Archive, Paper 2023/1495"
    target: https://eprint.iacr.org/2023/1495
    author:
      -
        ins: T. Isobe
        name: Takanori Isobe
        org: University of Hyogo
      -
        ins: M. Rahman
        name: Mostafizar Rahman
        org: University of Hyogo
    date: 2023

  JLD21:
    title: "Guess-and-Determine Attacks on AEGIS"
    rc: "The Computer Journal, vol 65, 2022(8), pp. 2221–2230"
    seriesinfo:
      DOI: 10.1093/comjnl/bxab059
    author:
      -
        ins: L. Jiao
        name: Lin Jiao
        org: State Key Laboratory of Cryptology
      -
        ins: Y. Li
        name: Yongqiang Li
        org: State Key Laboratory of Information Security, Institute of Information Engineering, Chinese Academy of Sciences; School of Cyber Security, University of Chinese Academy of Sciences
      -
        ins: S. Du
        name: Shaoyu Du
        org: State Key Laboratory of Cryptology
    date: 2021

  LGR21:
    title: "Partitioning Oracle Attacks"
    rc: "30th USENIX Security Symposium (USENIX Security 21), pp. 195–212"
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

  LIMS21:
    title: "Weak Keys in Reduced AEGIS and Tiaoxin"
    rc: "IACR Transactions on Symmetric Cryptology, 2021(2), pp. 104–139"
    seriesinfo:
      DOI: 10.46586/tosc.v2021.i2.104-139
    author:
      -
        ins: F. Liu
        name: Fukang Liu
        org: East China Normal University; University of Hyogo
      -
        ins: T. Isobe
        name: Takanori Isobe
        org: University of Hyogo; National Institute of Information and Communications Technology; PRESTO, Japan Science and Technology Agency
      -
        ins: W. Meier
        name: Willi Meier
        org: University of Applied Sciences and Arts Northwestern Switzerland
      -
        ins: K. Sakamoto
        name: Kosei Sakamoto
        org: University of Hyogo
    date: 2021

  M14:
    title: "Linear Biases in AEGIS Keystream"
    rc: "Selected Areas in Cryptography. SAC 2014. Lecture Notes in Computer Science, vol 8781, pp. 290–305"
    seriesinfo:
      DOI: 10.1007/978-3-319-13051-4_18
    author:
      -
        ins: B. Minaud
        name: Brice Minaud
        org: ANSSI
    date: 2014

  STSI23:
    title: "MILP-based security evaluation for AEGIS/Tiaoxin-346/Rocca"
    rc: "IET Information Security, vol 17, 2023(3), pp. 458-467"
    seriesinfo:
      DOI: 10.1049/ise2.12109
    author:
      -
        ins: T. Shiraya
        name: Takuro Shiraya
        org: University of Hyogo
      -
        ins: N. Takeuchi
        name: Nobuyuki Takeuchi
        org: University of Hyogo
      -
        ins: K. Sakamoto
        name: Kosei Sakamoto
        org: University of Hyogo
      -
        ins: T. Isobe
        name: Takanori Isobe
        org: University of Hyogo; National Institute of Information and Communications Technology
    date: 2023

  VV18:
    title: "Can Caesar Beat Galois?"
    rc: "Applied Cryptography and Network Security. ACNS 2018. Lecture Notes in Computer Science, vol 10892, pp. 476–494"
    seriesinfo:
      DOI: 10.1007/978-3-319-93387-0_25
    author:
      -
        ins: S. Vaudenay
        name: Serge Vaudenay
        org: EPFL
      -
        ins: D. Vizár
        name: Damian Vizár
        org: EPFL
    date: 2018

--- abstract

This document describes the AEGIS-128L, AEGIS-256, AEGIS-128X, and AEGIS-256X AES-based authenticated encryption algorithms designed for high-performance applications.

The document is a product of the Crypto Forum Research Group (CFRG). It is not an IETF product and is not a standard.


--- middle

# Introduction

This document describes the AEGIS family of authenticated encryption with associated data (AEAD) algorithms {{AEGIS}}, which were chosen as additional finalists for high-performance applications in the Competition for Authenticated Encryption: Security, Applicability, and Robustness (CAESAR). Whilst AEGIS-128 was selected as a winner for this use case, AEGIS-128L has a better security margin alongside improved performance and AEGIS-256 uses a 256-bit key {{LIMS21}}. All variants of AEGIS are constructed from the AES encryption round function {{!FIPS-AES=FIPS.197.2001}}. This document specifies:

- AEGIS-128L, which has a 128-bit key, a 128-bit nonce, a 1024-bit state, a 128- or 256-bit authentication tag, and processes 256-bit input blocks.
- AEGIS-256, which has a 256-bit key, a 256-bit nonce, a 768-bit state, a 128- or 256-bit authentication tag, and processes 128-bit input blocks.
- AEGIS-128X, which is a mode based on AEGIS-128L, specialized for CPUs with large vector registers and vector AES instructions.
- AEGIS-256X, which is a mode based on AEGIS-256, specialized for CPUs with large vector registers and vector AES instructions.

The AEGIS cipher family offers performance that significantly exceeds that of AES-GCM with hardware support for parallelizable AES block encryption {{AEGIS}}. Similarly, software implementations can also be faster, although to a lesser extent.

Unlike with AES-GCM, nonces can be safely chosen at random with no practical limit when using AEGIS-256 and AEGIS-256X. AEGIS-128L and AEGIS-128X also allow for more messages to be safely encrypted when using random nonces.

With some existing AEAD schemes, such as AES-GCM, an attacker can generate a ciphertext that successfully decrypts under multiple different keys (a partitioning oracle attack) {{LGR21}}. This ability to craft a (ciphertext, authentication tag) pair that verifies under multiple keys significantly reduces the number of required interactions with the oracle in order to perform an exhaustive search, making it practical if the key space is small. For example, with password-based encryption, an attacker can guess a large number of passwords at a time by recursively submitting such a ciphertext to an oracle, which speeds up a password search by reducing it to a binary search.

In AEGIS, finding distinct (key, nonce) pairs that successfully decrypt a given (associated data, ciphertext, authentication tag) tuple is believed to have a complexity that depends on the tag size. A 128-bit tag provides 64-bit committing security, which is generally acceptable for interactive protocols. With a 256-bit tag, finding a collision becomes impractical.

Unlike most other AES-based AEAD constructions, leaking a state does not leak the key nor previous states.

Finally, an AEGIS key is not required after the setup phase, and there is no key schedule. Thus, ephemeral keys can be erased from memory before any data has been encrypted or decrypted, mitigating cold boot attacks.

Note that an earlier version of Hongjun Wu and Bart Preneel's paper introducing AEGIS specified AEGIS-128L and AEGIS-256 sporting differences with regards to the computation of the authentication tag and the number of rounds in the `Finalize()` function. We follow the specification of {{AEGIS}}, which can be found in the References section of this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Throughout this document, "byte" is used instead of "octet" and refers to an 8-bit sequence.

Primitives:

- `{}`: an empty bit array.
- `|x|`: the length of `x` in bits.
- `a ^ b`: the bitwise exclusive OR operation between `a` and `b`.
- `a & b`: the bitwise AND operation between `a` and `b`.
- `a || b`: the concatenation of `a` and `b`.
- `a mod b`: the remainder of the Euclidean division between `a` as the dividend and `b` as the divisor.
- `LE64(x)`: the little-endian encoding of unsigned 64-bit integer `x`.
- `ZeroPad(x, n)`: padding operation. Trailing zeros are concatenated to `x` until the total length is a multiple of `n` bits.
- `Truncate(x, n)`: truncation operation. The first `n` bits of `x` are kept.
- `Split(x, n)`: splitting operation. `x` is split into `n`-bit blocks, ignoring partial blocks.
- `Tail(x, n)`: returns the last `n` bits of `x`.
- `AESRound(in, rk)`: a single round of the AES encryption round function, which is the composition of the `SubBytes`, `ShiftRows`, `MixColums` and `AddRoundKey` transformations, as defined in section 5 of {{FIPS-AES}}. Here, `in` is the 128-bit AES input state, and `rk` is the 128-bit round key.
- `Repeat(n, F)`: `n` sequential evaluations of the function `F`.
- `CtEq(a, b)`: compares `a` and `b` in constant-time, returning `True` for an exact match, `False` otherwise.

AEGIS internal functions:

- `Update(M0, M1)` or `Update(M)`: the state update function.
- `Init(key, nonce)`: the initialization function.
- `Absorb(ai)`: the input block absorption function.
- `Enc(xi)`: the input block encryption function.
- `Dec(ci)`: the input block decryption function.
- `DecPartial(cn)`: the input block decryption function for the last ciphertext bits when they do not fill an entire block.
- `Finalize(ad_len_bits, msg_len_bits)`: the authentication tag generation function.

Input blocks are 256 bits for AEGIS-128L and 128 bits for AEGIS-256.

AES blocks:

- `Si`: the `i`-th AES block of the current state.
- `S'i`: the `i`-th AES block of the next state.
- `{Si, ...Sj}`: the vector of the `i`-th AES block of the current state to the `j`-th block of the current state.
- `C0`: an AES block built from the following bytes in hexadecimal format: `{ 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }`.
- `C1`: an AES block built from the following bytes in hexadecimal format: `{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }`.

AES blocks are always 128 bits in length.

Input and output values:

- `key`: the encryption key (128 bits for AEGIS-128L, 256 bits for AEGIS-256).
- `nonce`: the public nonce (128 bits for AEGIS-128L, 256 bits for AEGIS-256).
- `ad`: the associated data.
- `msg`: the plaintext.
- `ct`: the ciphertext.
- `tag`: the authentication tag (128 or 256 bits).

# The AEGIS-128L Algorithm

AEGIS-128L has a 1024-bit state, made of eight 128-bit blocks `{S0, ...S7}`.

The parameters for this algorithm, whose meaning is defined in {{!RFC5116, Section 4}} are:

- `K_LEN` (key length) is 16 bytes (128 bits).
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> bytes (2<sup>64</sup> bits).
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> bytes (2<sup>64</sup> bits).
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 16 bytes (128 bits).
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 or 32 bytes (2<sup>64</sup> + 128 or 256 bits).

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} shall be unambiguously encoded as a single input.
It is up to the application to create a structure in the associated data input if needed.

## Authenticated Encryption

~~~
Encrypt(msg, ad, key, nonce)
~~~

The `Encrypt` function encrypts a message and returns the ciphertext along with an authentication tag that verifies the authenticity of the message and associated data, if provided.

Security:

- For a given key, the nonce MUST NOT be reused under any circumstances; doing so allows an attacker to recover the internal state.
- The key MUST be randomly chosen from a uniform distribution.

Inputs:

- `msg`: the message to be encrypted (length MUST be less than `P_MAX`).
- `ad`: the associated data to authenticate (length MUST be less than `A_MAX`).
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- `ct`: the ciphertext.
- `tag`: the authentication tag.

Steps:

~~~
Init(key, nonce)

ct = {}

ad_blocks = Split(ZeroPad(ad, 256), 256)
for ai in ad_blocks:
    Absorb(ai)

msg_blocks = Split(ZeroPad(msg, 256), 256)
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
- The comparison of the input `tag` with the `expected_tag` MUST be done in constant time.

Inputs:

- `ct`: the ciphertext to be decrypted (length MUST be less than `C_MAX`).
- `tag`: the authentication tag.
- `ad`: the associated data to authenticate (length MUST be less than `A_MAX`).
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- Either the decrypted message `msg` or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
Init(key, nonce)

msg = {}

ad_blocks = Split(ZeroPad(ad, 256), 256)
for ai in ad_blocks:
    Absorb(ai)

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
- `nonce`: the public nonce.

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

## The Absorb Function

~~~
Absorb(ai)
~~~

The `Absorb` function absorbs a 256-bit input block `ai` into the state `{S0, ...S7}`.

Inputs:

- `ai`: the 256-bit input block.

Steps:

~~~
t0, t1 = Split(ai, 128)
Update(t0, t1)
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

t0, t1 = Split(ZeroPad(cn, 256), 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

xn = Truncate(out0 || out1, |cn|)

v0, v1 = Split(ZeroPad(xn, 256), 128)
Update(v0, v1)

return xn
~~~

## The Finalize Function

~~~
Finalize(ad_len_bits, msg_len_bits)
~~~

The `Finalize` function computes a 128- or 256-bit tag that authenticates the message and associated data.

Inputs:

- `ad_len_bits`: the length of the associated data in bits.
- `msg_len_bits`: the length of the message in bits.

Outputs:

- `tag`: the authentication tag.

Steps:

~~~
t = S2 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))

Repeat(7, Update(t, t))

if tag_length == 16: # 128 bits
    tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
else:                # 256 bits
    tag = (S0 ^ S1 ^ S2 ^ S3) || (S4 ^ S5 ^ S6 ^ S7)

return tag
~~~

# The AEGIS-256 Algorithm

AEGIS-256 has a 768-bit state, made of six 128-bit blocks `{S0, ...S5}`.

The parameters for this algorithm, whose meaning is defined in {{!RFC5116, Section 4}} are:

- `K_LEN` (key length) is 32 bytes (256 bits).
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> bytes (2<sup>64</sup> bits).
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> bytes (2<sup>64</sup> bits).
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 32 bytes (256 bits).
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 or 32 bytes (2<sup>64</sup> + 128 or 256 bits).

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} shall be unambiguously encoded as a single input.
It is up to the application to create a structure in the associated data input if needed.

## Authenticated Encryption

~~~
Encrypt(msg, ad, key, nonce)
~~~

The `Encrypt` function encrypts a message and returns the ciphertext along with an authentication tag that verifies the authenticity of the message and associated data, if provided.

Security:

- For a given key, the nonce MUST NOT be reused under any circumstances; doing so allows an attacker to recover the internal state.
- The key MUST be randomly chosen from a uniform distribution.

Inputs:

- `msg`: the message to be encrypted (length MUST be less than `P_MAX`).
- `ad`: the associated data to authenticate (length MUST be less than `A_MAX`).
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- `ct`: the ciphertext.
- `tag`: the authentication tag.

Steps:

~~~
Init(key, nonce)

ct = {}

ad_blocks = Split(ZeroPad(ad, 128), 128)
for ai in ad_blocks:
    Absorb(ai)

msg_blocks = Split(ZeroPad(msg, 128), 128)
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
- The comparison of the input `tag` with the `expected_tag` MUST be done in constant time.

Inputs:

- `ct`: the ciphertext to be decrypted (length MUST be less than `C_MAX`).
- `tag`: the authentication tag.
- `ad`: the associated data to authenticate (length MUST be less than `A_MAX`).
- `key`: the encryption key.
- `nonce`: the public nonce.

Outputs:

- Either the decrypted message `msg` or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
Init(key, nonce)

msg = {}

ad_blocks = Split(ZeroPad(ad, 128), 128)
for ai in ad_blocks:
    Absorb(ai)

ct_blocks = Split(ZeroPad(ct, 128), 128)
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
- `nonce`: the public nonce.

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

## The Absorb Function

~~~
Absorb(ai)
~~~

The `Absorb` function absorbs a 128-bit input block `ai` into the state `{S0, ...S5}`.

Inputs:

- `ai`: the input block.

Steps:

~~~
Update(ai)
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

t = ZeroPad(cn, 128)
out = t ^ z

xn = Truncate(out, |cn|)

v = ZeroPad(xn, 128)
Update(v)

return xn
~~~

## The Finalize Function

~~~
Finalize(ad_len_bits, msg_len_bits)
~~~

The `Finalize` function computes a 128- or 256-bit tag that authenticates the message and associated data.

Inputs:

- `ad_len_bits`: the length of the associated data in bits.
- `msg_len_bits`: the length of the message in bits.

Outputs:

- `tag`: the authentication tag.

Steps:

~~~
t = S3 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))

Repeat(7, Update(t))

if tag_length == 16: # 128 bits
    tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
else:                # 256 bits
    tag = (S0 ^ S1 ^ S2) || (S3 ^ S4 ^ S5)

return tag
~~~

# Parallel Modes

Some CPUs, such as Intel and Intel-compatible CPUs with the VAES extensions, include instructions to efficiently apply the AES round function to a vector of AES blocks.

AEGIS-128X and AEGIS-256X are optional, specialized modes designed to take advantage of these instructions. They share the same properties as the ciphers they are based on but can be significantly faster on these platforms, even for short messages.

AEGIS-128X and AEGIS-256X are parallel evaluations of multiple AEGIS-128L and AEGIS-256 instances respectively, with distinct initial states. On CPUs with wide vector registers, different states can be stored in different 128-bit lanes of the same vector register, allowing parallel updates using vector instructions.

The modes are parameterized by the parallelism degree. With 256-bit registers, 2 parallel operations can be applied to 128-bit AES blocks. With 512-bit registers, the number of instances can be raised to 4.

The state of a parallel mode is represented as a vector of AEGIS-128L or AEGIS-256 states.

## Additional Conventions and Definitions

- `D`: the degree of parallelism.
- `R`: the absorption and output rate of the mode. With AEGIS-128X, the rate is `2 * 128 * D` bits. With AEGIS-256X, the rate is `128 * D` bits.
- `V[j,i]`: the `j`-th AES block of the `i`-th state. `i` is in the `[0..D)` range. For AEGIS-128X, `j` is in the `[0..8)` range, while for AEGIS-256, `j` is in the `[0..6)` range.
- `V'[j,i]`: the `j`-th AES block of the next `i`-th state.
- `ctx[i]`: the `i`-th context separator. This is a 128-bit mask, made of a byte representing the state index, followed by a byte representing the highest index and 112 all-zero bits.
- `Byte(x)`: the value `x` encoded as 8 bits.

## Authenticated Encryption

~~~
Encrypt(msg, ad, key, nonce)
~~~

The `Encrypt` function of AEGIS-128X resembles that of AEGIS-128L, and similarly, the `Encrypt` function of AEGIS-256X mirrors that of AEGIS-256, but processes `R`-bit input blocks per update.

Steps:

~~~
Init(key, nonce)

ct = {}

ad_blocks = Split(ZeroPad(ad, R), R)
for ai in ad_blocks:
    Absorb(ai)

msg_blocks = Split(ZeroPad(msg, R), R)
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

The `Decrypt` function of AEGIS-128X resembles that of AEGIS-128L, and similarly, the `Decrypt` function of AEGIS-256X mirrors that of AEGIS-256, but processes `R`-bit input blocks per update.

Steps:

~~~
Init(key, nonce)

msg = {}

ad_blocks = Split(ZeroPad(ad, R), R)
for ai in ad_blocks:
    Absorb(ai)

ct_blocks = Split(ct, R)
cn = Tail(ct, |ct| mod R)

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

## AEGIS-128X

### The Init Function

~~~
Init(key, nonce)
~~~

The `Init` function initializes a vector of `D` AEGIS-128L states with the same `key` and `nonce` but a different context `ctx[i]`. The context is added to the state before every update.

Steps:

~~~
for i in 0..D:
    V[0,i] = key ^ nonce
    V[1,i] = C1
    V[2,i] = C0
    V[3,i] = C1
    V[4,i] = key ^ nonce
    V[5,i] = key ^ C0
    V[6,i] = key ^ C1
    V[7,i] = key ^ C0

nonce_v = {}
key_v = {}
for i in 0..D:
    nonce_v = nonce_v || nonce
    key_v = key_v || key

Repeat(10,
    for i in 0..D:
        ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128)
        V[3,i] = V[3,i] ^ ctx[i]
        V[7,i] = V[7,i] ^ ctx[i]

    Update(nonce_v, key_v)
)
~~~

### The Update Function

~~~
Update(M0, M1)
~~~

The AEGIS-128X `Update` function is similar to the AEGIS-128L `Update` function, but absorbs `R` (`2 * 128 * D`) bits at once. `M0` and `M1` are `128 * D` bits instead of 128 bits but are split into 128-bit blocks, each of them updating a different AEGIS-128L state.

Steps:

~~~
m0 = Split(M0, 128)
m1 = Split(M1, 128)

for i in 0..D:
    V'[0,i] = AESRound(V[7,i], V[0,i] ^ m0[i])
    V'[1,i] = AESRound(V[0,i], V[1,i])
    V'[2,i] = AESRound(V[1,i], V[2,i])
    V'[3,i] = AESRound(V[2,i], V[3,i])
    V'[4,i] = AESRound(V[3,i], V[4,i] ^ m1[i])
    V'[5,i] = AESRound(V[4,i], V[5,i])
    V'[6,i] = AESRound(V[5,i], V[6,i])
    V'[7,i] = AESRound(V[6,i], V[7,i])

    V[0,i]  = V'[0,i]
    V[1,i]  = V'[1,i]
    V[2,i]  = V'[2,i]
    V[3,i]  = V'[3,i]
    V[4,i]  = V'[4,i]
    V[5,i]  = V'[5,i]
    V[6,i]  = V'[6,i]
    V[7,i]  = V'[7,i]
~~~

### The Absorb Function

~~~
Absorb(ai)
~~~

The `Absorb` function is similar to the AEGIS-128L `Absorb` function, but absorbs `R` bits instead of 256 bits.

Steps:

~~~
t0, t1 = Split(ai, R)
Update(t0, t1)
~~~

### The Enc Function

~~~
Enc(xi)
~~~

The `Enc` function is similar to the AEGIS-128L `Enc` function, but encrypts `R` bits instead of 256 bits.

Steps:

~~~
z0 = {}
z1 = {}
for i in 0..D:
    z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
    z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))

t0, t1 = Split(xi, R)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(t0, t1)
ci = out0 || out1

return ci
~~~

### The Dec Function

~~~
Dec(ci)
~~~

The `Dec` function is similar to the AEGIS-128L `Dec` function, but decrypts `R` bits instead of 256 bits.

Steps:

~~~
z0 = {}
z1 = {}
for i in 0..D:
    z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
    z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))

t0, t1 = Split(ci, R)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(out0, out1)
xi = out0 || out1

return xi
~~~

### The DecPartial Function

~~~
DecPartial(cn)
~~~

The `DecPartial` function is similar to the AEGIS-128L `DecPartial` function, but decrypts up to `R` bits instead of 256 bits.

Steps:

~~~
z0 = {}
z1 = {}
for i in 0..D:
    z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
    z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))

t0, t1 = Split(ZeroPad(cn, R), 128 * D)
out0 = t0 ^ z0
out1 = t1 ^ z1

xn = Truncate(out0 || out1, |cn|)

v0, v1 = Split(ZeroPad(xn, R), 128 * D)
Update(v0, v1)

return xn
~~~

### The Finalize Function

~~~
Finalize(ad_len_bits, msg_len_bits)
~~~

The `Finalize` function finalizes every AEGIS-128L instance and combines the resulting authentication tags using the bitwise exclusive OR operation.

Steps:

~~~
t = {}
u = LE64(ad_len_bits) || LE64(msg_len_bits)
for i in 0..D:
    t = t || (V[2,i] ^ u)

Repeat(7, Update(t, t))

if tag_length == 16: # 128 bits
    tag = ZeroPad({}, 128)
    for i in 0..D:
        tag = tag ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]

else:                # 256 bits
    tag0 = ZeroPad({}, 128)
    tag1 = ZeroPad({}, 128)
    for i in 0..D:
        tag0 = tag0 ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
        tag1 = tag1 ^ V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
    tag = tag0 || tag1

return tag
~~~

## AEGIS-256X

### The Init Function

~~~
Init(key, nonce)
~~~

The `Init` function initializes a vector of `D` AEGIS-256 states with the same `key` and `nonce` but a different context `ctx[i]`. The context is added to the state before every update.

Steps:

~~~
k0, k1 = Split(key, 128)
n0, n1 = Split(nonce, 128)

for i in 0..D:
    V[0,i] = k0 ^ n0
    V[1,i] = k1 ^ n1
    V[2,i] = C1
    V[3,i] = C0
    V[4,i] = k0 ^ C0
    V[5,i] = k1 ^ C1

k0_v, k1_v = {}, {}
k0n0_v, k1n1_v = {}, {}
for i in 0..D:
    k0_v = k0_v || k0
    k1_v = k1_v || k1
    k0n0_v = k0n0_v || (k0 ^ n0)
    k1n1_v = k1n1_v || (k1 ^ n1)

Repeat(4,
    for i in 0..D:
        ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128)
        V[3,i] = V[3,i] ^ ctx[i]
        V[5,i] = V[5,i] ^ ctx[i]
        Update(k0_v)
        V[3,i] = V[3,i] ^ ctx[i]
        V[5,i] = V[5,i] ^ ctx[i]
        Update(k1_v)
        V[3,i] = V[3,i] ^ ctx[i]
        V[5,i] = V[5,i] ^ ctx[i]
        Update(k0n0_v)
        V[3,i] = V[3,i] ^ ctx[i]
        V[5,i] = V[5,i] ^ ctx[i]
        Update(k1n1_v)
)
~~~

### The Update Function

~~~
Update(M)
~~~

The AEGIS-256X `Update` function is similar to the AEGIS-256 `Update` function, but absorbs `R` (`128 * D`) bits at once. `M` is `128 * D` bits instead of 128 bits and is split into 128-bit blocks, each of them updating a different AEGIS-256 state.

Steps:

~~~
m = Split(M, 128)

for i in 0..D:
    V'[0,i] = AESRound(V[5,i], V[0,i] ^ m[i])
    V'[1,i] = AESRound(V[0,i], V[1,i])
    V'[2,i] = AESRound(V[1,i], V[2,i])
    V'[3,i] = AESRound(V[2,i], V[3,i])
    V'[4,i] = AESRound(V[3,i], V[4,i])
    V'[5,i] = AESRound(V[4,i], V[5,i])

    V[0,i]  = V'[0,i]
    V[1,i]  = V'[1,i]
    V[2,i]  = V'[2,i]
    V[3,i]  = V'[3,i]
    V[4,i]  = V'[4,i]
    V[5,i]  = V'[5,i]
~~~

### The Absorb Function

~~~
Absorb(ai)
~~~

The `Absorb` function is similar to the AEGIS-256 `Absorb` function, but absorbs `R` bits instead of 128 bits.

Steps:

~~~
Update(ai)
~~~

### The Enc Function

~~~
Enc(xi)
~~~

The `Enc` function is similar to the AEGIS-256 `Enc` function, but encrypts `R` bits instead of 128 bits.

Steps:

~~~
z = {}
for i in 0..D:
    z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))

Update(xi)

ci = xi ^ z

return ci
~~~

### The Dec Function

~~~
Dec(ci)
~~~

The `Dec` function is similar to the AEGIS-256 `Dec` function, but decrypts `R` bits instead of 128 bits.

Steps:

~~~
z = {}
for i in 0..D:
    z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))

xi = ci ^ z

Update(xi)

return xi
~~~

### The DecPartial Function

~~~
DecPartial(cn)
~~~

The `DecPartial` function is similar to the AEGIS-256 `DecPartial` function, but decrypts up to `R` bits instead of 128 bits.

Steps:

~~~
z = {}
for i in 0..D:
    z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))

t = ZeroPad(cn, R)
out = t ^ z

xn = Truncate(out, |cn|)

v = ZeroPad(xn, 128 * D)
Update(v)

return xn
~~~

### The Finalize Function

~~~
Finalize(ad_len_bits, msg_len_bits)
~~~

The `Finalize` function finalizes every AEGIS-256 instance and combines the resulting authentication tags using the bitwise exclusive OR operation.

Steps:

~~~
t = {}
u = LE64(ad_len_bits) || LE64(msg_len_bits)
for i in 0..D:
    t = t || (V[3,i] ^ u)

Repeat(7, Update(t))

if tag_length == 16: # 128 bits
    tag = ZeroPad({}, 128)
    for i in 0..D:
        tag = tag ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i]

else:                # 256 bits
    tag0 = ZeroPad({}, 128)
    tag1 = ZeroPad({}, 128)
    for i in 0..D:
        tag0 = tag0 ^ V[0,i] ^ V[1,i] ^ V[2,i]
        tag1 = tag1 ^ V[3,i] ^ V[4,i] ^ V[5,i]
    tag = tag0 || tag1

return tag
~~~

## Implementation Considerations

AEGIS-128X and AEGIS-256X with a degree of `1` are identical to AEGIS-128L and AEGIS-256. This property can be used to reduce the code size of a generic implementation.

In AEGIS-128X, `V` can be represented as eight 256-bit registers (when `D = 2`) or eight 512-bit registers (when `D = 4`). In AEGIS-256X, `V` can be represented as six 256-bit registers (when `D = 2`) or six 512-bit registers (when `D = 4`). With this representation, loops over `0..D` in the above pseudocode can be replaced by vector instructions.

## Operational Considerations

The AEGIS parallel modes are specialized and can only improve performance on specific CPUs.

The degrees of parallelism implementations are encouraged to support are `2` (for CPUs with 256-bit registers) and `4` (for CPUs with 512-bit registers). The resulting algorithms are called `AEGIS-128X2`, `AEGIS-128X4`, `AEGIS-256X2`, and `AEGIS-256X4`.

The following table summarizes how many bits are processed in parallel (rate), the memory requirements (state size), and the minimum vector register sizes a CPU should support for optimal performance.

| Algorithm   | Rate (bits) | Optimal Register Size | State Size (bits) |
| ----------- | ----------: | :-------------------: | ----------------: |
| AEGIS-128L  |         256 |       128 bits        |              1024 |
| AEGIS-128X2 |         512 |       256 bits        |              2048 |
| AEGIS-128X4 |        1024 |       512 bits        |              4096 |
| AEGIS-256   |         128 |       128 bits        |               768 |
| AEGIS-256X2 |         256 |       256 bits        |              1536 |
| AEGIS-256X4 |         512 |       512 bits        |              3072 |

Note that architectures with smaller vector registers but with many registers and large pipelines may still benefit from the parallel modes.

Protocols SHOULD opt for a parallel mode only when all the involved parties agree on a specific variant. AEGIS-128L and AEGIS-256 SHOULD remain the default choices.

Implementations MAY choose not to include the parallel AEGIS modes.

# Encoding (ct, tag) Tuples

Applications MAY keep the ciphertext and the authentication tag in distinct structures or encode both as a single string.

In the latter case, the tag MUST immediately follow the ciphertext:

~~~
combined_ct = ct || tag
~~~

# AEGIS as a Stream Cipher

All AEGIS variants can also be used as stream ciphers.

~~~
Stream(len, key, nonce)
~~~

The `Stream` function expands a key and an optional nonce into a variable-length, secure keystream.

Inputs:

- `len`: the length of the keystream to generate.
- `key`: the AEGIS key.
- `nonce`: the nonce. If unspecified, it is set to `N_MAX` zero bytes.

Outputs:

- `stream`: the keystream.

Steps:

~~~
stream, tag = Encrypt(ZeroPad({}, len), {}, key, nonce)

return stream
~~~

This is equivalent to encrypting a `len` all-zero bytes message without associated data, and discarding the authentication tag.

Instead of relying on the generic `Encrypt` function, implementations can skip the finalization step.

After initialization, the `Update` function is called with constant parameters, allowing further optimizations.

# Implementation Status

*This note is to be removed before publishing as an RFC.*

Multiple implementations of the schemes described in this document have been developed and verified for interoperability.

A comprehensive list of known implementations and integrations can be found at [](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead), which includes reference implementations closely aligned with the pseudocode provided in this document.

# Security Considerations

AEGIS-256 offers 256-bit message security against plaintext and state recovery, whereas AEGIS-128L offers 128-bit security.

An authentication tag may verify under multiple keys, nonces, or associated data, but AEGIS is assumed to be key committing in the receiver-binding game, preventing common attacks when used with low-entropy keys such as passwords. Finding distinct keys and/or nonces that successfully verify the same `(ad, ct, tag)` tuple is expected to require ~2<sup>64</sup> attempts with a 128-bit authentication tag and ~2<sup>128</sup> attempts with a 256-bit tag.

However, it is NOT fully committing because the authentication tag doesn't commit to the associated data. As shown in {{IR23}}, with the ability to also alter `ad`, it is possible to efficiently find multiple keys that will verify the same authenticated ciphertext.

Protocols mandating a fully committing scheme can provide the associated data as input to a cryptographic hash function and use the output as the `ad` parameter of the `Encrypt` and `Decrypt` functions. The selected hash function must ensure a minimum of 128-bit preimage resistance. An instance of such a function is SHA-256 {{!RFC6234}}.

Under the assumption that the secret key is unknown to the attacker both AEGIS-128L and AEGIS-256 target 128-bit security against forgery attacks regardless of the tag size.

Both algorithms MUST be used in a nonce-respecting setting: for a given `key`, a `nonce` MUST only be used once. Failure to do so would immediately reveal the bitwise difference between two messages.

If tag verification fails, the decrypted message and wrong message authentication tag MUST NOT be given as output. As shown in {{VV18}}, even a partial leak of the plaintext without verification would facilitate chosen ciphertext attacks.

Every key MUST be randomly chosen from a uniform distribution.

The nonce MAY be public or predictable. It can be a counter, the output of a permutation, or a generator with a long period.

With AEGIS-128L, random nonces can safely encrypt up to 2<sup>48</sup> messages using the same key with negligible (~ 2<sup>-33</sup>, to align with NIST guidelines) collision probability.

With AEGIS-256, random nonces can be used with no practical limits.

Regardless of the variant, the `key` and `nonce` are only required by the `Init` function; other functions only depend on the resulting state. Therefore, implementations can overwrite ephemeral keys with zeros right after the last `Update` call of the initialization function.

As shown in {{D23}}, AEGIS-128X and AEGIS-256X share the same security properties and requirements as AEGIS-128L and AEGIS-256 respectively. In particular, the security level and usage limits remain the same.

The security of AEGIS against timing and physical attacks is limited by the implementation of the underlying `AESRound()` function. Failure to implement `AESRound()` in a fashion safe against timing and physical attacks, such as differential power analysis, timing analysis or fault injection attacks, may lead to leakage of secret key material or state information. The exact mitigations required for timing and physical attacks also depend on the threat model in question.

AEGIS is considered secure against guess-and-determine attacks aimed at recovering the state from observed ciphertexts. This resilience extends to quantum adversaries in the Q1 model, wherein quantum attacks do not confer any practical advantage for decrypting previously recorded ciphertexts or achieving key recovery.

Security analyses of AEGIS can be found in {{AEGIS}}, {{M14}}, {{ENP19}}, {{LIMS21}}, {{JLD21}}, {{STSI23}}, {{IR23}}, and {{BS23}}.

# IANA Considerations

IANA has assigned the following identifiers in the AEAD Algorithms Registry:

| Algorithm Name   | ID   |
| ---------------- | ---- |
| `AEAD_AEGIS128L` | `32` |
| `AEAD_AEGIS256`  | `33` |
{: title="AEGIS entries in the AEAD Algorithms Registry"}

IANA has also assigned the following TLS cipher suites in the TLS Cipher Suite Registry:

| Cipher Suite Name       | Value         |
| ----------------------- | ------------- |
| `TLS_AEGIS_256_SHA384`  | `{0x13,0x06}` |
| `TLS_AEGIS_128L_SHA256` | `{0x13,0x07}` |
{: title="AEGIS entries in the TLS Cipher Suite Registry"}

A 128-bit tag length must be used with these cipher suites.

IANA is requested to update the references of these entries to refer to the final version of this document.

IANA is also requested to register the following identifiers in the AEAD Algorithms Registry:

- `AEAD_AEGIS128X2`
- `AEAD_AEGIS128X4`
- `AEAD_AEGIS256X2`
- `AEAD_AEGIS256X4`

as well as the following identifiers in the TLS Cipher Suite Registry:

- `TLS_AEGIS_128X2_SHA256`
- `TLS_AEGIS_128X4_SHA256`
- `TLS_AEGIS_256X2_SHA384`
- `TLS_AEGIS_256X4_SHA384`

# QUIC and DTLS 1.3 Header Protection

## DTLS 1.3 Record Number Encryption

In DTLS 1.3, record sequence numbers are encrypted as specified in [RFC9147].

For AEGIS-128L and AEGIS-256, the mask is generated using the AEGIS `Stream` function with:

- a 128-bit tag length
- `sn_key`, as defined in Section 4.2.3 of [RFC9147]
- `ciphertext[0..16]`: the first 16 bytes of the DTLS ciphertext
- `nonce_len`: the AEGIS nonce length

The 5-byte mask is computed as follows:

~~~
mask = Stream(5, sn_key, ZeroPad(ciphertext[0..16], nonce_len))
~~~

## QUIC Header Protection

In QUIC, parts of the QUIC packet headers are encrypted as specified in [RFC9001].

For AEGIS-128L and AEGIS-256, the mask is generated using the AEGIS `Encrypt` function with:

- a 128-bit tag length
- `hp_key`, as defined in Section 5.4 of [RFC9001]
- `sample`: the 16 bytes QUIC ciphertext sample
- `nonce_len`: the AEGIS nonce length

The mask is computed as follows:

~~~
mask = Encrypt("", "", hp_key, ZeroPad(sample, nonce_len))
~~~

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
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    :

msg   : 00000000000000000000000000000000

ct    : c1c0e58bd913006feba00f4b3cc3594e

tag128: abe0ece80c24868a226a35d16bdae37a

tag256: 25835bfbb21632176cf03840687cb968
        cace4617af1bd0f7d064c639a5c79ee4
~~~

### Test Vector 2

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    :

msg   :

ct    :

tag128: c2b879a67def9d74e6c14f708bbcc9b4

tag256: 1360dc9db8ae42455f6e5b6a9d488ea4
        f2184c4e12120249335c4ee84bafe25d
~~~

### Test Vector 3

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    : 0001020304050607

msg   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

ct    : 79d94593d8c2119d7e8fd9b8fc77845c
        5c077a05b2528b6ac54b563aed8efe84

tag128: cc6f3372f6aa1bb82388d695c3962d9a

tag256: 022cb796fe7e0ae1197525ff67e30948
        4cfbab6528ddef89f17d74ef8ecd82b3
~~~

### Test Vector 4

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    : 0001020304050607

msg   : 000102030405060708090a0b0c0d

ct    : 79d94593d8c2119d7e8fd9b8fc77

tag128: 5c04b3dba849b2701effbe32c7f0fab7

tag256: 86f1b80bfb463aba711d15405d094baf
        4a55a15dbfec81a76f35ed0b9c8b04ac
~~~

### Test Vector 5

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f
        20212223242526272829

msg   : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f
        3031323334353637

ct    : b31052ad1cca4e291abcf2df3502e6bd
        b1bfd6db36798be3607b1f94d34478aa
        7ede7f7a990fec10

tag128: 7542a745733014f9474417b337399507

tag256: b91e2947a33da8bee89b6794e647baf0
        fc835ff574aca3fc27c33be0db2aff98
~~~

### Test Vector 6

This test MUST return a "verification failed" error.

~~~
key   : 10000200000000000000000000000000

nonce : 10010000000000000000000000000000

ad    : 0001020304050607

ct    : 79d94593d8c2119d7e8fd9b8fc77

tag128: 5c04b3dba849b2701effbe32c7f0fab7

tag256: 86f1b80bfb463aba711d15405d094baf
        4a55a15dbfec81a76f35ed0b9c8b04ac
~~~

### Test Vector 7

This test MUST return a "verification failed" error.

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    : 0001020304050607

ct    : 79d94593d8c2119d7e8fd9b8fc78

tag128: 5c04b3dba849b2701effbe32c7f0fab7

tag256: 86f1b80bfb463aba711d15405d094baf
        4a55a15dbfec81a76f35ed0b9c8b04ac
~~~

### Test Vector 8

This test MUST return a "verification failed" error.

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    : 0001020304050608

ct    : 79d94593d8c2119d7e8fd9b8fc77

tag128: 5c04b3dba849b2701effbe32c7f0fab7

tag256: 86f1b80bfb463aba711d15405d094baf
        4a55a15dbfec81a76f35ed0b9c8b04ac
~~~

### Test Vector 9

This test MUST return a "verification failed" error.

~~~
key   : 10010000000000000000000000000000

nonce : 10000200000000000000000000000000

ad    : 0001020304050607

ct    : 79d94593d8c2119d7e8fd9b8fc77

tag128: 6c04b3dba849b2701effbe32c7f0fab8

tag256: 86f1b80bfb463aba711d15405d094baf
        4a55a15dbfec81a76f35ed0b9c8b04ad
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
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    :

msg   : 00000000000000000000000000000000

ct    : 754fc3d8c973246dcc6d741412a4b236

tag128: 3fe91994768b332ed7f570a19ec5896e

tag256: 1181a1d18091082bf0266f66297d167d
        2e68b845f61a3b0527d31fc7b7b89f13
~~~

### Test Vector 2

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    :

msg   :

ct    :

tag128: e3def978a0f054afd1e761d7553afba3

tag256: 6a348c930adbd654896e1666aad67de9
        89ea75ebaa2b82fb588977b1ffec864a
~~~

### Test Vector 3

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    : 0001020304050607

msg   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

ct    : f373079ed84b2709faee373584585d60
        accd191db310ef5d8b11833df9dec711

tag128: 8d86f91ee606e9ff26a01b64ccbdd91d

tag256: b7d28d0c3c0ebd409fd22b4416050307
        3a547412da0854bfb9723020dab8da1a
~~~

### Test Vector 4

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    : 0001020304050607

msg   : 000102030405060708090a0b0c0d

ct    : f373079ed84b2709faee37358458

tag128: c60b9c2d33ceb058f96e6dd03c215652

tag256: 8c1cc703c81281bee3f6d9966e14948b
        4a175b2efbdc31e61a98b4465235c2d9
~~~

### Test Vector 5

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f
        20212223242526272829

msg   : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f
        3031323334353637

ct    : 57754a7d09963e7c787583a2e7b859bb
        24fa1e04d49fd550b2511a358e3bca25
        2a9b1b8b30cc4a67

tag128: ab8a7d53fd0e98d727accca94925e128

tag256: a3aca270c006094d71c20e6910b5161c
        0826df233d08919a566ec2c05990f734
~~~

### Test Vector 6

This test MUST return a "verification failed" error.

~~~
key   : 10000200000000000000000000000000
        00000000000000000000000000000000

nonce : 10010000000000000000000000000000
        00000000000000000000000000000000

ad    : 0001020304050607

ct    : f373079ed84b2709faee37358458

tag128: c60b9c2d33ceb058f96e6dd03c215652

tag256: 8c1cc703c81281bee3f6d9966e14948b
        4a175b2efbdc31e61a98b4465235c2d9
~~~

### Test Vector 7

This test MUST return a "verification failed" error.

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    : 0001020304050607

ct    : f373079ed84b2709faee37358459

tag128: c60b9c2d33ceb058f96e6dd03c215652

tag256: 8c1cc703c81281bee3f6d9966e14948b
        4a175b2efbdc31e61a98b4465235c2d9
~~~

### Test Vector 8

This test MUST return a "verification failed" error.

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    : 0001020304050608

ct    : f373079ed84b2709faee37358458

tag128: c60b9c2d33ceb058f96e6dd03c215652

tag256: 8c1cc703c81281bee3f6d9966e14948b
        4a175b2efbdc31e61a98b4465235c2d9
~~~

### Test Vector 9

This test MUST return a "verification failed" error.

~~~
key   : 10010000000000000000000000000000
        00000000000000000000000000000000

nonce : 10000200000000000000000000000000
        00000000000000000000000000000000

ad    : 0001020304050607

ct    : f373079ed84b2709faee37358458

tag128: c60b9c2d33ceb058f96e6dd03c215653

tag256: 8c1cc703c81281bee3f6d9966e14948b
        4a175b2efbdc31e61a98b4465235c2da
~~~

## AEGIS-128X2 Test Vectors

### Initial State

~~~
key   : 000102030405060708090a0b0c0d0e0f

nonce : 101112131415161718191a1b1c1d1e1f

ctx[0]: 00010000000000000000000000000000
ctx[1]: 01010000000000000000000000000000
~~~

After initialization:

~~~
V[0,0]: a4fc1ad9a72942fb88bd2cabbba6509a
V[0,1]: 80a40e392fc71084209b6c3319bdc6cc

V[1,0]: 380f435cf801763b1f0c2a2f7212052d
V[1,1]: 73796607b59b1b650ee91c152af1f18a

V[2,0]: 6ee1de433ea877fa33bc0782abff2dcb
V[2,1]: b9fab2ab496e16d1facaffd5453cbf14

V[3,0]: 85f94b0d4263bfa86fdf45a603d8b6ac
V[3,1]: 90356c8cadbaa2c969001da02e3feca0

V[4,0]: 09bd69ad3730174bcd2ce9a27cd1357e
V[4,1]: e610b45125796a4fcf1708cef5c4f718

V[5,0]: fcdeb0cf0a87bf442fc82383ddb0f6d6
V[5,1]: 61ad32a4694d6f3cca313a2d3f4687aa

V[6,0]: 571c207988659e2cdfbdaae77f4f37e3
V[6,1]: 32e6094e217573bf91fb28c145a3efa8

V[7,0]: ca549badf8faa58222412478598651cf
V[7,1]: 3407279a54ce76d2e2e8a90ec5d108eb
~~~

### Test Vector 1

~~~
key   : 000102030405060708090a0b0c0d0e0f

nonce : 101112131415161718191a1b1c1d1e1f

ad    :

msg   :

ct    :

tag128: 63117dc57756e402819a82e13eca8379

tag256: b92c71fdbd358b8a4de70b27631ace90
        cffd9b9cfba82028412bac41b4f53759
~~~

### Test Vector 2

~~~
key   : 000102030405060708090a0b0c0d0e0f

nonce : 101112131415161718191a1b1c1d1e1f

ad    : 0102030401020304

msg   : 04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        0405060704050607

ct    : 5795544301997f93621b278809d6331b
        3bfa6f18e90db12c4aa35965b5e98c5f
        c6fb4e54bcb6111842c20637252eff74
        7cb3a8f85b37de80919a589fe0f24872
        bc926360696739e05520647e390989e1
        eb5fd42f99678a0276a498f8c454761c
        9d6aacb647ad56be62b29c22cd4b5761
        b38f43d5a5ee062

tag128: 1aebc200804f405cab637f2adebb6d77

tag256: c471876f9b4978c44f2ae1ce770cdb11
        a094ee3feca64e7afcd48bfe52c60eca
~~~

## AEGIS-128X4 Test Vectors

### Initial State

~~~
key   : 000102030405060708090a0b0c0d0e0f

nonce : 101112131415161718191a1b1c1d1e1f

ctx[0]: 00030000000000000000000000000000
ctx[1]: 01030000000000000000000000000000
ctx[2]: 02030000000000000000000000000000
ctx[3]: 03030000000000000000000000000000
~~~

After initialization:

~~~
V[0,0]: 924eb07635003a37e6c6575ba8ce1929
V[0,1]: c8b6a5d91475445e936d48e794be0ce2
V[0,2]: fcd37d050e24084befe3bbb219d64760
V[0,3]: 2e9f58cfb893a8800220242c373a8b18

V[1,0]: 1a1f60c4fab64e5471dc72edfcf6fe6b
V[1,1]: c1e525ebea2d6375a9edd045dce96381
V[1,2]: 97a3e25abd228a44d4a14a6d3fe9185c
V[1,3]: c2d4cf7f4287a98744645674265d4ca8

V[2,0]: 7bb50c534f6ec4780530ff1cce8a16e8
V[2,1]: 7b08d57557da0b5ef7b5f7d98b0ba189
V[2,2]: 6bfcac34ddb68404821a4d665303cb0f
V[2,3]: d95626f6dfad1aed7467622c38529932

V[3,0]: af339fd2d50ee45fc47665c647cf6586
V[3,1]: d0669b39d140f0e118a4a511efe2f95a
V[3,2]: 7a94330f35c194fadda2a87e42cdeccc
V[3,3]: 233b640d1f4d56e2757e72c1a9d8ecb1

V[4,0]: 9f93737d699ba05c11e94f2b201bef5e
V[4,1]: 61caf387cf7cfd3f8300ac7680ccfd76
V[4,2]: 5825a671ecef03b7a9c98a601ae32115
V[4,3]: 87a1fe4d558161a8f4c38731f3223032

V[5,0]: 7a5aca78d636c05bbc702b2980196ab6
V[5,1]: 915d868408495d07eb527789f282c575
V[5,2]: d0947bfbc1d3309cdffc9be1503aea62
V[5,3]: 8834ea57a15b9fbdc0245464a4b8cbef

V[6,0]: e46f4cf71a95ac45b6f0823e3aba1a86
V[6,1]: 8c4ecef682fc44a8eba911b3fc7d99f9
V[6,2]: a4fb61e2c928a2ca760b8772f2ea5f2e
V[6,3]: 3d34ea89da73caa3016c280500a155a3

V[7,0]: 85075f0080e9d618e7eb40f57c32d9f7
V[7,1]: d2ab2b320c6e93b155a3787cb83e5281
V[7,2]: 0b3af0250ae36831a1b072e499929bcb
V[7,3]: 5cce4d00329d69f1aae36aa541347512
~~~

### Test Vector 1

~~~
key   : 000102030405060708090a0b0c0d0e0f

nonce : 101112131415161718191a1b1c1d1e1f

ad    :

msg   :

ct    :

tag128: 5bef762d0947c00455b97bb3af30dfa3

tag256: a4b25437f4be93cfa856a2f27e4416b4
        2cac79fd4698f2cdbe6af25673e10a68
~~~

### Test Vector 2

~~~
key   : 000102030405060708090a0b0c0d0e0f

nonce : 101112131415161718191a1b1c1d1e1f

ad    : 0102030401020304

msg   : 04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        0405060704050607

ct    : e836118562f4479c9d35c17356a83311
        4c21f9aa39e4dda5e5c87f4152a00fce
        9a7c38f832eafe8b1c12f8a7cf12a81a
        1ad8a9c24ba9dedfbdaa586ffea67ddc
        801ea97d9ab4a872f42d0e352e2713da
        cd609f9442c17517c5a29daf3e2a3fac
        4ff6b1380c4e46df7b086af6ce6bc1ed
        594b8dd64aed2a7e

tag128: 0e56ab94e2e85db80f9d54010caabfb4

tag256: 69abf0f64a137dd6e122478d777e98bc
        422823006cf57f5ee822dd78397230b2
~~~

## AEGIS-256X2 Test Vectors

### Initial State

~~~
key   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

nonce : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f

ctx[0]: 00010000000000000000000000000000
ctx[1]: 01010000000000000000000000000000
~~~

After initialization:

~~~
V[0,0]: eca2bf4538442e8712d4972595744039
V[0,1]: 201405efa9264f07911db58101903087

V[1,0]: 3e536a998799408a97f3479a6f779d48
V[1,1]: 0d79a7d822a5d215f78c3bf2feb33ae1

V[2,0]: cf8c63d6f2b4563cdd9231107c85950e
V[2,1]: 78d17ed7d8d563ff11bd202c76864839

V[3,0]: d7e0707e6bfbbad913bc94b6993a9fa0
V[3,1]: 097e4b1bff40d4c19cb29dfd125d62f2

V[4,0]: a373cf6d537dd66bc0ef0f2f9285359f
V[4,1]: c0d0ae0c48f9df3faaf0e7be7768c326

V[5,0]: 9f76560dcae1efacabdcce446ae283bc
V[5,1]: bd52a6b9c8f976a26ec1409df19e8bfe
~~~

### Test Vector 1

~~~
key   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

nonce : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f

ad    :

msg   :

ct    :

tag128: 62cdbab084c83dacdb945bb446f049c8

tag256: 25d7e799b49a80354c3f881ac2f1027f
        471a5d293052bd9997abd3ae84014bb7
~~~

### Test Vector 2

~~~
key   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

nonce : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f

ad    : 0102030401020304

msg   : 04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        0405060704050607

ct    : 73110d21a920608fd77b580f1e442808
        7a7365cb153b4eeca6b62e1a70f7f9a8
        d1f31f17da4c3acfacb2517f2f5e1575
        8c35532e33751a964d18d29a599d2dc0
        7f9378339b9d8c9fa03d30a4d7837cc8
        eb8b99bcbba2d11cd1a0f994af2b8f94
        7ef18473bd519e5283736758480abc99
        0e79d4ccab93dde9

tag128: 94a3bd44ad3381e36335014620ee638e

tag256: 0392c62b17ddb00c172a010b5a327d0f
        97317b6fbaee31ef741f004d7adc1e81
~~~

## AEGIS-256X4 Test Vectors

### Initial State

~~~
key   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

nonce : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f

ctx[0]: 00030000000000000000000000000000
ctx[1]: 01030000000000000000000000000000
ctx[2]: 02030000000000000000000000000000
ctx[3]: 03030000000000000000000000000000
~~~

After initialization:

~~~
V[0,0]: 482a86e8436cd2361063a4b2702769b9
V[0,1]: d95a2be81c9245b22996f68eea0122f9
V[0,2]: 0c2a3b348b1a5e256c6751377318c41e
V[0,3]: f64436a21653fe7cf2e0829a177db383

V[1,0]: e705e8866267717d96092e58e78b574c
V[1,1]: d1dd412142df9806cc267af2fe1d830e
V[1,2]: 30e7dfd3c9941b8394e95bdf5bac99d9
V[1,3]: 9f27186f8a4fab86820689822c3c74d2

V[2,0]: e1aa6af5d9e31dde8d94a48a0810fa89
V[2,1]: 63555cdf0d98f18fb75b029ad80786c0
V[2,2]: a3ee0e4a3429a9539e4fcec385475608
V[2,3]: 28ea527d31ef61df498dc107fe02df99

V[3,0]: 37f06808410c8f3954525ae44584d3be
V[3,1]: 8fcc23bca2fe2209f93d34e2da35b33d
V[3,2]: 33156347df89eaa69ab11096362daccf
V[3,3]: bbe58d9dbe8c5b0469be5a87086db5d4

V[4,0]: d1c9eb37fecbc5ada7b351fa4f501f32
V[4,1]: 0b9b803283c1538628b507c8f6432434
V[4,2]: bfb8b6d4f87cce28825c7e92f54b8728
V[4,3]: 8917bb5b09c32f900c6a5a1d63c46264

V[5,0]: 4f6110c2ef0c3c687e90c1e5532ddf8e
V[5,1]: 031bd85d99f64684d23728a0453c72a1
V[5,2]: 10bc7ec34d4119b5bdeb6c7dfc458247
V[5,3]: 591ece530aeaa5c9867220156f5c25e3
~~~

### Test Vector 1

~~~
key   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

nonce : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f

ad    :

msg   :

ct    :

tag128: 3b7fee6cee7bf17888ad11ed2397beb4

tag256: 6093a1a8aab20ec635dc1ca71745b01b
        5bec4fc444c9ffbebd710d4a34d20eaf
~~~

### Test Vector 2

~~~
key   : 000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f

nonce : 101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f

ad    : 0102030401020304

msg   : 04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        04050607040506070405060704050607
        0405060704050607

ct    : bec109547f8316d598b3b7d947ad4c0e
        f5b98e217cffa0d858ad49ae34109a95
        abc5b5fada820c4d6ae2fca0f5e2444e
        52a04a1edb7bec71408de3e199500521
        94506be3ba6a4de51a15a577ea0e4c14
        f7539a13e751a555f48d0f49fecffb22
        0525e60d381e2efa803b09b7164ba59f
        dc66656affd51e06

tag128: ec44b512d713f745547be345bcc66b6c

tag256: ba3168ecd7f7120c5e204a7e0d616e39
        5675ddfe00e4e5490a5ba93bb1a70555
~~~

# Acknowledgments
{:numbered="false"}

The AEGIS authenticated encryption algorithm was invented by Hongjun Wu and Bart Preneel.

The round function leverages the AES permutation invented by Joan Daemen and Vincent Rijmen. They also authored the Pelican MAC that partly motivated the design of the AEGIS MAC.

We would like to thank the following individuals for their contributions:

- Eric Lagergren and Daniel Bleichenbacher for catching a broken test vector and Daniel Bleichenbacher for many helpful suggestions.
- John Preuß Mattsson for his review of the draft, and for suggesting how AEGIS should be used in the context of DTLS and QUIC.
- Bart Mennink and Charlotte Lefevre as well as Takanori Isobe and Mostafizar Rahman for investigating the commitment security of the schemes specified in this document.

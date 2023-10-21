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
This document is a product of the Crypto Forum Research Group (CFRG). It is not an IETF product and is not a standard.


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

Note that an earlier version of Hongjun Wu and Bart Preneel's paper introducing AEGIS specified AEGIS-128L and AEGIS-256 sporting differences with regards to the computation of the authentication tag and the number of rounds in `Finalize()` respectively. We follow the specification of {{AEGIS}} that is current at the time of writing, which can be found in the References section of this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

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

- `K_LEN` (key length) is 16 octets (128 bits).
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> octets (2<sup>64</sup> bits).
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> octets (2<sup>64</sup> bits).
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 16 octets (128 bits).
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 or 32 octets (2<sup>64</sup> + 128 or 256 bits).

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

- `K_LEN` (key length) is 32 octets (256 bits).
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> octets (2<sup>64</sup> bits).
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> octets (2<sup>64</sup> bits).
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 32 octets (256 bits).
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 or 32 octets (2<sup>64</sup> + 128 or 256 bits).

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

# Parallel modes

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
- `ctx`: the context separator.
- `Byte(x)`: the value `x` encoded as 8 bits.

## Authenticated Encryption

~~~
Encrypt(msg, ad, key, nonce)
~~~

The `Encrypt` function of `AEGIS-128X` resembles that of `AEGIS-128L`, and similarly, the `Encrypt` function of `AEGIS-256X` mirrors that of `AEGIS-256`, but processes `R`-bit input blocks per update.

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

The `Decrypt` function of `AEGIS-128X` resembles that of `AEGIS-128L`, and similarly, the `Decrypt` function of `AEGIS-256X` mirrors that of `AEGIS-256`, but processes `R`-bit input blocks per update.

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

The `Init` function initializes a vector of `D` AEGIS-128L states with the same `key` and `nonce` but a different context `ctx`. The context is added to the state before every update.

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
        ctx = Byte(i)
        V[3,i] = V[3,i] ^ ZeroPad(ctx, 128)
        V[7,i] = V[7,i] ^ ZeroPad(ctx, 128)

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

The `Init` function initializes a vector of `D` AEGIS-256 states with the same `key` and `nonce` but a different context `ctx`. The context is added to the state before every update.

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
        ctx = Byte(i)
        V[3,i] = V[3,i] ^ ZeroPad(ctx, 128)
        V[5,i] = V[5,i] ^ ZeroPad(ctx, 128)
        Update(k0_v)
        V[3,i] = V[3,i] ^ ZeroPad(ctx, 128)
        V[5,i] = V[5,i] ^ ZeroPad(ctx, 128)
        Update(k1_v)
        V[3,i] = V[3,i] ^ ZeroPad(ctx, 128)
        V[5,i] = V[5,i] ^ ZeroPad(ctx, 128)
        Update(k0n0_v)
        V[3,i] = V[3,i] ^ ZeroPad(ctx, 128)
        V[5,i] = V[5,i] ^ ZeroPad(ctx, 128)
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

AEGIS-128X and AEGIS-256X with a degree of `1` are indentical to AEGIS-128L and AEGIS-256. This property can be used to reduce the code size of a generic implementation.

In AEGIS-128X, `V` can be represented as eight 256-bit registers (for AEGIS-128X2) or eight 512-bit registers (for AEGIS-128X4). In AEGIS-256X, `V` can be represented as six 256-bit registers (for AEGIS-256X2) or six 512-bit registers (for AEGIS-256X4). With this representation, loops over `0..D` in the above pseudocode can be replaced by vector instructions.

## Operational Considerations

The AEGIS parallel modes are specialized and can only improve performance on specific CPUs.

The degrees of parallelism implementations are encouraged to support are `2` (for CPUs with 256-bit registers) and `4` (for CPUs with 512-bit registers). The resulting algorithms are called `AEGIS-128X2`, `AEGIS-128X4`, `AEGIS-256X2`, and `AEGIS-256X4`.

The following table summarizes how many bits are processed in parallel (rate), the memory requirements (state size), and the mininum vector register sizes a CPU should support for optimal performance.

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

# Security Considerations

AEGIS-256 offers 256-bit message security against plaintext and state recovery, whereas AEGIS-128L offers 128-bit security.

An authentication tag may verify under multiple keys, nonces, or associated data, but AEGIS is assumed to be key committing in the receiver-binding game, preventing common attacks when used with low-entropy keys such as passwords. Finding distinct keys and/or nonces that successfully verify the same `(ad, ct, tag)` tuple is expected to require ~2<sup>64</sup> attempts with a 128-bit authentication tag and ~2<sup>128</sup> attempts with a 256-bit tag.

However, it is NOT fully committing because the key doesn't commit to the associated data. As shown in {{IR23}}, with the ability to also alter `ad`, it is possible to efficiently find multiple keys that will verify the same authenticated ciphertext.

Under the assumption that the secret key is unknown to the attacker both AEGIS-128L and AEGIS-256 target 128-bit security against forgery attacks regardless of the tag size.

Both algorithms MUST be used in a nonce-respecting setting: for a given `key`, a `nonce` MUST only be used once. Failure to do so would immediately reveal the bitwise difference between two messages.

If tag verification fails, the decrypted message and wrong message authentication tag MUST NOT be given as output. As shown in the analysis of the (robustness of CAESAR candidates beyond their guarantees){{VV18}}, even a partial leak of the plaintext without verification would facilitate chosen ciphertext attacks.

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

## AEGIS-128X Test Vectors

### AEGIS-128X2 Test Vector

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

ct    : 9958ad79ff1feea50a27d5dd88728d15
        7a4ce0cd996b9fffb4fde113ef646de4
        aa67278fb1ebcb6571526b309d708447
        c818ffc3d84c9c73b0cca3040bb85b81
        d366311956f4cb1a66b02b25b58a7f75
        9797169b0e398c4db16c9a577d4de180
        5d646b823fa095ec34feefb58768efc0
        6d9516c55b653f91

tag128: 179247ab85ea2c4f9f712cac8bb7c9d3

tag256: 04ad653f69c3e3bf3d29013367473ade
        573551bdcf71f32a0debb089e58fb9e1
~~~

### AEGIS-128X4 Test Vector

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

ct    : 9958ad79ff1feea50a27d5dd88728d15
        7a4ce0cd996b9fffb4fde113ef646de4
        6e4c5230174a6268f89f01d557879360
        a9068d7cb825bb0e8a97ea2e82059f69
        aa67278fb1ebcb6571526b309d708447
        c818ffc3d84c9c73b0cca3040bb85b81
        93fc9a4499e384ae87bfeaa46f514b63
        30c147c3ddbb6e94

tag128: 58038e00f6b7e861e2badb160beb71d4

tag256: 01d860572aa4ce5b83183cc94bc9fb44
        5e2d70c0687f6fbc6991c2918d3ab0e8
~~~

## AEGIS-256X Test Vectors

### AEGIS-256X2 Test Vector

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

ct    : a1b0f4b9b83eb676c8d2b8d1692be03d
        95280efa4e2c09962880dc614f94642b
        a7581f933d98c7355623ff63be82bb8a
        476ddd0dfe0185b4e8da6c25bd9f38b9
        d09e0ec9baf01cd47369dbca9d331bfc
        d49fb4e6806e61f344d61b11ac552e4c
        50c6d26570210e1202eb9b347b908a55
        361ea8d15f8494e3

tag128: 3c24d8bed42e92d3f85535946545fe38

tag256: 3e3543e177aec683d341ca2ae92a8a1b
        02119b5fa38054502b14ffbe8c6f7423
~~~

### AEGIS-256X4 Test Vector

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

ct    : a1b0f4b9b83eb676c8d2b8d1692be03d
        95280efa4e2c09962880dc614f94642b
        d4f1068ba92cf7bfd89c2acd70ef492b
        0544105f5c3b948cee0248486b4a3411
        a7581f933d98c7355623ff63be82bb8a
        476ddd0dfe0185b4e8da6c25bd9f38b9
        d1da0307b0f33484ed9abad2c9184cb4
        b58d7a8a486c0605

tag128: 2ddf105d8bb7a2d7adb60cd5a5285183

tag256: da85a761bdd56e8c11d3179e11ed353a
        f75ab73c3662cc5bbc651b4bb4c564b9
~~~

# Acknowledgments
{:numbered="false"}

The AEGIS authenticated encryption algorithm was invented by Hongjun Wu and Bart Preneel.

The round function leverages the AES permutation invented by Joan Daemen and Vincent Rijmen. They also authored the Pelican MAC that partly motivated the design of the AEGIS MAC.

We would like to thank the following individuals for their contributions:

- Eric Lagergren and Daniel Bleichenbacher for catching a broken test vector and Daniel Bleichenbacher for many helpful suggestions.
- John Preuß Mattsson for his review of the draft, and for suggesting how AEGIS should be used in the context of DTLS and QUIC.
- Bart Mennink and Charlotte Lefevre as well as Takanori Isobe and Mostafizar Rahman for investigating the commitment security of the schemes specified in this document.

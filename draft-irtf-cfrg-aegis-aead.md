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

  JLD21:
    title: "Guess-and-Determine Attacks on AEGIS"
    rc: "The Computer Journal"
    seriesinfo:
      DOI: 10.1093/comjnl/bxab059
    author:
      -
        ins: L. Jiao
        name: Lin Jiao
        org: State Key Laboratory of Cryptology, Beijing
      -
        ins: Y. Li
        name: Yongqiang Li
        org: State Key Laboratory of Information Security, Institute of Information Engineering, Chinese Academy of Sciences; School of Cyber Security, University of Chinese Academy of Sciences
      -
        ins: S. Du
        name: Shaoyu Du
        org: State Key Laboratory of Cryptology, Beijing
    date: 2021-05-22

  LIMS21:
    title: "Weak Keys in Reduced AEGIS and Tiaoxin"
    rc: "IACR Transactions on Symmetric Cryptology, 2021(2), pp. 104–139"
    target: https://eprint.iacr.org/2021/187
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
    date: 2020-01-31

  CRA18:
    title: "Can Caesar Beat Galois? Robustness of CAESAR Candidates against Nonce Reusing and High Data Complexity Attacks"
    rc: "Applied Cryptography and Network Security. ACNS 2018. Lecture Notes in Computer Science, vol 10892, pp. 476–494"
    seriesinfo:
      DOI: 10.1007/978-3-319-93387-0_25
    author:
      -
        ins: S. Vaudenay
        name: Serge Vaudenay
        org: École Polytechnique Fédérale de Lausanne EPFL
      -
        ins: D. Vizár
        name: Damian Vizár
        org: École Polytechnique Fédérale de Lausanne EPFL
    date: 2018

  Min14:
    title: "Linear Biases in AEGIS Keystream"
    rc: "Selected Areas in Cryptography. SAC 2014. Lecture Notes in Computer Science, vol 8781, pp. 290–305"
    seriesinfo:
      DOI: 10.1007/978-3-319-13051-4_18
    target: https://eprint.iacr.org/2018/292
    author:
      -
        ins: B. Minaud
        name: Brice Minaud
        org: Agence nationale de la sécurité des systèmes d'information ANSSI
    date: 2014

  STSI23:
    title: "MILP-based security evaluation for AEGIS/Tiaoxin-346/Rocca"
    rc: "IET Information Security, 2023, pp. 1-10"
    seriesinfo:
      DOI: 10.1049/ise2.12109
    target: https://doi.org/10.1049/ise2.12109
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
    date: 2023-01-27

--- abstract

This document describes AEGIS-128L and AEGIS-256, two AES-based authenticated encryption algorithms designed for high-performance applications.
This document is a product of the Crypto Forum Research Group (CFRG). It is not an IETF product and is not a standard.


--- middle

# Introduction

This document describes the AEGIS-128L and AEGIS-256 authenticated encryption with associated data (AEAD) algorithms {{AEGIS}}, which were chosen as additional finalists for high-performance applications in the Competition for Authenticated Encryption: Security, Applicability, and Robustness (CAESAR). Whilst AEGIS-128 was selected as a winner for this use case, AEGIS-128L has a better security margin alongside improved performance and AEGIS-256 uses a 256-bit key {{LIMS21}}. All variants of AEGIS are constructed from the AES encryption round function {{!FIPS-AES=FIPS.197.2001}}. This document specifies:

- AEGIS-128L, which has a 128-bit key, a 128-bit nonce, a 1024-bit state, a 128- or 256-bit authentication tag, and processes 256-bit input blocks.
- AEGIS-256, which has a 256-bit key, a 256-bit nonce, a 768-bit state, a 128- or 256-bit authentication tag, and processes 128-bit input blocks.

The AEGIS cipher family offers performance that significantly exceeds that of AES-GCM with hardware support for parallelizable AES block encryption {{AEGIS}}. Similarly, software implementations can also be faster, although to a lesser extent.

Unlike with AES-GCM, nonces can be safely chosen at random with no practical limit when using AEGIS-256. AEGIS-128L also allows for more messages to be safely encrypted when using random nonces.

With some existing AEAD schemes, such as AES-GCM, an attacker can generate a ciphertext that successfully decrypts under multiple different keys (a partitioning oracle attack) {{LGR21}}. This ability to craft a (ciphertext, authentication tag) pair that verifies under multiple keys significantly reduces the number of required interactions with the oracle in order to perform an exhaustive search, making it practical if the key space is small. For example, with password-based encryption, an attacker can guess a large number of passwords at a time by recursively submitting such a ciphertext to an oracle, which speeds up a password search by reducing it to a binary search.

A key-committing AEAD scheme is more resistant against partitioning oracle attacks than non-committing AEAD schemes, making it significantly harder to find multiple keys that are valid for a given authentication tag. A 128-bit tag provides 64-bit key-committing security, which is generally acceptable for interactive protocols. With a 256-bit tag, finding a collision becomes impractical. As of the time of writing, no research has been published claiming that AEGIS is not a key-committing AEAD scheme.

Finally, unlike most other AES-based AEAD constructions, leaking a state does not leak the previous states.

Note that an earlier version of Hongjun Wu and Bart Preneel's paper introducing AEGIS specified AEGIS-128L and AEGIS-256 sporting differences with regards to the computation of the authentication tag and the number of rounds in `Finalize()` respectively. We follow the specification of {{AEGIS}} that is current at the time of writing, which can be found in the References section of this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Primitives:

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

- `Update(M0, M1)`: the state update function.
- `Init(key, nonce)`: the initialization function.
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
for xi in ad_blocks:
    Enc(xi)

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
for xi in ad_blocks:
    Enc(xi)

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
for xi in ad_blocks:
    Enc(xi)

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

# Encoding (ct, tag) Tuples

Applications MAY keep the ciphertext and the authentication tag in distinct structures or encode both as a single string.

In the latter case, the tag MUST immediately follow the ciphertext:

~~~
combined_ct = ct || tag
~~~

# Security Considerations

AEGIS-256 offers 256-bit message security against plaintext and state recovery, whereas AEGIS-128L offers 128-bit security.

An authentication tag may verify under multiple keys. Assuming AEGIS is key-committing, finding equivalent keys is expected to require ~2<sup>64</sup> attempts with a 128-bit authentication tag and ~2<sup>128</sup> attempts with a 256-bit tag.

Under the assumption that the secret key is unknown to the attacker and the tag is not truncated, both AEGIS-128L and AEGIS-256 target 128-bit security against forgery attacks.

Both algorithms MUST be used in a nonce-respecting setting: for a given `key`, a `nonce` MUST only be used once. Failure to do so would immediately reveal the bitwise difference between two messages.

If tag verification fails, the decrypted message and wrong message authentication tag MUST NOT be given as output. As shown in the analysis of the (robustness of CAESAR candidates beyond their guarantees){{CRA18}}, even a partial leak of the plaintext without verification would facilitate chosen ciphertext attacks.

Every key MUST be randomly chosen from a uniform distribution.

The nonce MAY be public or predictable. It can be a counter, the output of a permutation, or a generator with a long period.

With AEGIS-128L, random nonces can safely encrypt up to 2<sup>48</sup> messages using the same key with negligible collision probability.

With AEGIS-256, random nonces can be used with no practical limits.

The security of AEGIS against timing and physical attacks is limited by the implementation of the underlying `AESRound()` function. Failure to implement `AESRound()` in a fashion safe against timing and physical attacks, such as differential power analysis, timing analysis or fault injection attacks, may lead to leakage of secret key material or state information. The exact mitigations required for timing and physical attacks also depend on the threat model in question.

Security analyses of AEGIS can be found in Chapter 4 of {{AEGIS}}, in {{Min14}}, in {{ENP19}}, in {{LIMS21}}, in {{JLD21}}, and in {{STSI23}}.

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

IANA is requested to update the references of these entries to refer to the final version of this document.

# QUIC and DTLS 1.3 Header Protection

## DTLS 1.3 Record Number Encryption

In DTLS 1.3, record sequence numbers are encrypted as specified in [RFC9147].

For AEGIS-128L and AEGIS-256, the mask is generated using the AEGIS `Encrypt` function with:

- a 128-bit tag length
- `sn_key`, as defined in Section 4.2.3 of [RFC9147]
- `ciphertext[0..16]`: the first 16 bytes of the DTLS ciphertext
- `nonce_len`: the AEGIS nonce length

The mask is computed as follows:

~~~
mask = Encrypt("", "", sn_key, ZeroPad(ciphertext[0..16], nonce_len))
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

# Acknowledgments
{:numbered="false"}

The AEGIS authenticated encryption algorithm was invented by Hongjun Wu and Bart Preneel.

The round function leverages the AES permutation invented by Joan Daemen and Vincent Rijmen. They also authored the Pelican MAC that partly motivated the design of the AEGIS MAC.

We would like to thank Eric Lagergren and Daniel Bleichenbacher for catching a broken test vector and Daniel Bleichenbacher for many helpful suggestions.

We would also like to thank John Preuß Mattsson for his review of the draft, and for suggesting how AEGIS should be used in the context of DTLS and QUIC.

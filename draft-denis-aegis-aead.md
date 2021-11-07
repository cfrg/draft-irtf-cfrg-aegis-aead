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
    email: fd@00f.net
 -
    name: Fabio Enrico Renzo Scotoni
    organization: Individual Contributor
    email: fabio@esse.ch

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

--- abstract

This document describes AEGIS-128L and AEGIS-256, two AES-based authenticated encryption algorithms designed for high-performance applications.


--- middle

# Introduction

This document describes the AEGIS-128L and AEGIS-256 authenticated encryption algorithms {{AEGIS}}.

Both are constructed from the AES encryption round function {{!FIPS-AES=FIPS.197.2001}}.

- AEGIS-128L has a 128-bit key, a 128-bit nonce, a 1024-bit state, a 128-bit authentication tag, and processes 256-bit input blocks.
- AEGIS-256 has a 256-bit key, a 256-bit nonce, a 768-bit state, a 128-bit authentication tag, and processes 128-bit input blocks.

The AEGIS cipher family offers optimal performance on CPUs with hardware support for parallelizable AES block encryption.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Primitives:

- `|x|`: the length of `x` in bits
- `a ^ b`: the bit-wise exclusive OR operation between `a` and `b`
- `a & b`: the bit-wise AND operation between `a` and `b`
- `a || b`: the concatenation of `a` and `b`
- `a mod b`: the remainder of the Euclidean division between `a` as the dividend and `b` as the divisor
- `LE64(x)`: the little-endian encoding of 64-bit integer `x`
- `Pad(x, n)`: padding operation. Trailing zeros are concatenated to `x` until the total length is a multiple of `n` bits.
- `Truncate(x, n)`: truncation operation. The first `n` bits of `x` are kept.
- `Split(x, n)`: splitting operation. `x` is split `n`-bit blocks, ignoring partial blocks.
- `Tail(x, n)`: returns the last `n` bits of `x`.
- `AESRound(in, rk)`: a single round of the AES encryption round function, which is the composition of the `SubBytes`, `ShiftRows`, `MixColums` and `AddRoundKey` transformations as defined in section 5 of {{FIPS-AES}}. `in` is the 128-bit AES input state and `rk` is the 128-bit round key.
- `Repeat(n, F)`: `n` sequential evaluations of the function `F`

AEGIS internal functions:

- `Update(M0, M1)`: the state update function
- `Init(k, iv)`: the initialization function
- `Enc(xi)`: the 256-bit block encryption function
- `Dec(ci)`: the 256-bit block decryption function
- `DecPartial(cn)`: the 256-bit block decryption function for the last ciphertext bits, when they do not fill an entire block
- `Finalize(adlen, mlen)`: the authentication tag generation function

AES blocks:

- `Si`: the `i`-th block of the current state
- `S'i`: the `i`-th block of the next state
- `C0`: the constant `0x000101020305080d1522375990e97962` as an AES block
- `C1`: the constant `0xdb3d18556dc22ff12011314273b528dd` as an AES block

AES blocks are always 128 bits in length.

Input and output values:

- `k`: the encryption key (128 bits for AEGIS-128L, 256 bits for AEGIS-256)
- `iv`: the public nonce (128 bits for AEGIS-128L, 256 bits for AEGIS-256)
- `ad`: the associated data
- `m`: the cleartext
- `c`: the ciphertext
- `tag`: the authentication tag (128 bits)

# The AEGIS-128L Algorithm

AEGIS-128L has a 1024-bit state, made of eight 128-bit blocks `{S0, ...S7}`.

The parameters for this algorithm, as defined in {{!RFC5116, Section 4}} are:

- `K_LEN` (key length) is 16 octets
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> octets
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> octets
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 16 octets
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 octets

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} shall be unambiguously encoded as a single input.
It is up to the application to create a structure in the associated data input if it is needed.

## Authenticated Encryption

The `Encrypt` function encrypts a message and returns the ciphertext along with an authentication tag that verifies the authenticity of the message and, if provided, of associated data.

~~~
Encrypt(m, ad, k, iv)
~~~

Inputs:

- `m`: the message to be encrypted
- `ad`: the associated data to authenticate
- `k`: the encryption key
- `iv`: the public nonce

Outputs:

- `c`: the ciphertext
- `tag`: the authentication tag

Steps:

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
m = Truncate(m, |c|)
~~~

## Authenticated Decryption

The `Decrypt` function decrypts a ciphertext, verifies that the authentication tag is correct, and returns the message on success, or an error if tag verification failed.

~~~
Decrypt(c, tag, ad, k, iv)
~~~

Inputs:

- `c`: the ciphertext to be decrypted
- `ad`: the associated data to authenticate
- `k`: the encryption key
- `iv`: the public nonce

Outputs:

- either `m`: the message, or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
Init(k, iv)

m = {}

ad_blocks = Split(Pad(ad, 256), 256)
for xi in ad_blocks:
    Enc(xi)

c_blocks = Split(c, 256)
cn = Tail(c, |c| mod 256)

for ci in c_blocks:
    m = m || Dec(ci)

if cn is not empty:
    m = m || DecPartial(cn)

expected_tag = Finalize(|ad|, |m|)
~~~

The comparison of the authentication tag `tag` with the expected tag SHOULD be done in constant time.

## The Init Function

~~~
Init(k, iv)
~~~

The `Init` function constructs the initial state `{S0, ...S7}` using the key `k` and the nonce `iv`.

Inputs:

- `k`: the encryption key
- `iv`: the nonce

Defines:

- `{S0, ...S7}`: the initial state

Steps:

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

## The Update Function

~~~
Update(M0, M1)
~~~

The `Update` function is the core of the AEGIS-128L algorithm.
It updates the state `{S0, ...S7}` using two 128-bit values.

Inputs:

- `M0`: the first 128-bit block to be absorbed
- `M1`: the second 128-bit block to be absorbed

Modifies:

- `{S0, ...S7}`: the state

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

- `xi`: the 256-bit encrypted input block

Outputs:

- `ci`: the 256-bit decrypted block

Steps:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(xi, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(t0, t1)
ci = out0 || out1
~~~

## The Dec Function

~~~
Dec(ci)
~~~

The `Dec` function decrypts a 256-bit input block `ci` using the state `{S0, ...S7}`.

Inputs:

- `ci`: the 256-bit encrypted input block

Outputs:

- `xi`: the 256-bit decrypted block

Steps:

~~~
z0 = S6 ^ S1 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(ci, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(out0, out1)
xi = out0 || out1
~~~

## The DecPartial Function

~~~
DecPartial(cn)
~~~

The `DecPartial` function decrypts the last ciphertext bits `cn` using the state `{S0, ...S7}`, when they do not fill an entire block.

Inputs:

- `cn`: the encrypted input

Outputs:

- `xn`: the decryption of `cn`

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
~~~

## The Finalize Function

~~~
Finalize(adlen, mlen)
~~~

The `Finalize` function computes a 128-bit tag that authenticate the message as well as the associated data.

Inputs:

- `adlen`: the length of the associated data in bits
- `mlen`: the length of the message in bits

Outputs:

- `tag`: the authentication tag

Steps:

~~~
t = S2 ^ (LE64(adlen) || LE64(mlen))

Repeat(7, Update(t, t))

tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
~~~

# The AEGIS-256 Algorithm

AEGIS-256 has a 768-bit state, made of six 128-bit blocks `{S0, ...S5}`.

The parameters for this algorithm, as defined in {{!RFC5116, Section 4}} are:

- `K_LEN` (key length) is 32 octets
- `P_MAX` (maximum length of the plaintext) is 2<sup>61</sup> octets
- `A_MAX` (maximum length of the associated data) is 2<sup>61</sup> octets
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = 32 octets
- `C_MAX` (maximum ciphertext length) = `P_MAX` + tag length = 2<sup>61</sup> + 16 octets

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} shall be unambiguously encoded as a single input.
It is up to the application to create a structure in the associated data input if it is needed.

## Authenticated Encryption

~~~
Encrypt(m, ad, k, iv)
~~~

The `Encrypt` function encrypts a message and returns the ciphertext along with an authentication tag that verifies the authenticity of the message and, if provided, of associated data.

Inputs:

- `m`: the message to be encrypted
- `ad`: the associated data to authenticate
- `k`: the encryption key
- `iv`: the public nonce

Outputs:

- `c`: the ciphertext
- `tag`: the authentication tag

Steps:

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

## Authenticated Decryption

The `Decrypt` function decrypts a ciphertext, verifies that the authentication tag is correct, and returns the message on success, or an error if tag verification failed.

~~~
Decrypt(c, tag, ad, k, iv)
~~~

Inputs:

- `c`: the ciphertext to be decrypted
- `ad`: the associated data to authenticate
- `k`: the encryption key
- `iv`: the public nonce

Outputs:

- either `m`: the message, or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
Init(k, iv)

m = {}

ad_blocks = Split(Pad(ad, 128), 128)
for xi in ad_blocks:
    Enc(xi)

c_blocks = Split(Pad(c, 128), 128)
cn = Tail(c, |c| mod 128)

for ci in c_blocks:
    m = m || Dec(ci)

if cn is not empty:
    m = m || DecPartial(cn)

expected_tag = Finalize(|ad|, |m|)
~~~

The comparison of the authentication tag `tag` with the expected tag SHOULD be done in constant time.

## The Init Function

~~~
Init(k, iv)
~~~

The `Init` function constructs the initial state `{S0, ...S5}` using the key `k` and the nonce `iv`.

Inputs:

- `k`: the encryption key
- `iv`: the nonce

Defines:

- `{S0, ...S5}`: the initial state

Steps:

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

## The Update Function

~~~
Update(M)
~~~

The `Update` function is the core of the AEGIS-256 algorithm.
It updates the state `{S0, ...S5}` using a 128-bit value.

Inputs:

- `M`: the block to be absorbed

Modifies:

- `{S0, ...S5}`: the state

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

- `xi`: the encrypted input block

Outputs:

- `ci`: the decrypted block

Steps:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)

Update(xi)

ci = xi ^ z
~~~

## The Dec Function

~~~
Dec(ci)
~~~

The `Dec` function decrypts a 128-bit input block `ci` using the state `{S0, ...S5}`.

Inputs:

- `ci`: the encrypted input block

Outputs:

- `xi`: the decrypted block

Steps:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)

xi = ci ^ z

Update(xi)
~~~

It returns the 128-bit block `out`.

## The DecPartial Function

~~~
DecPartial(cn)
~~~

The `DecPartial` function decrypts the last ciphertext bits `cn` using the state `{S0, ...S5}`, when they do not fill an entire block.

Inputs:

- `cn`: the encrypted input

Outputs:

- `xn`: the decryption of `cn`

Steps:

~~~
z = S1 ^ S4 ^ S5 ^ (S2 & S3)

t = Pad(ci, 128)
out = t ^ z

xn = Truncate(out, |cn|)

v = Pad(xn, 128)
Update(v)
~~~

## The Finalize Function

~~~
Finalize(adlen, mlen)
~~~

The `Finalize` function computes a 128-bit tag that authenticate the message as well as the associated data.

Inputs:

- `adlen`: the length of the associated data in bits
- `mlen`: the length of the message in bits

Outputs:

- `tag`: the authentication tag

Steps:

~~~
t = S3 ^ (LE64(adlen) || LE64(mlen))

Repeat(7, Update(t))

tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
~~~

# Encoding (c, tag) Tuples

Applications MAY keep the ciphertext and the 128-bit authentication tag in distinct structures, or encode both as a single string.

In the later case, the tag is expected to immediately follow the ciphertext:

~~~
combined_ciphertext = c || tag
~~~

# Security Considerations

Both algorithms MUST be used in a nonce-respecting setting: for a given key `k`, a nonce MUST only be used once. Failure to do so would immediately reveal the bitwise difference between two messages.

The nonce `iv` does not have to be secret nor unpredictable. It can be a counter, the output of a permutation, or a generator with a long period.

With AEGIS-128L, random nonces can safely encrypt up to 2<sup>32</sup> messages using the same key with negligible collision probability.

With AEGIS-256, random nonces can be used with no practical limits.

Under the assumption that the secret key is unknown to the attacker and the tag is not truncated, both AEGIS-128L and AEGIS-256 target 128-bit security against forgery attacks.

AEGIS-256 offers 256-bit message security against plaintext and state recovery. AEGIS-128L offers 128-bit security. They are both key-committing.

The security of AEGIS against timing attacks is limited by the implementation of the underlying `AESRound()` function. Failure to implement `AESRound()` in a fashion safe against side-channel attacks, such as differential power analysis or timing attacks, may likely lead to leaking secret key material or state information. The exact mitigations required for side-channel attacks also depend on the threat model in question.

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

iv   : 00000000000000000000000000000000

ad   :

m    : 00000000000000000000000000000000

c    : 41de9000a7b5e40e2d68bb64d99ebb19

tag  : f4d997cc9b94227ada4fe4165422b1c8
~~~

### Test Vector 2

~~~
key  : 00000000000000000000000000000000

iv   : 00000000000000000000000000000000

ad   :

m    :

c    :

tag  : 83cc600dc4e3e7e62d4055826174f149
~~~

### Test Vector 3

~~~
key  : 10010000000000000000000000000000

iv   : 10000200000000000000000000000000

ad   : 0001020304050607

m    : 000102030405060708090a0b0c0d0e0f
       101112131415161718191a1b1c1d1e1f

c    : 79d94593d8c2119d7e8fd9b8fc77845c
       5c077a05b2528b6ac54b563aed8efe84

tag  : cc6f3372f6aa1bb82388d695c3962d9a
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

iv   : 00000000000000000000000000000000
       00000000000000000000000000000000

ad   :

m    : 00000000000000000000000000000000

c    : b98f03a947807713d75a4fff9fc277a6

tag  : 478f3b50dc478ef7d5cf2d0f7cc13180
~~~

### Test Vector 2

~~~
key  : 00000000000000000000000000000000
       00000000000000000000000000000000

iv   : 00000000000000000000000000000000
       00000000000000000000000000000000

ad   :

m    :

c    :

tag  : f7a0878f68bd083e8065354071fc27c3
~~~

### Test Vector 3

~~~
key  : 10010000000000000000000000000000
       00000000000000000000000000000000

iv   : 10000200000000000000000000000000
       00000000000000000000000000000000

ad   : 0001020304050607

m    : 000102030405060708090a0b0c0d0e0f
       101112131415161718191a1b1c1d1e1f

c    : f373079ed84b2709faee373584585d60
       accd191db310ef5d8b11833df9dec711

tag  : 8d86f91ee606e9ff26a01b64ccbdd91d
~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge

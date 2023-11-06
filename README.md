# The AEGIS Family Of Authenticated Encryption Algorithms

This is the working area for the individual Internet-Draft, "The AEGIS family of authenticated encryption algorithms".

* [Editor's Copy](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/#go.draft-irtf-cfrg-aegis-aead.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead)
* [Compare Editor's Copy to Individual Draft](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/#go.draft-irtf-cfrg-aegis-aead.diff)

## Known Implementations

| Name                                                                                                                                | Language   |
| ----------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| [This document's reference implementations](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead/tree/main/reference-implementations) | Zig        |
| [CAESAR reference AEGIS-128L implementations](https://github.com/jedisct1/supercop/tree/master/crypto_aead/aegis128l)               | C          |
| [CAESAR reference AEGIS-256 implementations](https://github.com/jedisct1/supercop/tree/master/crypto_aead/aegis256)                 | C          |
| [Linux kernel](https://cregit.linuxsources.org/code/5.0/arch/x86/crypto/aegis128l-aesni-glue.c.html)                                | C          |
| [libsodium](https://libsodium.org)                                                                                                  | C          |
| [angt/aegis256](https://github.com/angt/aegis256)                                                                                   | C          |
| [TwoEightNine/aegis](https://github.com/TwoEightNine/aegis)                                                                         | C          |
| [libaegis](https://github.com/jedisct1/libaegis)                                                                                    | C          |
| [google/aegis-cipher](https://github.com/google/aegis_cipher)                                                                       | C++        |
| [aegis](https://crates.io/crates/aegis)                                                                                             | Rust       |
| [Zig standard library](https://github.com/ziglang/zig/blob/master/lib/std/crypto/aegis.zig)                                         | Zig        |
| [x13a/py-aegis](https://github.com/x13a/py-aegis)                                                                                   | Python     |
| [ericlagergren/aegis](https://github.com/ericlagergren/aegis)                                                                       | Go         |
| [samuel-lucas6/AEGIS.NET](https://github.com/samuel-lucas6/AEGIS.NET)                                                               | C#         |
| [aegis-js](https://github.com/psve/aegis-js)                                                                                        | JavaScript |
| [aegis-kotlin](https://github.com/psve/aegis-kotlin)                                                                                | Kotlin     |
| [aegis-jasmin](https://github.com/jedisct1/aegis-jasmin)                                                                            | Jasmin     |

## AEGIS support in TLS stacks

- [Experimental support for BoringSSL](https://github.com/jedisct1/boringssl/tree/aegis)
- [Facebook's Fizz](https://github.com/facebookincubator/fizz)
- [PicoTLS](https://github.com/h2o/picotls)
- [Zig TLS client](https://ziglang.org/documentation/master/std/#A;std:crypto.tls.CipherSuite)

## Test vectors

For convenience, test vectors can be downloaded in JSON format from the [`test-vectors` directory](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead/tree/main/test-vectors).

Google's Project Wycheproof includes additional test vectors:

* [for AEGIS-128L](https://github.com/google/wycheproof/blob/master/testvectors/aegis128L_test.json)
* [for AEGIS-256](https://github.com/google/wycheproof/blob/master/testvectors/aegis256_test.json)

## Contributing

See the
[guidelines for contributions](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).


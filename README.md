# The AEGIS Family Of Authenticated Encryption Algorithms

This is the working area for the individual Internet-Draft, "The AEGIS family of authenticated encryption algorithms".

* [Editor's Copy](https://jedisct1.github.io/draft-aegis-aead/#go.draft-denis-aegis-aead.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-denis-aegis-aead)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-denis-aegis-aead)
* [Compare Editor's Copy to Individual Draft](https://jedisct1.github.io/draft-aegis-aead/#go.draft-denis-aegis-aead.diff)


# Known Implementations

| Name                                                                                                                          | Language |
| ----------------------------------------------------------------------------------------------------------------------------- | -------- |
| [This document's reference implementations](https://github.com/jedisct1/draft-aegis-aead/tree/main/reference-implementations) | Zig      |
| [CAESAR reference AEGIS-128L implementations](https://github.com/jedisct1/supercop/tree/master/crypto_aead/aegis128l)         | C        |
| [CAESAR reference AEGIS-256 implementations](https://github.com/jedisct1/supercop/tree/master/crypto_aead/aegis256)           | C        |
| [Linux kernel](https://cregit.linuxsources.org/code/5.0/arch/x86/crypto/aegis128l-aesni-glue.c.html)                          | C        |
| [`libsodium`](https://libsodium.org)                                                                                          | C        |
| [`angt/aegis256`](https://github.com/angt/aegis256)                                                                           | C        |
| [`TwoEightNine/aegis`](https://github.com/TwoEightNine/aegis)                                                                 | C        |
| [`google/aegis-cipher`](https://github.com/google/aegis_cipher)                                                               | C++      |
| [`aegis`](https://crates.io/crates/aegis)                                                                                     | Rust     |
| [Zig standard library](https://github.com/ziglang/zig/blob/master/lib/std/crypto/aegis.zig)                                   | Zig      |

## Contributing

See the
[guidelines for contributions](https://github.com/jedisct1/draft-aegis-aead/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).


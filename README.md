# The AEGIS Authenticated Encryption Algorithm

This is the working area for the individual Internet-Draft, "The AEGIS authenticated encryption algorithm".

* [Editor's Copy](https://dip-proto.github.io/ad/#go.draft-aegis-aead.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-aegis-aead)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-aegis-aead)
* [Compare Editor's Copy to Individual Draft](https://dip-proto.github.io/ad/#go.draft-aegis-aead.diff)


# Known Implementations

| Name                                                                                                         | Language |
| ------------------------------------------------------------------------------------------------------------ | -------- |
| [Reference AES-128L implementations](https://github.com/jedisct1/supercop/tree/master/crypto_aead/aegis128l) | C        |
| [Reference AES-256 implementations](https://github.com/jedisct1/supercop/tree/master/crypto_aead/aegis256)   | C        |
| [Zig standard library](https://github.com/ziglang/zig/blob/master/lib/std/crypto/aegis.zig)                  | Zig      |
| [Linux kernel](https://cregit.linuxsources.org/code/5.0/arch/x86/crypto/aegis128l-aesni-glue.c.html)         | C        |
| [`libsodium`](https://libsodium.org)                                                                         | C        |
| [`aegis-cipher`](https://github.com/google/aegis_cipher)                                                     | C        |
| [`aegis256`](https://github.com/angt/aegis256)                                                               | C        |
| [`aegis`](https://crates.io/crates/aegis)                                                                    | Rust     |


## Contributing

See the
[guidelines for contributions](https://github.com/jedisct1/draft-aegis-aead/blob/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).


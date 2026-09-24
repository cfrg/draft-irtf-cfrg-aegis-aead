# Early adopters of AEGIS (RFC 10032)

Early adopters of the AEGIS family of authenticated encryption algorithms include Meta, Google Cloud, OVHcloud, Surfshark, Tigerbeetle and Turso, alongside the projects listed below.

- [Early adopters of AEGIS (RFC 10032)](#early-adopters-of-aegis-rfc-10032)
  - [Standards and recommendations](#standards-and-recommendations)
  - [Companies and products](#companies-and-products)
  - [Coverage and interviews](#coverage-and-interviews)
  - [Databases and storage](#databases-and-storage)
  - [Networking and VPNs](#networking-and-vpns)
  - [File encryption tools](#file-encryption-tools)

In the tables, **all six** means AEGIS-128L, AEGIS-256, AEGIS-128X2, AEGIS-128X4, AEGIS-256X2, and AEGIS-256X4.

## Standards and recommendations

[ETSI](https://www.etsi.org/about/), the European Telecommunications Standards Institute, is a standards organization recognized by the European Union that develops global standards for telecommunications, cybersecurity, and other digital technologies.

| Organization or document                                                                                                                                                                                               | Status                                                 | AEGIS coverage                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [IRTF CFRG: RFC 10032](https://www.rfc-editor.org/rfc/rfc10032.html)                                                                                                                                                   | Informational RFC, September 2026                      | Specifies AEGIS-128L, AEGIS-256, and the parallel AEGIS-128X and AEGIS-256X modes.                                                                     |
| [ETSI EN 304 620: VPNs](https://docbox.etsi.org/CYBER/EUSR/Open/EN_304-620_v1.0.0_2026-08-12_Virtual-Private-Networks_Enquiry-draft.pdf#page=168)                                                                      | Enquiry draft, August 2026                             | Annex K lists AEGIS-128, AEGIS-128L, AEGIS-256, and AEGIS-256X among extended cryptographic mechanisms for authenticated encryption and VPN protocols. |
| [ETSI EN 304 625: network interfaces](https://docbox.etsi.org/CYBER/EUSR/Open/EN_304-625_V1.0.0_2026-08-10_Network-Interfaces_Enquiry-draft.pdf#page=109)                                                              | Enquiry draft, August 2026                             | Annex K includes the same AEGIS variants among extended cryptographic mechanisms.                                                                      |
| [ETSI EN 304 619: antivirus software](https://docbox.etsi.org/CYBER/EUSR/Open/EN_304-619_V1.0.0_2026-07-15_Antivirus-Enquiry-draft.pdf#page=158)                                                                       | Enquiry draft, July 2026                               | Annex K lists a 256-bit mechanism named “AEGIS-X2” for authenticated encryption.                                                                       |
| [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x92-Appendix-C_Cryptography.md#authenticated-encryption)                                                                                    | Published, May 2025                                    | Appendix C lists AEGIS-128, AEGIS-128L, and AEGIS-256 as approved authenticated encryption algorithms.                                                 |
| [Belgian Data Protection Authority](https://www.autoriteprotectiondonnees.be/publications/avis-n-49-2023.pdf#page=15)                                                                                                  | Opinion 49/2023, March 2023                            | Recommends AEGIS-256 for authenticated encryption when communicating personal data concerning offenses (page 15, footnote 50).                         |
| [IANA AEAD Algorithms registry](https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml)                                                                                                                | Assigned identifiers                                   | IDs 32 through 37 cover all six variants.                                                                                                              |
| [IANA TLS Cipher Suites registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)                                                                                               | Assigned identifiers                                   | `0x1306`: `TLS_AEGIS_256_SHA512`; `0x1307`: `TLS_AEGIS_128L_SHA256`.                                                                                   |
| [CAESAR competition](https://competitions.cr.yp.to/caesar-submissions.html)                                                                                                                                            | Final portfolio, 2019                                  | Selected AEGIS-128 for high-performance applications; AEGIS-128L and AEGIS-256 were additional finalists.                                              |
| [AEGIS cipher suites for TLS, DTLS, and QUIC](https://datatracker.ietf.org/doc/draft-denis-tls-aegis/)                                                                                                                 | Individual Internet-Draft, revision 07, September 2026 | Proposes AEGIS-128L and AEGIS-256 suites.                                                                                                              |
| [IRTF CFRG: RFC 9771](https://www.rfc-editor.org/rfc/rfc9771.html)                                                                                                                                                     | Informational RFC, May 2025                            | Uses AEGIS as an example of AEAD properties, including multi-user and quantum security.                                                                |
| [Ericsson proposal at the NIST Block Cipher Modes workshop](https://csrc.nist.gov/csrc/media/Presentations/2023/proposal-for-standardization-of-encryption-schemes/images-media/sess-4-mattsson-bcm-workshop-2023.pdf) | Standardization proposal, 2023                         | Ericsson researchers recommend standardizing AEGIS.                                                                                                    |

The original AEGIS-128, named in some of these documents, is distinct from AEGIS-128L and is not specified by RFC 10032.

## Companies and products

| Company or product                                                                | How it uses AEGIS                                                                                                                               | Variants                                        |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| [Meta](https://github.com/facebookincubator/fizz)                                 | Optional AEGIS cipher suites in Meta's TLS 1.3 stack.                                                                                           | AEGIS-128L, AEGIS-256, AEGIS-128X2, AEGIS-128X4 |
| [Google Cloud](https://cloud.google.com/)                                         | Data-at-rest encryption, reported in the description of Bill Buchanan's interview with AEGIS co-designer Bart Preneel.                          | Not specified                                   |
| [OVHcloud / OverTheBox](https://www.ovhcloud.com/fr/internet/overthebox/)         | Encrypted internet-connection aggregation through [Glorytun](https://github.com/angt/glorytun), which uses AEGIS-256 on AES-NI-capable systems. | AEGIS-256                                       |
| [Surfshark Dausos](https://surfshark.com/features/surfshark-vpn-protocols/dausos) | VPN protocol using AEGIS for tunnel encryption.                                                                                                 | AEGIS-256X2                                     |
| [Turso Cloud](https://turso.tech/)                                                | Customer-supplied keys for database and write-ahead log encryption.                                                                             | All six                                         |
| [TigerBeetle](https://tigerbeetle.com)                                            | Storage and message checksums using an AEGIS MAC with a fixed zero key; this use does not encrypt data.                                         | AEGIS-128L MAC                                  |
| [S2 and s2-lite](https://s2.dev/)                                                 | Customer-supplied-key record encryption in the cloud service and self-hosted stream store.                                                      | AEGIS-256                                       |
| [Category Labs / Monad](https://www.category.xyz/)                                | Authenticated UDP transport in monad-bft's Noise-based protocol.                                                                                | AEGIS-128L                                      |
| [NordVPN (NepTUN / libtelio)](https://nordvpn.com/)                               | AEGIS [cipher negotiation](https://github.com/NordSecurity/libtelio/pull/1988) for the NepTUN VPN engine.                                       | AEGIS-256, AEGIS-256X2, AEGIS-256X4             |

## Coverage and interviews

- [Surfshark's Dausos launch announcement](https://surfshark.com/blog/surfshark-launches-a-vpn-protocol) describes its use of AEGIS-256X2 for VPN encryption.
- [Bill Buchanan interviews Bart Preneel](https://www.youtube.com/watch?v=GOHc8dITEQA), an AEGIS co-designer; the interview's published description reports Google Cloud's use of AEGIS for data-at-rest encryption.
- [Turso introduces native database encryption](https://turso.tech/blog/introducing-fast-native-encryption-in-turso-database), including its choice of AEGIS and performance measurements.
- [S2: Your data, your keys](https://s2.dev/blog/encryption) explains customer-supplied-key encryption and recommends AEGIS-256 for stream records.

## Databases and storage

| Project or company                                                             | How it uses AEGIS                                                                             | Variants                                                     |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| [Turso Database](https://github.com/tursodatabase/turso)                       | Native database and write-ahead log encryption.                                               | All six                                                      |
| [Hoodik / Hoodik Cloud](https://hoodik.io/)                                    | Default cipher for end-to-end file encryption.                                                | AEGIS-128L                                                   |
| [SQLite3MultipleCiphers](https://utelle.github.io/SQLite3MultipleCiphers/)     | Optional database page encryption for SQLite.                                                 | All six                                                      |
| [Devolutions Ahtola](https://github.com/Devolutions/ahtola)                    | Turso-compatible database page encryption in its C# database engine; integration merged.      | All six                                                      |
| [AgentFS](https://www.agentfs.ai) and [AppFS](https://github.com/esp3j0/appfs) | Optional encryption of the local database backing the filesystem.                             | All six                                                      |
| [Dataflare](https://dataflare.app)                                             | Database manager with encrypted Turso connection options.                                     | All six                                                      |
| [Omnidraw](https://github.com/omnidraw/omnidraw)                               | Encrypted databases for the canvas application's secret-store resources.                      | AEGIS-256                                                    |
| [OrcaCD](https://orcacd.dev)                                                   | Docker GitOps tool encrypting stored database values.                                         | AEGIS-256                                                    |
| [Linux dm-crypt / cryptsetup](https://gitlab.com/cryptsetup/cryptsetup)        | Authenticated disk encryption for LUKS2 volumes.                                              | AEGIS-128                                                    |
| [KeyLox](https://github.com/MangoLambda/KeyLox)                                | Credential encryption in a terminal password manager.                                         | AEGIS-256                                                    |
| [memelord](https://github.com/glommer/memelord)                                | [Configurable encryption](https://github.com/glommer/memelord/pull/8) for its Turso database. | AEGIS-128L, AEGIS-128X2, AEGIS-128X4, AEGIS-256, AEGIS-256X2 |

## Networking and VPNs

See also the README's [AEGIS support in TLS stacks](README.md#aegis-support-in-tls-stacks) for Fizz, picotls, and other TLS integrations.

| Project or company                                                                     | How it uses AEGIS                                                                                          | Variants              |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------- |
| [Chameleon-PQ](https://github.com/btdt1983/chameleon-pq)                               | VPN with AEGIS or ChaCha20-Poly1305 selected according to hardware and performance.                        | AEGIS-256X2           |
| [H2O](https://h2o.examp1e.net)                                                         | Optional AEGIS TLS support in the HTTP server through [picotls](https://github.com/h2o/picotls).           | AEGIS-128L, AEGIS-256 |
| [picoquic](https://github.com/private-octopus/picoquic)                                | Optional AEGIS cipher suites for TLS and QUIC.                                                             | AEGIS-128L, AEGIS-256 |
| [mihomo](https://wiki.metacubex.one) and [Clash Verge Rev](https://www.clashverge.dev) | Proxy core and client with optional AEGIS Shadowsocks methods.                                             | AEGIS-128L, AEGIS-256 |
| [Chute](https://chute.life/)                                                           | Optional, nonstandard Shadowsocks methods requiring a compatible server.                                   | AEGIS-128L, AEGIS-256 |
| [glorytun](https://github.com/angt/glorytun)                                           | VPN encryption when AES-NI is available, with a ChaCha20-Poly1305 fallback.                                | AEGIS-256             |
| [tigertunnel](https://github.com/jedisct1/tigertunnel)                                 | Encrypted TCP tunnel for TigerBeetle.                                                                      | AEGIS-128X2           |
| [floo](https://yux.github.io/floo/)                                                    | Forward and reverse tunnel with selectable ciphers; defaults to AEGIS-128L.                                | All six               |
| [QuicFuscate](https://github.com/Christopher-Schulze/QuicFuscate)                      | Optional AEGIS payload protection, separate from its TLS/QUIC cipher suites.                               | AEGIS-128L            |
| [RADDI](https://www.raddi.net)                                                         | Peer transport encryption in the decentralized discussion network.                                         | AEGIS-256             |
| [snake-net](https://github.com/sem-hub/snake-net)                                      | Optional VPN encryption engine enabled with the `aegis` build tag.                                         | AEGIS-128L            |
| [Prodigy](https://github.com/victorstewart/prodigy)                                    | Encryption of paired-service communication in its application orchestration platform.                      | AEGIS-128L            |
| [otou](https://github.com/Urist-McDeveloper/otou)                                      | Packet encryption for an IPv4 tunnel over UDP.                                                             | AEGIS-128L            |
| [moss](https://github.com/mylanconnolly/moss)                                          | Encrypts communication between nodes and protects user identity seeds in its microkernel operating system. | AEGIS-128L, AEGIS-256 |
| [drasyl-rs](https://github.com/mikalv/drasyl-rs)                                       | Peer-to-peer message encryption.                                                                           | AEGIS-256X2           |

## File encryption tools

| Project                                                                                               | How it uses AEGIS                                                                            | Variants              |
| ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------- |
| [TurboCrypt](https://github.com/jedisct1/turbocrypt)                                                  | File, directory, Git repository, and mounted-container encryption.                           | AEGIS-128X2           |
| [asymcrypt](https://github.com/jedisct1/rust-asymcrypt)                                               | File and stream encryption combined with X-Wing key encapsulation.                           | AEGIS-128X2           |
| [hf-mount-encrypted](https://github.com/jedisct1/hf-mount-encrypted)                                  | Independent hf-mount fork adding client-side file encryption for Hugging Face bucket mounts. | AEGIS-128X2           |
| [Kryp](https://github.com/babico/kryp)                                                                | File encryption with selectable AEGIS algorithms.                                            | AEGIS-128L, AEGIS-256 |
| [ThreeKnights CRP / CRP Pro](https://play.google.com/store/apps/details?id=io.threeknights.crp&hl=en) | Android file and text encryption; AEGIS-256 is offered in CRP Pro.                           | AEGIS-128L, AEGIS-256 |
| [GitFoil](https://github.com/code-of-kai/git-foil)                                                    | A layer of authenticated encryption for files stored in Git repositories.                    | AEGIS-256             |

Cryptographic libraries and language bindings are listed separately in the README's [known implementations](README.md#known-implementations).

Additions and corrections are welcome.

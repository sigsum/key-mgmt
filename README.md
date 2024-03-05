# Key management

This repository provides documentation and tooling for managing and accessing
the private signing keys in the Sigsum system.

## Documentation

  - [Quick start](./docs/quick-start.md) instructions on YubiHSM provisioning
    and signing for log servers and witnesses via SSH agent.
  - [Key management](./docs/key-management.md) procedure using YubiHSMs

## Repository overview

  - [sigsum-agent](./cmd/sigsum-agent) A program that can act as a signing
    oracle, following the SSH agent protocol and conventions. Tailored to the
    needs of the Sigsum system, it supports Ed25519 signatures only, and it can
    use either a private key on disk, or a key stored in a YubiHSM (support for
    other types hardware keys, in particular TKey and Yubikey, is under
    consideration).
  - [provisioning scripts](./scripts) A collection of scripts to provision
    YubiHSMs for use with Sigsum logs and witnesses.
  - To appear: SSH key and signature formats as importable Go packages

## Contact

  - IRC room `#sigsum` @ OFTC.net
  - Matrix room `#sigsum` which is bridged with IRC
  - The [sigsum-general][] mailing list

[sigsum-general]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-general.lists.sigsum.org/

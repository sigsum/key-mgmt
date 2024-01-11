# Key management

This repository provides documentation and tooling for key management useful in
the Sigsum system.  For example, a Go implementation of SSH formatted Ed25519
keys, signatures, and a minimal SSH agent compatible with YubiHSMs are included.

## Overview

  - [Quick start](./docs/quick-start.md) instructions on YubiHSM provisioning
    and signing for log servers and witnesses via SSH agent.
  - [Key management](./docs/key-management) procedure using YubiHSMs
  - To appear: SSH key and signature formats as importable Go packages

## Contact

  - IRC room `#sigsum` @ OFTC.net
  - Matrix room `#sigsum` which is bridged with IRC
  - The [sigsum-general][] mailing list

[sigsum-general]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-general.lists.sigsum.org/

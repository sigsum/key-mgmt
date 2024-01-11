# Releases

## What is being released

The following programs are releases and supported:

  - `scripts/`
  - `cmd/yubihsm-agent`

Releases are announced on the [sigsum-announce][] mailing list. The [NEWS
file](./NEWS) documents the user visible changes for each release, the
recommended upgrade procedure, and components tested for interoperability.

Note that a release is simply a git-tag specified on our mailing list.  There
may be intermediate git-tags between two advertised releases.  These
intermediate tags are **not** released and supported.

The key-mgmt Go module only contains internal libraries.  By the terms of the
LICENSE file you are free to use this code "as is" in almost any way you like.
However, we support its use **only** via the `yubihsm-agent` program for now.
We don't aim to provide any backwards compatibility for internal interfaces.

We encourage use of the key management strategy described in this repository,
including use of the released scripts for provisioning and `yubihsm-agent` to
integrate with the SSH-agent protocol that Sigsum logs and witnesses support.

[sigsum-announce]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-announce.lists.sigsum.org/

## What release cycle is used

We don't anticipate there to be many upcoming feature releases.  Therefore,
there is no release cycle.  If something new becomes available is is released.

In case critical bugs are discovered, we intend to provide bug-fix-only updates
for the latest release in a timely manner.  Backporting bug-fixes to older
releases than the latest one will be considered on a case-by-case basis.

## Upgrading from a previous release

You are expected to upgrade linearly from one advertised release to the next
advertised release, e.g., from v0.1.2 to v0.3.6.  We strive to make such linear
upgrades easy and well-documented to help with forward-compatibility.  Any
complications that are caused by changed command-line flags or similar will be
outlined clearly in the [NEWS files](./NEWS).  Pay close attention to the
"Breaking changes" section for these migration notes (if any).

## Planned changes

  - Make formats related to SSH private keys and signatures available as
    importable Go packages (rather than keeping them in `/internal`).

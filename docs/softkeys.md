
# ML-DSA-44 for Post-Quantum secure cosignatures

This document provides a strategy for managing a soft ML-DSA-44 witness key.  A
*soft key* is a key that is stored as a file on disk.  When mentioning a signing
key or private key (file) in the following text, such *soft key* is always
meant.  If you have the option of using an ML-DSA-44 key in a separate hardware
domain, please do that instead.


## Overview

1. The signing key is generated with at least 128 bits of "good" entropy.
2. Signing requires access to a soft key stored on disk.  This signing key is
   only accessible to root and the user/group that needs access to it.  This
   signing key is, for the purpose of backup only, encrypted with a passphrase
   that is also stored on disk.  The passphrase shall as well have some 128 bits
   of entropy.
3. Re-provisioning the signing key requires access to an encrypted backup and
   the corresponding passphrase.  The passphrase and the encrypted backup are
   never stored in the same backup location, making key recovery harder.
4. A single trusted operator can gain access to the signing key on the running
   system, as well as to the encrypted backup and its passphrase.  In other
   words, we are not trying to protect against an operator that is malicious.

The attacker's goal is to recover the signing key.  The easiest ways to achieve
this is by gaining root access to the system, compromising specific witness
software component(s), or breaching two separate backup sites.  All of these
attack vectors are considered "hard" in our setting, as elaborated on further
below.

We assume randomness produced by a TKey is "good".

We assume the attacker is unable to breach two backup sites without detection.
Similar to above, this is because of physical security boundaries like locks,
alarms, safes, and tamper-evident bags.

An attacker being able to mount various types of physical attacks without
detection is out of scope.  Like getting a copy of the system's disk, being in a
position to inspect RAM at runtime, resetting the BIOS password, or tampering
with the server's hardware.

Any attacker that is able to gain root access is out of scope.  It is however in
scope to make it "hard" to gain root access.  Such hardening is not the primary
focus of this document, but a few examples are mentioned towards the end.

Any attacker that is able to compromise the witness software is too powerful.
So, it's crucial that the operators only deploy benign witness software.  We
consider this attack vector "hard" because our intended operator knows the
deployed software in detail, and only deploys code that has gone through manual
code review.


## Key generation

Private key files will be stored in OpenSSH private key format, using its
built-in passphrase encryption (bcrypt-pbkdf).  Modelled after Ed25519, the file
stores the private key seed.  Our `sigsum-agent` can load such files.

The ML-DSA-44 private key file will be created using our `genkey-mldsa44` tool.
When paired with [`tkey-random-generator`](https://github.com/tillitis/tkey-random-generator).
Our tool will be run on the remote live-system (for example a witness server),
use entropy from the TRNG of a TKey in local machine, mixed (HKDF) with entropy
from the live-system.

Key generation will be done using a local provisioning machine with a TKey,
which connects to the live-system over a Wireguard-tunnel with PSK (pre-shared
key).  Thus having PQ-resistance while providing the remote live-system entropy
(from TKey) for private key seed and passphrase.  See also the section on
Backup.  This is deemed equivalent to first doing key generation on an
"air-gapped" machine (with no network access), and then using a networked
machine to transfer both private key and its passphrase to the remote
live-system -- an attacker being "present" on any one of these two machines
(either now, or in the future after having decrypted a dump of tunnel traffic)
would have access to both key and passphrase.

(If we have OpenSSH 10.6 everywhere, an option could be to use ssh's
mlkem768x25519-sha256 for key-exchange, and ssh-mldsa44-ed25519 for host/user
authentication, especially if we could have the latter in a hardware device; but
we don't).

## Passphrase

When generating the private key file, `genkey-mldsa44` by default prompts the
user to enter a new passphrase for encrypting the key at rest.  For example, 32
random hex digits (16 bytes of data) from a TKey would yield 128 bits of
entropy.


## Provisioning and operation

Our tools will help us generate and store the private key on the disk of the
live-system.  The private key will be encrypted with a passphrase, but this is
only for backup purposes -- the passphrase will also be stored on the disk.

The tools will make available locally the encrypted private key, and the
passphrase.  These are to be stored on two other, separate backup sites.


## Backup considerations

To allow for recovering from failures, while at the same time raising the bar
for what an attacker must compromise in order to get hold of a decrypted private
key, the private key file will be encrypted using a passphrase.  The items will
be stored in the following way, for use during operation, and for backup:

```
<location>: <item>
livesystem-disk: passphrase
livesystem-disk: private key
backupsite1: passphrase
backupsite2: private key
provisioning-ansible: NO private keys, NO passphrases
```

This lets us recover if one, but no more, of the following sites burning down:
livesystem, backupsite1, and backupsite2.  Attacker must compromise both two
backup sites, or get root and fully own livesystem.


## Provisioning procedure

### Equipment:
 - 1x local provisioning machine
 - 1x TKey, dedicated for softkey generation
 - ssh access over Wireguard+PSK tunnel to target machine, live-system
 - 2x USB sticks for backup, or only 1, if passphrase kept using pen on paper
 - Tamper-evident bags
 - 2x physically secure locations for USB sticks for backup

The script in [../scripts/provision-softkey](../scripts/provision-softkey)
carries out generation and provisioning.

Overall, TKey is used locally to generate passphrase and entropy for the private
key seed.  This secret material is provided to the remote target machine over
ssh.

Our `genkey-mlsda44` tool is run on the target machine and creates the private
key by mixing entropy from TKey with entropy from the target machine itself.
The private key is encrypted with using the passphrase, and both written to a
location on target machine's disk.

The new private key and passphrase are delivered to the local machine, written
to ephemeral locations, in `/dev/shm/`.

See the script itself for further details.

After successfully running the provisioning script, the output private key and
passphrase shall be stored on 2 separate USB sticks (one file on each).  The USB
sticks are each kept in a tamper-evident bags, and stored at separate backup
locations.

The TKey used shall be stored in one of the backup locations.  This is
helpful if ever some vulnerability is discovered in the TKey that could affect
us -- we then know exactly which one (version, variant) we used, and that it is
kept in a secure location.

## Considerations

We recommend pairing this key management strategy with relevant system hardening
for preventing privilege escalation and data exfiltration.  This is of course
also relevant when using a hardware-backed signing oracle, but it is of extra
importance here, since we are mitigating extraction of a signing key, not only
of signatures.  On a Debian or Fedora system, examples of hardening could
include using SELinux, DNS/HTTP egress filtering, and ensuring there are no
trivial data exfiltration mechanisms available (like denying regular users from
accessing a configured Postfix).

It is outside the scope of this document to consider if the system deploying the
soft ML-DSA-44 key is resistant to Cryptographically Relevant Quantum Computers
(CRQC).

Overall, the outlined key management strategy pairs well with a deployment that
would otherwise *only* be using a hardware-backed Ed25519.  In other words, with
an Ed25519 and ML-DSA-44 *hybrid policy* the provided security can only improve
against attackers with CRQC.

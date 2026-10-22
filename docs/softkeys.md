
# ML-DSA-44 for Post-Quantum secure cosignatures

This document provides a strategy for managing a soft ML-DSA-44 witness key.  A
*soft key* is a key that is stored as a file on disk.  When mentioning a private
key (file) in the following text, such *soft key* is always meant.  If you have
the option of using an ML-DSA-44 key in a separate hardware domain, please do
that instead.


## Overview

1. The signing key is generated with at least 128 bits of "good" entropy.
2. Signing requires access to a soft key stored on disk.  This signing key is
   only accessible to root and the user/group that needs access to it.  This
   signing key is encrypted with a passphrase that is not stored on the disk.
   The passphrase shall as well have some 128 bits of entropy.
3. Re-provisioning the signing key requires access to an encrypted backup and
   the corresponding passphrase.  The passphrase and the encrypted backup are
   never stored in the same backup location, making key recovery harder.
4. A single trusted operator can gain access to the signing key on the running
   system, as well as to the encrypted backup and its passphrase.  In other
   words, we are not trying to protect against an operator that is malicious.


## Setting

What we try to protect against are mistakes, misconfiguration, failures, and
external threats.  Examples of mistakes and misconfiguration include a backup
job or a system log that accidentally includes the signing key.  Examples of
failures include a backup location that burns down to the ground.  Examples of
external threats include an attacker that manages to execute code remotely.

The attacker's goal is to recover the signing key.  The easiest ways to achieve
this is by gaining root access to the system, compromising specific witness
software component(s), or breaching two separate backup sites.  All of these
attack vectors are considered "hard" in our setting, as elaborated on further
below.


## Assumptions

We assume randomness produced by a TKey is "good".

We assume the attacker can get a copy of the system's disk, e.g., because the
disk broke and was brought outside the usual security perimeter that is
otherwise secured by locks, alarms, and physical tamper-detection mechanisms.

We assume the attacker is unable to mount other types of physical attacks
without detection, such as being in a position to inspect RAM at runtime,
resetting the BIOS password, or tampering with the server's hardware.

We assume the attacker is unable to breach two backup sites without detection.
Similar to above, this is because of physical security boundaries like locks,
alarms, safes, and tamper-evident bags.

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
When paired with [`tkey-random-generator`](https://github.com/tillitis/tkey-random-generator),
our tool will use entropy from the TRNG of a TKey in local machine, mixed (HKDF)
with entropy from (and on) the remote live-system.

Key generation will be done using a local provisioning machine with a TKey,
which connects to the live-system (for example a witness server) over a
Wireguard-tunnel with PSK (pre-shared key).  Thus having PQ-resistance while
providing the remote live-system entropy (from TKey) for private key seed and
passphrase.  See also the section on Backup.  This is deemed equivalent to first
doing key generation on an "air-gapped" (no network access) machine, and then
using a networked machine to transfer both private key and its passphrase to the
remote live-system -- an attacker being "present" on any one of these two
machines (either now, or in the future after having decrypted a dump of tunnel
traffic) would have access to both key and passphrase.

TODO: is ssh's PQ key exchange enough, or we require Wireguard with PSK?
Like `ssh -v -o KexAlgorithms=mlkem768x25519-sha256 target`

## Passphrase

When generating the private key file, `genkey-mldsa44` by default prompts the
user to enter a new passphrase for encrypting the key at rest.  For example, 32
random hex digits (16 bytes of data) from a TKey would yield 128 bits of
entropy.


## Provisioning and operation

Our tools will help us generate and store the private key on the disk of the
live-system.  The passphrase will be stored in an *EFI variable* on this system.
The EFI variables store is smallish key-value like storage managed by UEFI
firmware, it is persistent across reboots, and commonly used for Secure Boot
keys and other boot-related configuration.  The physical storage may be some SPI
flash, or NVRAM chip accessible by the UEFI firmware.

The tools will also make available locally the same private key encrypted with a
different passphrase.  These are to be stored on two other, separate backup
sites.

The passphrase in the EFI variable can be accessed from Linux at
`/sys/firmware/efi/efivars`, which must be limited to root or user that starts
the `sigsum-agent` process.

During startup, a script that reads out the passphrase from the *EFI variable*
is used to pass it to `sigsum-agent` by way of Bash Process Substitution,
something like: `sigsum-agent -k /key/file -p <(passphrase-reader)`.


## Backup considerations

To allow for recovering from failures, while at the same time raising the bar
for what an attacker must compromise in order to get hold of a decrypted private
key, the private key file will be encrypted using two different passphrases.
The items will be stored in the following way, for use during operation, and for
backup:

```
<location>: <item>
livesystem-EFI-variable: passphrase1
livesystem-disk: privkey(passphrase1)
backupsite1: passphrase2
backupsite2: privkey(passphrase2)
provisioning-ansible: NO privkeys, NO passphrases
```

We avoid dealing with the additional complications of storing the private key in
source code repo.  Like using Ansible's vault-encryption, or not; which
passphrase the private key kept there is encrypted with, etc.

Instead we focus on making it smooth to provision the livesystem with
passphrase1 and privkey(passphrase1), and getting also an additional
privkey(passphrase2) for storing at backupsite1, and the passphrase2 at
backupsite2.

It also lets us recover if one, but no more, of the following sites burning
down: livesystem, backupsite1, and backupsite2.  Attacker must compromise both
two backup sites, or get root and fully own livesystem (able to read both
EFI-variables and disk).  Attacker that gets hold of the livesystem-disk and
also compromises 1 of the backup sites can still not access the private key.


## Provisioning procedure

### Equipment:
 - 1x local provisioning machine
 - 1x TKey, dedicated for softkey generation
 - ssh access over Wireguard+PSK tunnel to target machine, live-system
 - 2x USB sticks for backup
 - Tamper-evident bags
 - 2x physically secure locations for USB sticks for backup

The script in [../scripts/provision-softkey](../scripts/provision-softkey)
carries out generation and provisioning. (TODO: the script itself is not yet
entirely complete, or ready for use)

Overall, TKey is used locally to generated passphrases and entropy for the
private key seed.  This secret material is provided to the remote target machine
over ssh.  The `passphrase1` is stored as an EFI variable on the target machine.

Our `genkey-mlsda44` tool is run on the target machine and creates the private
key by mixing entropy from TKey with entropy from the target machine itself.
The private key is encrypted with `passphrase1` (now called
`privkey(passphrase1)`, and written to a location on target machine's disk.

Then `genkey-mldsa44` is invoked again over ssh, running on the target machine
and, having access to `passphrase1`, re-encrypts `privkey(passphrase1)` using
`passphrase2`.  The new `privkey(passphrase2)` and `passphrase2` are written to
an ephemeral (`/dev/shm`) location on the local machine.

See the script itself for further details.

After successfully running the provisioning script, the output
`privkey(passphrase2)` and `passphrase2` shall be stored on 2 separate USB
sticks (one file on each).  The USB sticks are each kept in a tamper-evident
bags, and stored at separate backup locations.

The `passphrase2` may alternatively be kept written down using pen on paper.

The TKey used shall be stored together with the provisioning machine.


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

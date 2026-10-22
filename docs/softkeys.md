# ML-DSA-44 for Post-Quantum secure cosignatures

We will use so-called "softkeys", meaning private key in a file on
disk.

The OpenSSH private key file format will be used. Using its builtin
passphrase encryption (bcrypt-pbkdf). Modelled after Ed25519, the file
stores the private key seed. Our `sigum-agent` can load such files.

We call this a *privkeyfile* from now on; it is always passphrase
encrypted.

## Key generation

The ML-DSA-44 privkeyfile will be created using our `genkey-mldsa44`
tool.

The 32 bytes random seed for the private key will be sourced from:
*TODO* one of the following;

- the `genkey-mldas44` default, Go's crypto/rand, which is implicit by
  the use of func `mldsa.GenerateKey`

- some hardware device, like a TKey:
  ```
  go run github.com/tillitis/tkey-random-generator/cmd/tkey-random-generator@main generate 32 | genkey-mldsa44 --seed=-
  ```

- a combination of the 2 above using HKDF, compare stprov:
  <https://git.glasklar.is/system-transparency/core/stprov/-/blob/main/internal/secrets/secrets.go#L56>

### Passphrase

When generating a privkeyfile, `genkey-mldsa44` by default prompts the
user to enter a new passphrase for encrypting the key at rest.

The passphrase may be written down (pen on paper) and kept in some
physically secure storage.

## Provisioning and operation

The privkeyfile (passphrase encrypted) is stored in the provisioning
system's source code repository (Ansible playbook in Git).

Provisioning places the privkeyfile on the target machine (for example
a witness), in the expected location on disk.

The passphrase for the privkeyfile will be stored in an *EFI variable*
on the target machine. This is persistent across reboots. Access to
`/sys/firmware/efi/efivars` should be limited to root or user that
starts the `sigsum-agent` process.

During startup, a script that reads out the passphrase from the *EFI
variable* is used to pass it to `sigsum-agent` by way of Bash Process
Substitution, something like: `sigsum-agent -k /key/file -p
<(passphrase-reader)`.

*TODO* Do we also keep privkeyfile additionally encrypted using
Ansible Vault, and a per-host-secret (our ansible-pull method etc)?

- Affects ability to recover from for example a broken disk; the
  per-host-secret is a symmetric key only present on the host (target
  machine).
- Affects where key generation can be carried out; if it is to be
  encrypted with a per-host-secret, it must happen on the host (target
  machine). Meaning a seed from hardware device would have to be
  generated elsewhere, and pasted over to host (which is remote)
  before use.

## Considerations

The privkeyfile is always encrypted with a passphrase at rest. It is
only ever decrypted when loaded into signing tool on the target
machine.

Being encrypted at rest, it can be stored in source code repository,
and backed up.

The passphrase for decrypting privkeyfile is stored in *EFI variable*
on the target machine, and possibly on paper in physically secure
storage, as backup.

Keeping the passphrase separate from the privkeyfile on disk protects
against an attacker getting hold of only the physical disk (but not
the whole machine, EFI variable storage and all).

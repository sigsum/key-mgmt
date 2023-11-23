# YubiHSM Agent

This repository provides documentation and scripts to provision YubiHSMs for log
servers and witnesses.  To integrate the provisioned YubiHSMs with the ssh-agent
protocol, a minimal daemon for such purposes is provided (only Ed25519 signing).

The detailed documentation for our key management strategy is available in a
[separate document](./docs/key-management.md).  A demo of provisioning and then
signing with the wrapped ssh-agent is shown at the bottom of this document.

## Install the YubiHSM toolchain

Locate a release for your system's distribution on Yubico's [YubiHSM page][].

[YubiHSM page]: https://developers.yubico.com/YubiHSM2/Releases/

### Debian

Example after downloading and verifying the signature for Debian 12:

    $ tar -xzf yubihsm2-sdk-2023-11-debian12-amd64.tar.gz
    $ cd yubihsm2-sdk-2023-11-debian12
    $ sudo dpkg -i $(ls *.deb | grep -v '\-dev_')

The above installs commands like `yubihsm-shell` and `yubihsm-connector`.  Undo
the install with `dpkg -r PKGNAME`, followed by `userdel yubihsm-connector`.

## Install yubihsm-agent

Install [Go's toolchain][], at least version 1.19.  You may find packaged
versions of Go in your distribution, e.g., `apt install golang-1.19` on Debian.

Install `yubihsm-agent`:

    $ go install sigsum.org/yubihsm/cmd/yubihsm-agent...To Be Added.

[Go's toolchain]: https://go.dev/doc/install

**Note:** you don't need yubihsm-agent in order to provision a new YubiHSM.

## Demo

Ensure that only a single YubiHSM is plugged in at the same time.  Otherwise it
becomes complicated to communicate which YubiHSM a script should operate on.
Each script will prompt for you to insert YubiHSMs with different purposes, such
as creating a replica of a backup or provisioning a log server signing-oracle.

### Factory-reset YubiHSMs

For each YubiHSM that needs to be provisioned:

    $ ./scripts/yhp-reset

The above script will exit with error unless the YubiHSM is in a state that
corresponds to a complete factory-reset.  In other words, there's exactly one
object stored on the YubiHSM.  That one object is a default authentication key.

### Generate keys and create initial backup

    $ ./scripts/yhp-keygen | tee backup-1.txt

### Provision backup replica from backup

    $ ./scripts/yhp-backup | tee backup-2.txt

Note that the same authkey and wrapkey passphrases are used.  They are
redundantly written to the file so that clean-up gets easier in the future.  For
example, if the YubiHSM corresponding to `backup-1.txt` break: provision a new
YubiHSM similar to the above, store `backup-3.txt` and delete `backup-1.txt`.

### Provision log server signing-oracle from backup

    $ ./scripts/yhp-logsrv | tee logsrv-1.txt

Repeat this for the number of log server nodes you have in production, e.g., 2.

### Provision witness signing-oracle from backup

    $ ./scripts/yhp-witness | tee witness.txt

### Restore from backup in the future

This is in no way different from the initial provisioning.  Simply use
`yhp-backup`, `yhp-logsrv`, or `yhp-witness` depending on what to restore.

### Automate all provisioning scripts

You might want to put together your own script that automates everything expect
for plugging YubiHSMs in and out of the provisioning machine.  Example below.

    #!/bin/bash
    
    set -eu

    ./scripts/yhp-keygen  | tee backup-1.txt
    export AUTHKEY_PASSPHRASE=$(grep backup_authkey_passphrase backup-1.txt | cut -d'=' -f2)
    export WRAPKEY_PASSPHRASE=$(grep backup_wrapkey_passphrase backup-1.txt | cut -d'=' -f2)
    ./scripts/yhp-backup  | tee backup-2.txt
    ./scripts/yhp-logsrv  | tee logsrv-1.txt
    ./scripts/yhp-logsrv  | tee logsrv-2.txt
    ./scripts/yhp-witness | tee witness.txt

### Backup output files on USB sticks

  - `backup*`: put them on separate USB sticks that are only inserted into the
    provisioning machine.  Access to any of these USB sticks and a corresponding
    backup YubiHSM device will (by design) allow for full key recovery.
  - `logsrv*` and `witness.txt`: put them on another USB stick that operational
    folks get access to and sometimes plug into their computers (so they can
    transfer secrets to nodes that are active).  Access to any of these USB
    sticks and a corresponding YubiHSM allows for signing-oracle access.

If it makes sense for your operational setup, you may consider storing `logsrv*`
and `witness.txt` separately from each other.  E.g., if log servers and
witnesses are not operated by the same day-to-day operations team.

**Note:** you might want to `tee` directly to the respective USB sticks.

### Try signing using yubihsm-agent

The `yubihsm-agent` program is a tiny ssh-agent daemon that computes Ed25519
signatures by interacting with the `yubihsm-connector` protocol on localhost.

Test that valid signatures are created for all log server and witness YubiHSMs:

    $ To Be Added.

**Note:** does not need to happen on the provisioning machine.

## Contact

  - IRC room `#sigsum` @ OFTC.net
  - Matrix room `#sigsum` which is bridged with IRC
  - The [sigsum-general][] mailing list

[sigsum-general]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-general.lists.sigsum.org/

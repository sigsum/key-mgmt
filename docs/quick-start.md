# Quick start

The detailed documentation for our YubiHSM key management strategy is documented
[separately](./key-management.md).  Below are install instructions and a
complementary demo on how to do the provisioning and sign with `yubihsm-agent`.

## Install the YubiHSM tools

### Installing from source

To install `yubihsm-connector` (just go install does not work):

    $ git clone https://github.com/Yubico/yubihsm-connector.git
    $ cd yubihsm-connector
    $ make
    $ install bin/yubihsm-connector ~/.local/bin/  # Or desired install location

And for `yubihsm-shell`:

    $ git clone https://github.com/Yubico/yubihsm-shell.git
    $ cd yubihsm-shell
    $ mkdir build
    $ cd build
    $ cmake --install-prefix="${HOME}/.local" ..
    $ make
    $ make install

Note that if `yubihsm-shell` and its associated libraries are installed
in a non-default location, you need to set `PATH` to include the
directory where executables are installed (this is required for
running our provisioning scripts). You will also need to set
`LD_LIBRARY_PATH` to point to the library installation directory,
e.g., `export LD_LIBRARY_PATH="${HOME}/.local/lib"`. Without
`LD_LIBRARY_PATH`, `yubihsm-shell` fails, with error messages that
confusingly don't look like linking problems.

### Installing Yubico's binary packages

Locate a release for your system's distribution on Yubico's [YubiHSM page][].

[YubiHSM page]: https://developers.yubico.com/YubiHSM2/Releases/

Example after downloading and verifying the signature for a Debian 12 release:

    $ tar -xzf yubihsm2-sdk-2023-11-debian12-amd64.tar.gz
    $ cd yubihsm2-sdk-2023-11-debian12
    $ sudo dpkg -i $(ls *.deb | grep -v '\-dev_')

The above installs commands like `yubihsm-shell` and `yubihsm-connector`.  Undo
the install with `dpkg -r PKGNAME`, followed by `userdel yubihsm-connector`.

### Add udev configuration

Add a udev rule to grant your user access to communicate with YubiHSMs.  For
example, copy-paste the following into `/etc/udev/rules.d/50-yubihsm2.rules`:

    # Based on:
    # https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
    
    # This udev file should be used with udev 188 and newer
    ACTION!="add|change", GOTO="yubihsm2_connector_end"
    
    # Yubico YubiHSM 2
    # The GROUP attribute here has to match the user that runs the Connector
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0030", GROUP="YOURUSER"
    
    LABEL="yubihsm2_connector_end"

Reload the added configuration:

    # udevadm control --reload-rules
    # udevadm trigger

### Verify setup

Insert your YubiHSM and run `yubihsm-connector -d`, then check that it is
possible to connect with `yubihsm-shell` in a separate terminal:

    $ yubihsm-shell
    Using default connector URL: http://localhost:12345
    yubihsm> connect
    Session keepalive set up to run every 15 seconds
    yubihsm> ^D

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

    key-mgmt $ ./scripts/yhp-reset
    *** INSERT YubiHSM to factory-reset
    ENTER to continue
    *** FOUND YubiHSM, serial number XXXXXXXXX
    ENTER to continue
    *** INSERT again while TOUCHING the YubiHSM for 10s
    ENTER to continue
    *** OK

The above script will exit with error unless the YubiHSM is in a state that
corresponds to a complete factory-reset.  In other words, there's exactly one
object stored on the YubiHSM.  That one object is a default authentication key.

### Generate keys and create initial backup

    key-mgmt $ ./scripts/yhp-keygen | tee backup-1.txt
    *** INSERT YubiHSM keygen and initial backup provisioning
    ENTER to continue
    *** FOUND YubiHSM, serial number XXXXXXXXXX
    ENTER to continue
    Found 4 object(s)
    id: 0x0064, type: authentication-key, algo: aes128-yubico-authentication, sequence: 0, label: Backup authentication
    id: 0x0190, type: wrap-key, algo: aes128-ccm-wrap, sequence: 0, label: Common wrap key
    id: 0x01f4, type: asymmetric-key, algo: ed25519, sequence: 0, label: Log server signing key
    id: 0x0258, type: asymmetric-key, algo: ed25519, sequence: 0, label: Witness signing key
    
    backup_authkey_passphrase=fdaf209618830d9ed9f5fb0f7af83068
    backup_wrapkey_passphrase=b7924ea7eaf959d5b23d3ec5c68208a0
    backup_serial_number=XXXXXXXXXX

### Provision backup replica from backup

    key-mgmt $ ./scripts/yhp-backup | tee backup-2.txt
    *** INSERT YubiHSM to create a backup replica from
    ENTER to continue
    *** FOUND YubiHSM, serial number XXXXXXXXXX
    ENTER to continue
    ENTER authkey passphrase: fdaf209618830d9ed9f5fb0f7af83068
    ENTER wrapkey passphrase: b7924ea7eaf959d5b23d3ec5c68208a0
    
    *** INSERT YubiHSM to provision new backup replica onto (must be in factory-reset state)
    ENTER to continue
    *** FOUND YubiHSM, serial number YYYYYYYYYY
    ENTER to continue
    Found 4 object(s)
    id: 0x0064, type: authentication-key, algo: aes128-yubico-authentication, sequence: 0, label: Backup authentication
    id: 0x0190, type: wrap-key, algo: aes128-ccm-wrap, sequence: 0, label: Common wrap key
    id: 0x01f4, type: asymmetric-key, algo: ed25519, sequence: 0, label: Log server signing key
    id: 0x0258, type: asymmetric-key, algo: ed25519, sequence: 0, label: Witness signing key
    
    backup_authkey_passphrase=fdaf209618830d9ed9f5fb0f7af83068
    backup_wrapkey_passphrase=b7924ea7eaf959d5b23d3ec5c68208a0
    backup_serial_number=YYYYYYYYYY

Note that the same authkey and wrapkey passphrases are used.  They are
redundantly written to the file so that clean-up gets easier in the future.  For
example, if the YubiHSM corresponding to `backup-1.txt` break: provision a new
YubiHSM similar to the above, store `backup-3.txt` and delete `backup-1.txt`.

### Provision log server signing-oracle from backup

    key-mgmt $ ./scripts/yhp-logsrv | tee logsrv-1.txt
    *** INSERT YubiHSM to restore log server signing key from
    ENTER to continue
    *** FOUND YubiHSM, serial number XXXXXXXXXX
    ENTER to continue
    ENTER authkey passphrase: fdaf209618830d9ed9f5fb0f7af83068
    ENTER wrapkey passphrase: b7924ea7eaf959d5b23d3ec5c68208a0
    
    *** INSERT YubiHSM to provision new logsrv signing oracle on (must be in factory-reset state)
    ENTER to continue
    *** FOUND YubiHSM, serial number ZZZZZZZZZZ
    ENTER to continue
    Found 2 object(s)
    id: 0x00c8, type: authentication-key, algo: aes128-yubico-authentication, sequence: 0, label: Logsrv authentication
    id: 0x01f4, type: asymmetric-key, algo: ed25519, sequence: 0, label: Log server signing key
    
    logsrv_authkey_passphrase(ZZZZZZZZZZ)=35bb8bdb943620df860e5cf4c9dcf0cd

Repeat this for the number of log server nodes you have in production, e.g., 2.

### Provision witness signing-oracle from backup

    key-mgmt $ ./scripts/yhp-witness | tee witness.txt
    *** INSERT YubiHSM to restore witness signing key from
    ENTER to continue
    *** FOUND YubiHSM, serial number XXXXXXXXXX
    ENTER to continue
    ENTER authkey passphrase: fdaf209618830d9ed9f5fb0f7af83068
    ENTER wrapkey passphrase: b7924ea7eaf959d5b23d3ec5c68208a0
    
    *** INSERT YubiHSM to provision new witness signing oracle on (must be in factory-reset state)
    ENTER to continue
    *** FOUND YubiHSM, serial number TTTTTTTTTT
    ENTER to continue
    Found 2 object(s)
    id: 0x012c, type: authentication-key, algo: aes128-yubico-authentication, sequence: 0, label: Witness authentication
    id: 0x0258, type: asymmetric-key, algo: ed25519, sequence: 0, label: Witness signing key
    
    witness_authkey_passphrase(TTTTTTTTTT)=ea99fcdf59ae9328754a979e87c181fe

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

Replace `| tee` with `>` to avoid emitting sensitive information on stdout.

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

### Try signing using yubihsm-agent

The `yubihsm-agent` program is a tiny ssh-agent daemon that computes Ed25519
signatures by interacting with the `yubihsm-connector` protocol on localhost.

Test that valid signatures are created for all log server and witness YubiHSMs:

    $ To Be Added.

**Note:** does not need to happen on the provisioning machine.

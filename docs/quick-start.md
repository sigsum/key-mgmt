# Quick start

The detailed documentation for our YubiHSM key management strategy is documented
[separately](./key-management.md).  Below are install instructions and a
complementary demo on how to do the provisioning and sign with `sigsum-agent`.

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

## Install additional system packages

`openssl` and `base64` are used by `scripts/`.  On Debian 12, try:

    # apt install openssl basez

The above tooling is used to sanity check whether the generated and imported
keys work by signing a fixed message which is then verified using `openssl`.

**Note:** this is not needed on systems that only use `sigsum-agent`.

## Install sigsum-agent

Install [Go's toolchain][].  You need at least version 1.19.  You may find
packaged versions of Go in your distribution.  For example, on Debian 12:

    apt install golang-go

Now the latest version of `sigsum-agent` can be installed as follows:

    $ go install sigsum.org/key-mgmt/cmd/sigsum-agent@latest

[Go's toolchain]: https://go.dev/doc/install

**Note:** you don't need `sigsum-agent` in order to provision a new YubiHSM.

## Demo

Ensure that only a single YubiHSM is plugged in at the same time.  Otherwise it
becomes complicated to communicate which YubiHSM a script should operate on.
Each script will prompt for you to insert YubiHSMs with different purposes, such
as creating a replica of a backup or provisioning a log server signing-oracle.

### Factory-reset YubiHSMs

For each YubiHSM that needs to be provisioned:

    key-mgmt$ ./scripts/yhp-reset

The above script will exit with error unless the YubiHSM is in a state that
corresponds to a complete factory-reset.  In other words, there's exactly one
object stored on the YubiHSM.  That one object is a default authentication key.

### Generate keys and create initial backup

    key-mgmt$ ./scripts/yhp-keygen | tee backup-1.txt

Expect to see, e.g., the authkey and wrapkey passphrases, as well as the
generated public keys (one for the log server and another one for the witness).

### Provision backup replica from backup

    key-mgmt$ ./scripts/yhp-backup | tee backup-2.txt

Note that the same authkey and wrapkey passphrases are used.  They are
redundantly written to stdout so that clean-up gets easier in the future.  For
example, if the YubiHSM corresponding to `backup-1.txt` break: provision a new
YubiHSM similar to the above, store `backup-3.txt` and delete `backup-1.txt`.

### Provision log server signing-oracle from backup

    key-mgmt$ ./scripts/yhp-logsrv | tee logsrv-1.txt

Repeat this for the number of log server nodes you have in production, e.g., 2.

### Provision witness signing-oracle from backup

    key-mgmt $ ./scripts/yhp-witness | tee witness.txt

### Restore from backup in the future

This is in no way different from the initial provisioning.  Simply use
`yhp-backup`, `yhp-logsrv`, or `yhp-witness` depending on what to restore.

### Automate all provisioning scripts

You might want to put together your own script that automates everything expect
for plugging YubiHSMs in and out of the provisioning machine.  Example below.

    #!/bin/bash
    
    set -eu
    set -o pipefail

    ./scripts/yhp-keygen  | tee backup-1.txt
    export AUTHKEY_PASSPHRASE=$(grep backup_authkey_passphrase backup-1.txt | cut -d'=' -f2)
    export WRAPKEY_PASSPHRASE=$(grep backup_wrapkey_passphrase backup-1.txt | cut -d'=' -f2)
    ./scripts/yhp-backup  | tee backup-2.txt
    ./scripts/yhp-logsrv  | tee logsrv-1.txt
    ./scripts/yhp-logsrv  | tee logsrv-2.txt
    ./scripts/yhp-witness | tee witness.txt

    echo ""
    echo "OK"
    echo ""
    echo "Suggestion: diff -u backup-* # just different serial number"
    echo "Suggestion: diff -u logsrv-* # just different serial number + passphrase"
    echo "Suggestion: eyeball that backup-* and logsrv-* have the same log key"
    echo "Suggestion: eyeball that backup-* and witness.txt have the same witness key"

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

### Try signing using sigsum-agent

The `sigsum-agent` program is a tiny ssh-agent daemon that computes Ed25519
signatures by interacting with the `yubihsm-connector` protocol on localhost. To
use a key, you need an "auth-file" containing the auth-id (decimal number) and
the corresponding passphrase, separated by a `:` character, and the key-id.
E.g., with the default configuration of these provisioning scripts, a log server
key uses auth-id 200 and key-id 500, while a witness key uses auth-id 300 and
key-id 600. An auth-file for the log server can be created using

    $ (umask 077 && echo 200:SECRET-PASSPHRASE > log-auth)

To sign a test message using a log server key, you can then run

    $ yubihsm-connector &
    $ sigsum-agent -a log-auth -i 500 ssh-add -L > key.pub
    $ echo "test message" > msg
    $ sigsum-agent -a log-auth -i 500 ssh-keygen -q -Y sign -n test-namespace -f key.pub msg

The signature can be verified using

    $ ssh-keygen -q -Y check-novalidate -n test-namespace -f key.pub -s msg.sig < msg

See `sigsum-agent --help` for details on the agent's options.

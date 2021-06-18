#!/bin/bash
#gpg operates under a GPLv3 license; TODO ask AT if that's ok
set -e
PASS=$1
FILENAME=$2
echo $PASS  | gpg --symmetric --batch --yes --passphrase-fd 0 $FILENAME
echo "[PEBIL_ENCRYPT] Encrypted $FILENAME to $FILENAME.gpg"
echo "[PEBIL_ENCRYPT] Decrypt $FILENAME.gpg with the command 'gpg --decrypt $FILENAME.gpg'"
echo "[PEBIL_ENCRYPT] Remember: the passphrase is the sanitize_password option you specified on the commandline. If you forget this password, the file is unusable."
echo "[PEBIL_ENCRYPT] To create a plain text version of this file, replace '--sanitize-password blah' with '--sanitize'"
rm $FILENAME

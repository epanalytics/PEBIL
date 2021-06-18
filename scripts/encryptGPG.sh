#!/bin/bash
#gpg operates under a GPLv3 license; TODO ask AT if that's ok
set -e
PASS=$1
FILENAME=$2.translation
echo $PASS  | gpg --symmetric --batch --yes --passphrase-fd 0 $FILENAME
echo "Encrypted $FILENAME to $FILENAME.gpg"
echo "Decrypt $FILENAME.gpg with the command 'gpg --decrypt $FILENAME.gpg'"
echo "Remember: the passphrase is the sanitize_password option you specified on the commandline. If you forget this password, the file is unusable."
echo "To create a plain text version of this file, replace '--sanitize-password blah' with '--sanitize'"
rm $FILENAME

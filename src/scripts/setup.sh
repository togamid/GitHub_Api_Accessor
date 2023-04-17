#!/bin/bash
# Pfad richtig regeln
cp git_credential_helper.sh ~/git-credential-helper.sh
git config --global credential.helper "/bin/bash ~/git-credential-helper.sh"
exit 0
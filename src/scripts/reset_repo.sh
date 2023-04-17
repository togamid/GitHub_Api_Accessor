#!/bin/bash
#resets the repository to the indicated commit
cd tmp
rm -f dependency-check-report.*
cd ${1}
git reset --hard ${2}
git clean -f
git push --force origin HEAD
mvn clean
mvn dependency:copy-dependencies
exit 0
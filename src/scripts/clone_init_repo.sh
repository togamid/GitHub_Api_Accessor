#!/bin/bash
# nimmt als argument den username und den Projektnamen
rm -r -f tmp
mkdir tmp
cd tmp
git clone https://github.com/${1}/${2}.git
cd ${2}
mvn clean
mvn dependency:copy-dependencies
exit 0
#!/bin/bash
/root/owasp-dependency-check/bin/dependency-check.sh --scan "/root/app/tmp" --format XML --out "/root/app/tmp"
exit 0
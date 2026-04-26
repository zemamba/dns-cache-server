#!/bin/zsh
set -euo pipefail
cd -- "$(dirname "$0")"
go build -o dns-cache .
sudo ./dns-cache

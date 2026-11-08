#!/usr/bin/env bash
# Regenerate crates/ransom/assets/lockstar-wallpaper.png, the ransom wallpaper
# cleanroom-ransom drops on the share (see scenario/README.md).
#
#   scripts/lockstar-wallpaper.sh
#
# ImageMagick and the DejaVu fonts come from the nixpkgs this flake pins, and the PNG is written
# without timestamps, so the same commit gives the same bytes. The image carries two attacker
# addresses that appear nowhere else in the scenario: an investigator only learns them by
# looking at the picture.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
out="$repo/crates/ransom/assets/lockstar-wallpaper.png"

if ! command -v magick >/dev/null || [ -z "${DEJAVU:-}" ]; then
  fonts=$(nix eval --inputs-from "$repo" --raw nixpkgs#dejavu_fonts.outPath)
  nix build --inputs-from "$repo" --no-link nixpkgs#dejavu_fonts
  exec env DEJAVU="$fonts/share/fonts/truetype" \
    nix shell --inputs-from "$repo" nixpkgs#imagemagick --command "$0" "$@"
fi

mkdir -p "$(dirname "$out")"
magick -size 1024x576 xc:'#3b0000' \
  -fill '#ff3030' -font "$DEJAVU/DejaVuSans-Bold.ttf" -pointsize 46 \
  -annotate +48+82 'YOUR FILES ARE ENCRYPTED' \
  -fill white -pointsize 24 \
  -annotate +48+132 'Acme Logistics: your network belongs to LOCKSTAR 3.1.' \
  -font "$DEJAVU/DejaVuSansMono-Bold.ttf" -pointsize 24 \
  -annotate +48+210 'Victim ID:        ACME-7Q2-0451' \
  -annotate +48+254 'Negotiation chat: chat.lockstar.example/ACME-7Q2-0451' \
  -annotate +48+298 'Leak site:        leaks.lockstar.example/acme-logistics' \
  -annotate +48+342 'Email:            lockstar-support@ransom.example' \
  -fill '#ffd0d0' -font "$DEJAVU/DejaVuSans.ttf" -pointsize 22 \
  -annotate +48+420 'Log in to the chat with your victim ID within 72 hours.' \
  -annotate +48+456 'After 72 hours we publish your payroll and patient data on the leak site.' \
  -fill '#ff8080' -pointsize 18 \
  -annotate +48+530 'Do not rename, move or modify the .locked files.' \
  -colors 16 -strip -define png:exclude-chunks=date,time \
  "PNG8:$out"
ls -l "$out"
sha256sum "$out"

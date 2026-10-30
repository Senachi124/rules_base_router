#!/bin/bash
# Package the pinned, checksummed v2 networking engine, without Go or Homebrew.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP=$1
VERSION=1.14.4
case "$(uname -m)" in
  arm64) ARCH=arm64; SHA=0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838 ;;
  x86_64) ARCH=amd64; SHA=eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25 ;;
  *) echo 'Unsupported Mac architecture' >&2; exit 1 ;;
esac
ARCHIVE="sing-box-$VERSION-darwin-$ARCH.tar.gz"
CACHE="$ROOT/.tools/downloads"
mkdir -p "$CACHE" "$APP/Contents/MacOS" "$APP/Contents/Resources/Licenses"
STAGE=$(mktemp -d "$CACHE/package.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
matches() { [ -f "$1" ] && [ "$(shasum -a 256 "$1" | awk '{print $1}')" = "$SHA" ]; }
if ! matches "$CACHE/$ARCHIVE"; then
  /usr/bin/curl --fail --location --show-error --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 600 --retry 2 \
    "https://github.com/SagerNet/sing-box/releases/download/v$VERSION/$ARCHIVE" -o "$STAGE/$ARCHIVE"
  matches "$STAGE/$ARCHIVE" || { echo 'Engine archive checksum failed' >&2; exit 1; }
  mv "$STAGE/$ARCHIVE" "$CACHE/$ARCHIVE"
fi
tar -xzf "$CACHE/$ARCHIVE" -C "$STAGE"
cp "$STAGE/sing-box-$VERSION-darwin-$ARCH/sing-box" "$APP/Contents/MacOS/sing-box"
cp "$STAGE/sing-box-$VERSION-darwin-$ARCH/LICENSE" "$APP/Contents/Resources/Licenses/sing-box-LICENSE"
cp "$ROOT/target/release/routebar-v2" "$APP/Contents/MacOS/routebar-v2"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$APP/Contents/Resources/Licenses/THIRD_PARTY_NOTICES.md"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/Licenses/RouteBar-LICENSE"
chmod 755 "$APP/Contents/MacOS/sing-box" "$APP/Contents/MacOS/routebar-v2"
"$APP/Contents/MacOS/sing-box" version

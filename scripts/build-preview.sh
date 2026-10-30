#!/bin/bash
# Build the certificate-free app with the command line Swift SDK.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/toolchain.sh
"$ROUTEBAR_CARGO" build --release --locked --lib -p routebar-core
"$ROUTEBAR_CARGO" build --release --locked -p routebar-v2
mkdir -p build
APP="$(pwd)/build/RouteBar.app.stage.$$"
trap 'rm -rf "$APP"' EXIT
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
COMMON=(-swift-version 5 -O -target "$(uname -m)-apple-macos13.0" -import-objc-header include/RouteBarCore.h -L target/release -lroutebar_core -framework Foundation -framework Security -framework SystemConfiguration -lresolv)
swiftc "${COMMON[@]}" -parse-as-library -module-name RouteBar \
  macos/App/*.swift macos/Shared/Models.swift macos/Shared/CoreBridge.swift \
  macos/Shared/KeychainStore.swift macos/Shared/SigningIdentity.swift macos/Shared/DNSWire.swift \
  macos/Shared/V2*.swift macos/Shared/WhitelistModels.swift macos/Shared/SessionAuthorization.swift \
  -framework SwiftUI -framework AppKit -o "$APP/Contents/MacOS/RouteBar"
./scripts/package-backend.sh "$APP"
python3 scripts/package-preview.py "$APP"
codesign --force --sign - "$APP/Contents/MacOS/routebar-v2"
codesign --force --sign - "$APP/Contents/MacOS/sing-box"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
if [ -e build/RouteBar.app ]; then
  rm -rf build/RouteBar.previous.app
  mv build/RouteBar.app build/RouteBar.previous.app
fi
mv "$APP" build/RouteBar.app
echo "Built $(pwd)/build/RouteBar.app (local ad-hoc signing; no Apple Developer certificate required)."

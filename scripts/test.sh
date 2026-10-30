#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/toolchain.sh
"$ROUTEBAR_CARGO" test --workspace --locked
"$ROUTEBAR_CARGO" clippy --workspace --all-targets --locked -- -D warnings
"$ROUTEBAR_CARGO" fmt --all -- --check
"$ROUTEBAR_CARGO" build --release --lib --locked
mkdir -p build
swiftc -swift-version 5 -import-objc-header include/RouteBarCore.h \
  macos/Shared/Models.swift macos/Shared/CoreBridge.swift macos/Shared/DNSWire.swift \
  macos/Tests/SmokeTests.swift -L target/release -lroutebar_core \
  -framework Foundation -framework Security -framework SystemConfiguration -lresolv \
  -o build/swift-tests
build/swift-tests
swiftc -swift-version 5 -import-objc-header include/RouteBarCore.h \
  macos/Shared/*.swift macos/PacketExtension/PacketTunnelProvider.swift \
  macos/Tests/PacketSettingsTests.swift -L target/release -lroutebar_core \
  -framework Foundation -framework Network -framework NetworkExtension \
  -framework Security -framework SystemConfiguration -lresolv \
  -o build/packet-settings-tests
build/packet-settings-tests
swiftc -swift-version 5 macos/Shared/Models.swift macos/Shared/V2Backend.swift \
  macos/Tests/V2BackendTests.swift -framework Foundation -o build/v2-backend-tests
build/v2-backend-tests

swiftc -swift-version 5 macos/Shared/Models.swift macos/Shared/V2Backend.swift \
  macos/Shared/WhitelistModels.swift macos/Tests/WhitelistTests.swift \
  -framework Foundation -o build/whitelist-tests
build/whitelist-tests

swiftc -swift-version 5 macos/Shared/Models.swift macos/Shared/V2Backend.swift \
  macos/Shared/SessionAuthorization.swift macos/Tests/SessionAuthorizationTests.swift \
  -framework Foundation -framework Security -o build/session-authorization-tests
build/session-authorization-tests

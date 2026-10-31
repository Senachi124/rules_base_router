# Rules Base Router

## 本 fork 新增 Windows 版

**Windows 0.2.2 預設分流：** `ChatGPT.exe`、`codex.exe`、
`codex-code-mode-host.exe` 經 `vm1`，其他流量 direct，DNS 經 `vm1`。
首次啟動會準備好規則，只需匯入私人 WireGuard profile；已有設定不會被覆蓋。
repo 不包含私人 profile 或金鑰。
[繁體中文使用及儲存說明](docs/WINDOWS.zh-Hant.md) · [版本紀錄](windows/CHANGELOG.md)

支援 Windows 10/11 x64，提供原生桌面介面、WireGuard 匯入、應用程式／網域／IP
規則、DNS 設定、驗證、連線及斷線。保留原有 macOS 程式。

```powershell
git clone https://github.com/Senachi124/rules_base_router.git
cd rules_base_router
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-windows.ps1
.\build\RouteBar-windows-x64\RouteBar.exe
```

編譯需要 Rust/rustup、Visual Studio C++ Build Tools 及 Windows SDK。
完成後亦會產生 `build/RouteBar-windows-x64.zip`，解壓後保留所有檔案即可使用。
按 Connect 時需要管理員授權；授權後會交接至管理員視窗並連線。
最小化會留在通知區，關閉程式會停止 VPN，沒有開機服務。

目前是 Windows 預覽版；離線測試及實機出口／DNS 檢查已通過，完整的路由清理、
重連及跨權限驗收仍需在目標電腦進行。完整範圍見 [Windows 文件](docs/WINDOWS.zh-Hant.md)。

## 原有 macOS 版

macOS 原生 App，讓指定應用程式與網站經 WireGuard VPN 連線，其餘流量保持直連。

App 名稱為 **RouteBar**，使用 SwiftUI 介面、Rust 分流控制器及 sing-box 網絡引擎。本機編譯及使用不需要 Apple Developer certificate 或 Network Extension entitlement；修改系統路由仍需 macOS 管理員授權。

[English](README.md) · [架構](docs/ARCHITECTURE.md) · [配置與 CLI](docs/CONFIGURATION.md) · [開發指南](docs/DEVELOPMENT.md)

## 功能

- 單一白名單介面，管理 App、程序名稱、精確域名、域名後綴及 IP 網段。
- 多個 WireGuard 出口，規則由上至下匹配，第一條命中生效。
- 支援「指定 App 連接指定網站」等複合條件。
- DNS 伺服器、出口及 IPv4／IPv6 策略獨立設定。
- 開 App 時授權一次，之後連線、套用變更、斷線及讀取日誌共用本次授權。
- 套用前驗證配置；新服務啟動失敗時嘗試回復舊設定。
- 選單列操作、服務狀態及活動日誌。

## 編譯與啟動

需要 macOS 13 或更新版本、Apple Command Line Tools 或 Xcode、Python 3，以及 [rustup](https://rustup.rs/)。Rust 版本由 [rust-toolchain.toml](rust-toolchain.toml) 固定。目前已在 Apple Silicon 驗證；Intel 及較舊 macOS 仍需另行驗收。

```sh
git clone https://github.com/chanyan999/rules_base_router.git
cd rules_base_router
./scripts/build.sh
open build/RouteBar.app
```

建置會透過 HTTPS 下載固定版本 sing-box，核對 SHA-256，再連同 Rust 控制器放入 App，並完成本機 ad-hoc 簽署。不需要 Go 或 XcodeGen。編譯產物及下載快取不會加入 Git；此建置未經 Developer ID 公證。

## 使用方式

1. 開啟 RouteBar，完成 macOS 管理員授權；授權本身不會啟動 VPN。
2. 在「VPN 出口」匯入 WireGuard `.conf`，新匯入的設定檔會儲存於登入 Keychain。
3. 在「白名單」加入 App 或網站，選擇出口並排列規則優先次序。
4. 停止其他 VPN，再按「連線」。
5. 運行期間可編輯白名單，按「套用變更」才會更新服務；重啟會中斷現有連線。
6. 按「中斷連線」停止服務，並刪除生成的私鑰配置。

取消授權仍可編輯白名單，亦可按「授權本次開啟」重試。關閉視窗會保留選單列 App；完全退出 App 會結束本次授權，但已運行的背景 VPN 會繼續，並在開機時載入，直至中斷。每次開啟都會建立新的授權 session；macOS 可能沿用近期系統認證，RouteBar 不會儲存密碼。

## 分流規則

規則採用第一條命中優先。App／程序名稱之間為 OR，域名／後綴／IP 網段之間亦為 OR；同一條規則同時包含兩組條件時，兩組都必須符合。未匹配流量預設直連。

DNS 是獨立的全局策略，不會單憑某個 App 使用 VPN 就自動改為 VPN DNS。共享網絡程序、加密 DNS、ECH 及連線快取會限制辨識能力。目前沒有全系統 kill switch；VPN 停止、重啟或失效期間，流量可能使用一般系統路由。

詳見 [配置文件](docs/CONFIGURATION.md) 及 [安全範圍](SECURITY.md)。

## 測試

先完成建置，再執行：

```sh
./scripts/test.sh
python3 scripts/test-whitelist-integration.py
```

測試使用合成設定檔與本機 fixtures，不需管理員權限，亦不會啟動系統 VPN。可選的 Go 參考版本差分測試見 [開發指南](docs/DEVELOPMENT.md)；自動測試與實機驗收範圍見 [驗證記錄](docs/VALIDATION.md)。

## 原始碼與文件

- `controller/`：目前使用的 Rust 配置、sing-box 轉換、服務及授權 helper。
- `macos/App/`、`macos/Shared/`：SwiftUI、白名單模型、Keychain 及本機通訊。
- `core/`：原有 Rust WireGuard library、驗證 ABI 及診斷工具。
- `macos/Tests/`、`scripts/`：測試、編譯及打包。
- `docs/`：架構、配置、開發及驗證文件。

原有 Network Extension 原始碼保留作參考及回歸測試，目前 App 不會嵌入這些 extension。參閱 [舊架構說明](docs/LEGACY_NETWORK_EXTENSION.md)。

## 貢獻與授權

提交前請閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)。不要提交真實 VPN 設定檔、私鑰、個人配置或日誌；可由 [config.example.yaml](config.example.yaml) 建立本機設定。

本專案原始碼採用 [MIT](LICENSE)。各依賴保留本身授權；sing-box 為 GPL-3.0-or-later 獨立 executable。重新分發 binary 前請閱讀 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

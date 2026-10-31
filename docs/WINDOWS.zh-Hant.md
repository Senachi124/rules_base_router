# RouteBar for Windows 0.2.1

Windows 10/11 x64 預覽版。這個版本預設將 Codex 經 `vm1`，其他程式 direct；
DNS 統一經 `vm1`。沒有開機自動連線，也沒有 kill switch。

## 預設分流

| 項目 | 出口 |
| --- | --- |
| `ChatGPT.exe` | `vm1` |
| `codex.exe` | `vm1` |
| `codex-code-mode-host.exe` | `vm1` |
| 其他程式／未命中規則的流量 | `direct` |
| 系統 DNS | `1.1.1.1`，經 `vm1`，`prefer_ipv4` |

規則按 process name 配對；Codex 啟動的 `python.exe`、`git.exe` 等子程序不會自動
繼承 Codex 規則。瀏覽器代理擴充功能仍按其自身代理設定運作。

首次啟動且沒有已保存設定時，介面會預先顯示上述規則。已有設定不會被覆蓋。
`vm1` 是出口名稱；repo 和 ZIP 不包含伺服器位址、私人 WireGuard profile 或金鑰。

## 下載及啟動

從此 fork 的 GitHub Actions → Windows → 成功的執行 → `RouteBar-windows-x64`
下載 artifact，解壓裡面的 ZIP。保留整個資料夾：

```text
RouteBar.exe
routebar-v2.exe
sing-box.exe
libcronet.dll
config.example.yaml
BUILD-INFO.json
README.md / README.zh-Hant.md / CHANGELOG.md
Licenses/
```

可以將整個資料夾放在桌面，或建立 `RouteBar.exe` 的桌面捷徑。不能只複製一個
EXE。更新時先退出舊版（會斷線），再開啟新版；標題應顯示 `0.2.1`。
`BUILD-INFO.json` 記錄版本、來源 commit 和打包時間。

使用環境需要 .NET Framework 4.8/4.8.1，以及 Visual C++ v14 **x64** Runtime
（controller 依賴 `VCRUNTIME140.dll`）。Windows 11 內置 .NET Framework；缺少
VC++ Runtime 時使用 [Microsoft 官方安裝包](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)。
不用安裝 Rust、Go、Python、WSL、.NET SDK 或 NordVPN。連線時需要 UAC 管理員授權。

## 設定及使用

1. 首次啟動選 **VPN exits → Import WireGuard .conf**，匯入你的 profile。
   如果預設 vm1 profile 尚未提供，首次匯入會填入 `vm1`，並複製到 app 自己的
   設定目錄；無須將檔案改名成 vm1.conf。
2. **Validate visible settings** 驗證目前畫面上的規則及 profile。
3. **Save settings** 或 **Save DNS and default** 保存設定，不會切換現有連線。
4. 準備好後按 **Connect**，接受 UAC；已有連線時按 **Apply changes** 套用修改。
   新版 Connect／Apply 亦會先保存設定，成功後才更新「已套用」狀態。
5. **Disconnect** 停止 tunnel；關閉 app 亦會停止。最小化則留在系統匣運行。

頂部 **Import config** 用於 RouteBar JSON/YAML，並非 WireGuard `.conf`。
若用包內 `config.example.yaml`，先將私人 `vm1.conf` 放在該 YAML 旁邊，再匯入。
這種方式會引用該 `.conf` 的位置，並不自動複製；之後要保留該 profile。

## 設定存放位置

```text
%LOCALAPPDATA%\RouteBarWindows\config.json       已保存設定
%LOCALAPPDATA%\RouteBarWindows\*.conf            管理的私人 profiles
%LOCALAPPDATA%\RouteBarWindows\session-*         當前連線的臨時副本
%TEMP%\routebar-*                               引擎／驗證暫存
```

資料不會隨 EXE 所在位置改變；同一帳戶搬動程式資料夾仍會讀取原設定。
JSON/YAML 只儲存規則和 profile 路徑，沒有內嵌私人金鑰。匯出 JSON 不等於完整備份：
搬到另一部電腦仍須轉移 profiles 並調整路徑。臨時 session 不能代替永久 profile。

## 測試與限制

建置及離線測試：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-windows.ps1
```

涵蓋 Rust、引擎 schema、UI／連線生命週期、Codex 預設規則、現有設定保留等測試，
不會啟動系統 VPN。實機已觀察到全機 tunnel 的 IPv4/IPv6 vm1 出口及正常 DNS，
亦已觀察到分流模式下非 Codex 程式 direct 出口。Codex process 規則已驗證配對；
未對每個 Codex 子程序逐一抓包，未完成所有重連／跨權限／螢幕 DPI 驗收。

介面 Running 代表引擎程序運作，並非自動完成出口驗證。斷線或重新套用時可能
直接上網。其他系統 VPN 的 kill switch、瀏覽器安全 DNS 及外掛代理仍可能影響
實際路徑；程式不會修改這些產品的設定。

//! Foreground full-device macOS tunnel using RouteBar's own Rust WireGuard core.
#[cfg(target_os = "macos")]
#[path = "routebar_vpn/network.rs"]
mod network;
#[cfg(target_os = "macos")]
#[path = "routebar_vpn/runtime.rs"]
mod runtime;
#[cfg(target_os = "macos")]
#[path = "routebar_vpn/state.rs"]
mod state;
#[cfg(target_os = "macos")]
#[path = "routebar_vpn/utun.rs"]
mod utun;

fn main() {
    #[cfg(target_os = "macos")]
    if let Err(error) = runtime::run() {
        eprintln!("RouteBar VPN: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("routebar-vpn currently supports macOS only");
        std::process::exit(1);
    }
}

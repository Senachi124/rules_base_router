#[cfg(target_os = "macos")]
include!("main_macos.rs");

#[cfg(windows)]
include!("windows/cli.rs");

#[cfg(not(any(target_os = "macos", windows)))]
fn main() {
    eprintln!("RouteBar supports macOS and Windows.");
    std::process::exit(1);
}

//! Rust configuration and lifecycle controller for the certificate-free TUN backend.
pub mod config;
pub mod engine;
#[cfg(not(windows))]
pub mod runtime;
#[cfg(windows)]
#[path = "windows/runtime.rs"]
pub mod runtime;
#[cfg(target_os = "macos")]
pub mod service;
#[cfg(target_os = "macos")]
pub mod session;
pub mod wireguard;

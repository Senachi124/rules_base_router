# Sourced by build/test scripts. Prefer upstream Rust: some Homebrew std archives
# are built against the current host OS and cannot target older macOS releases.
if [ -x "$HOME/.cargo/bin/cargo" ]; then
  ROUTEBAR_CARGO="$HOME/.cargo/bin/cargo"
  export RUSTC="$HOME/.cargo/bin/rustc"
else
  ROUTEBAR_CARGO="$(command -v cargo)"
fi
export MACOSX_DEPLOYMENT_TARGET=13.0

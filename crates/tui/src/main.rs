//! `cleanroom-tui`: the Cleanroom incident command center. The console lives in the library.
#![allow(
    unused_crate_dependencies,
    reason = "thin entry point; the library half of this package uses every dependency. \
              `allow`, not `expect`: the lint only runs under the strict Clippy profile"
)]

fn main() -> std::process::ExitCode {
    cleanroom_tui::run()
}

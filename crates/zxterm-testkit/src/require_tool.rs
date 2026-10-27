//! A tool-presence skip helper: checks a tool is on `PATH` and returns a
//! skip reason if it is not — never panics, never silently no-ops.

use std::env;
use std::path::PathBuf;

/// Returns `None` if `tool` is on `PATH`, or `Some(reason)` — a
/// human-readable reason a test should print before returning early — if it
/// is not.
pub fn require_tool(tool: &str) -> Option<String> {
    match find_on_path(tool) {
        Some(_) => None,
        None => Some(format!("{tool} not found on PATH")),
    }
}

fn find_on_path(tool: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_tool_known_to_be_present() {
        // `sh` is required by std::process::Command's own fallback paths on
        // any POSIX system this workspace targets.
        assert!(require_tool("sh").is_none());
    }

    #[test]
    fn reports_a_reason_for_a_missing_tool() {
        let reason = require_tool("zxterm-testkit-tool-that-does-not-exist");
        assert_eq!(
            reason,
            Some("zxterm-testkit-tool-that-does-not-exist not found on PATH".to_string())
        );
    }
}

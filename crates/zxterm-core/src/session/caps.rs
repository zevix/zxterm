//! Capabilities (`protocol.md` §2), ZBTerm `engine/caps.js` bit for bit.

/// `caps.js::VIEW_LIVE`: receive live terminal output.
pub const VIEW_LIVE: u8 = 1 << 0;
/// `caps.js::READ_HISTORY`: decrypt recorded history for granted epochs.
pub const READ_HISTORY: u8 = 1 << 1;
/// `caps.js::QUICK_CATCHUP`: set, never checked (today and in v2).
pub const QUICK_CATCHUP: u8 = 1 << 2;
/// `caps.js::SEND_INPUT`: send sealed input to the host PTY.
pub const SEND_INPUT: u8 = 1 << 3;
/// `caps.js::ADMIN`: set, never checked (today and in v2).
pub const ADMIN: u8 = 1 << 4;
/// `caps.js::FULL_CAPS`.
pub const FULL_CAPS: u8 = 31;

/// `caps.js::normalize`: the known bits of `v`.
pub fn normalize(v: u64) -> u8 {
    (v & FULL_CAPS as u64) as u8
}

/// `caps.js::hasCap`.
pub fn has_cap(caps: u8, cap: u8) -> bool {
    caps & FULL_CAPS & cap == cap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_match_caps_js() {
        assert_eq!(
            [VIEW_LIVE, READ_HISTORY, QUICK_CATCHUP, SEND_INPUT, ADMIN],
            [1, 2, 4, 8, 16]
        );
        assert_eq!(
            FULL_CAPS,
            VIEW_LIVE | READ_HISTORY | QUICK_CATCHUP | SEND_INPUT | ADMIN
        );
        assert_eq!(normalize(0xFF), 31);
        assert!(has_cap(VIEW_LIVE | SEND_INPUT, SEND_INPUT));
        assert!(!has_cap(VIEW_LIVE, SEND_INPUT));
    }
}

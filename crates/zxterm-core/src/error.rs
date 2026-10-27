//! Error type mirroring ZBTerm's `engine/errors.js::EngineError`/`CODES`
//! exactly, so the seam (K7) maps the two one to one.

use std::error::Error as StdError;
use std::fmt;

/// Mirrors ZBTerm `engine/errors.js::CODES` exactly: eight codes, as read
/// from that file on 2026-09-28.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// `engine/errors.js::CODES.E_NET`
    ENet,
    /// `engine/errors.js::CODES.E_AUTH`
    EAuth,
    /// `engine/errors.js::CODES.E_NOKEY`
    ENoKey,
    /// `engine/errors.js::CODES.E_CORRUPT`
    ECorrupt,
    /// `engine/errors.js::CODES.E_HOST_UNREACHABLE`
    EHostUnreachable,
    /// `engine/errors.js::CODES.E_BACKEND_UNSUPPORTED`
    EBackendUnsupported,
    /// `engine/errors.js::CODES.E_BACKEND_UNAVAILABLE`
    EBackendUnavailable,
    /// `engine/errors.js::CODES.E_INTERNAL`
    EInternal,
}

impl Code {
    /// The wire string exactly as ZBTerm `engine/errors.js::CODES` writes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::ENet => "E_NET",
            Code::EAuth => "E_AUTH",
            Code::ENoKey => "E_NOKEY",
            Code::ECorrupt => "E_CORRUPT",
            Code::EHostUnreachable => "E_HOST_UNREACHABLE",
            Code::EBackendUnsupported => "E_BACKEND_UNSUPPORTED",
            Code::EBackendUnavailable => "E_BACKEND_UNAVAILABLE",
            Code::EInternal => "E_INTERNAL",
        }
    }

    /// All eight codes, in the order `engine/errors.js::CODES` declares them.
    pub const ALL: [Code; 8] = [
        Code::ENet,
        Code::EAuth,
        Code::ENoKey,
        Code::ECorrupt,
        Code::EHostUnreachable,
        Code::EBackendUnsupported,
        Code::EBackendUnavailable,
        Code::EInternal,
    ];
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Mirrors ZBTerm `engine/errors.js::EngineError`'s shape: `{code, message,
/// details}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub message: String,
    pub details: Option<String>,
}

impl Error {
    /// Builds an `Error` with no details, mirroring
    /// `new EngineError(code, message)`.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Builds an `Error` with details, mirroring
    /// `new EngineError(code, message, details)`.
    pub fn with_details(
        code: Code,
        message: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Error {
            code,
            message: message.into(),
            details: Some(details.into()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl StdError for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_strings_match_zbterm_codes() {
        // engine/errors.js::CODES, verified 2026-09-28.
        assert_eq!(Code::ENet.as_str(), "E_NET");
        assert_eq!(Code::EAuth.as_str(), "E_AUTH");
        assert_eq!(Code::ENoKey.as_str(), "E_NOKEY");
        assert_eq!(Code::ECorrupt.as_str(), "E_CORRUPT");
        assert_eq!(Code::EHostUnreachable.as_str(), "E_HOST_UNREACHABLE");
        assert_eq!(Code::EBackendUnsupported.as_str(), "E_BACKEND_UNSUPPORTED");
        assert_eq!(Code::EBackendUnavailable.as_str(), "E_BACKEND_UNAVAILABLE");
        assert_eq!(Code::EInternal.as_str(), "E_INTERNAL");
        assert_eq!(Code::ALL.len(), 8);
    }

    #[test]
    fn error_carries_code_message_details() {
        let err = Error::with_details(Code::EAuth, "bad signature", "detail");
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(err.message, "bad signature");
        assert_eq!(err.details.as_deref(), Some("detail"));
        assert_eq!(err.to_string(), "E_AUTH: bad signature");
    }
}

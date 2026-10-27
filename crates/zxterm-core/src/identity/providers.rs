//! Identity provider registry, ported from ZBTerm `engine/identity/
//! providers.js`. v1 ships `unknown` (never proven) and `github` (proven by
//! an SSH signature over a claim plus the published `.keys` list). Adding a
//! provider means adding a match arm here; nothing else in the identity
//! pipeline knows provider names.

use crate::error::{Code, Error};

/// `UNKNOWN` (providers.js).
pub const UNKNOWN: &str = "unknown";
/// `GITHUB` (providers.js).
pub const GITHUB: &str = "github";

/// A registered identity provider's fixed behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    pub id: &'static str,
    pub label: &'static str,
    pub needs_resolver: bool,
}

impl Provider {
    /// `displayId` (providers.js).
    pub fn display_id(&self, subject: &str) -> String {
        match self.id {
            UNKNOWN => format!("{}@UNKNOWN", &subject[..subject.len().min(12)]),
            GITHUB => format!("{}@github", subject.to_lowercase()),
            _ => unreachable!("Provider is only constructed by get_provider"),
        }
    }

    /// `validateSubject` (providers.js): `unknown` accepts and lowercases
    /// any string; `github` enforces `GITHUB_USERNAME`, trims, and
    /// lowercases, else `E_AUTH` `"Invalid github username: <value>"`.
    pub fn validate_subject(&self, subject: Option<&str>) -> Result<String, Error> {
        match self.id {
            UNKNOWN => Ok(subject.unwrap_or("").to_lowercase()),
            GITHUB => {
                let value = subject.unwrap_or("").trim();
                if !is_valid_github_username(value) {
                    return Err(Error::new(
                        Code::EAuth,
                        format!("Invalid github username: {value}"),
                    ));
                }
                Ok(value.to_lowercase())
            }
            _ => unreachable!("Provider is only constructed by get_provider"),
        }
    }
}

/// `GITHUB_USERNAME` (providers.js):
/// `/^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/` — a GitHub login is
/// 1-39 chars, alphanumeric or a hyphen that is never first, last, or
/// doubled.
fn is_valid_github_username(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() || chars.len() > 39 {
        return false;
    }
    if !chars[0].is_ascii_alphanumeric() {
        return false;
    }
    for i in 1..chars.len() {
        let c = chars[i];
        if c.is_ascii_alphanumeric() {
            continue;
        }
        // A `-` is allowed only when the *next* char is alphanumeric (the
        // regex's lookahead `-(?=[A-Za-z0-9])`), which also forbids a
        // trailing or doubled hyphen.
        if c == '-' && chars.get(i + 1).is_some_and(|n| n.is_ascii_alphanumeric()) {
            continue;
        }
        return false;
    }
    true
}

/// `getProvider` (providers.js): `E_AUTH` `"Unknown identity provider: <id>"`
/// for anything but `unknown`/`github`.
pub fn get_provider(id: &str) -> Result<Provider, Error> {
    match id {
        UNKNOWN => Ok(Provider {
            id: UNKNOWN,
            label: "Unverified",
            needs_resolver: false,
        }),
        GITHUB => Ok(Provider {
            id: GITHUB,
            label: "GitHub",
            needs_resolver: true,
        }),
        other => Err(Error::new(
            Code::EAuth,
            format!("Unknown identity provider: {other}"),
        )),
    }
}

/// `displayIdFor` (providers.js).
pub fn display_id_for(provider_id: &str, subject: &str) -> Result<String, Error> {
    Ok(get_provider(provider_id)?.display_id(subject))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_display_id_is_first_12_hex_chars_at_unknown() {
        let provider = get_provider(UNKNOWN).unwrap();
        assert_eq!(provider.display_id(&"a".repeat(64)), "aaaaaaaaaaaa@UNKNOWN");
    }

    #[test]
    fn github_display_id_is_subject_at_github() {
        let provider = get_provider(GITHUB).unwrap();
        assert_eq!(provider.display_id("Octocat"), "octocat@github");
    }

    #[test]
    fn github_validate_subject_lowercases_trims_and_rejects_bad_usernames() {
        let provider = get_provider(GITHUB).unwrap();
        assert_eq!(
            provider.validate_subject(Some("OctoCat")).unwrap(),
            "octocat"
        );
        assert!(provider.validate_subject(Some("-bad")).is_err());
        assert!(provider.validate_subject(Some(&"a".repeat(40))).is_err());
        assert!(provider.validate_subject(Some("a--b")).is_err());
        assert!(provider.validate_subject(Some("a-")).is_err());
        let err = provider.validate_subject(Some("-bad")).unwrap_err();
        assert_eq!(err.message, "Invalid github username: -bad");
    }

    #[test]
    fn unknown_provider_id_is_e_auth() {
        let err = get_provider("gitlab").unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(err.message, "Unknown identity provider: gitlab");
    }
}

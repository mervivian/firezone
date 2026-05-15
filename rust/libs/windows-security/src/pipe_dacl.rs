//! Type-safe builder for the SDDL flavours Firezone applies to its
//! named pipes.
//!
//! The full SDDL grammar (MS-DTYP §2.5.1) is sprawling — ACE types,
//! flag sets, generic vs specific access masks, four kinds of
//! conditional expression, on and on. This module deliberately
//! exposes only the small dialect our pipe DACLs need: protected
//! DACL, plain-allow + callback-allow ACEs, the file-access rights
//! `FA` / `FRFW`, and the `Member_of {SID(...)}` conditional.
//! Everything else is unrepresentable, so a typo or shape error
//! can't make it to runtime.

use crate::{SecurityDescriptor, current_logon_sid_string, current_user_sid_string};
use anyhow::Result;
use std::borrow::Cow;

/// File-system rights expressible in a Firezone pipe ACE. Encoded
/// SDDL strings: `FA` (full access) and `FRFW` (file generic read +
/// file generic write).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRights {
    /// `FA` — full access.
    FullAccess,
    /// `FRFW` — generic read + generic write.
    ReadWrite,
}

impl FileRights {
    fn as_sddl(self) -> &'static str {
        match self {
            FileRights::FullAccess => "FA",
            FileRights::ReadWrite => "FRFW",
        }
    }
}

/// A trustee — the SID or alias an ACE refers to.
///
/// There is no public string-based constructor. Every Trustee is
/// either a hard-coded alias, a SID read from the current process
/// token through Windows APIs, or a `&'static str` literal validated
/// at compile time via [`Self::from_static_sid`].
#[derive(Debug, Clone)]
pub struct Trustee(TrusteeRepr);

#[derive(Debug, Clone)]
enum TrusteeRepr {
    /// Two-letter SDDL alias (`SY`, `BA`, `BU`).
    Alias(&'static str),
    /// `S-1-…` SID — either a compile-time-validated literal
    /// (`Cow::Borrowed`) or a runtime-fetched token-derived SID
    /// (`Cow::Owned`).
    Sid(Cow<'static, str>),
}

impl Trustee {
    /// `SY` — the LocalSystem account.
    pub fn local_system() -> Self {
        Self(TrusteeRepr::Alias("SY"))
    }

    /// `BA` — the `BUILTIN\Administrators` group.
    pub fn builtin_administrators() -> Self {
        Self(TrusteeRepr::Alias("BA"))
    }

    /// `BU` — the `BUILTIN\Users` group.
    pub fn builtin_users() -> Self {
        Self(TrusteeRepr::Alias("BU"))
    }

    /// SID for the calling process's primary user, read from
    /// `GetTokenInformation(TokenUser)`. Cached per-thread inside the
    /// crate so repeated calls don't reissue the Win32 round-trip.
    pub fn current_user() -> Result<Self> {
        Ok(Self(TrusteeRepr::Sid(Cow::Owned(
            current_user_sid_string()?
        ))))
    }

    /// SID for the calling process's logon session, read from
    /// `GetTokenInformation(TokenLogonSid)`. Returns an error in
    /// contexts that don't have a logon-session SID (services,
    /// scheduled tasks); callers that want a graceful fallback can
    /// chain `.or_else(|_| Trustee::current_user())`.
    pub fn current_logon() -> Result<Self> {
        Ok(Self(TrusteeRepr::Sid(Cow::Owned(
            current_logon_sid_string()?,
        ))))
    }

    /// Compile-time-validated SID literal. The input is checked by a
    /// `const fn` parser that panics at const-eval time if the string
    /// isn't of the form `S-1-<digits>(-<digits>)+`. Intended for
    /// build-baked SIDs (e.g. the MSIX package SID via `env!()`).
    ///
    /// To make the check actually run at *build* time the call site
    /// must be in a `const` context. In a non-`const` context the
    /// same parser runs at runtime; that's the cost of stable Rust
    /// not having "const-only function" markers.
    pub const fn from_static_sid(s: &'static str) -> Self {
        assert!(
            is_valid_sid_str(s),
            "Trustee::from_static_sid: argument is not a syntactically valid SID string"
        );
        Self(TrusteeRepr::Sid(Cow::Borrowed(s)))
    }

    /// The string Windows expects for this trustee inside an SDDL
    /// ACE — `"SY"` for an alias, `"S-1-…"` for a SID.
    pub fn as_sddl_str(&self) -> &str {
        match &self.0 {
            TrusteeRepr::Alias(a) => a,
            TrusteeRepr::Sid(s) => s,
        }
    }
}

/// Pure-syntactic SID validator: matches `S-1-<u32>(-<u32>)+`.
/// Doesn't check that the resulting SID exists or that the numbers
/// are well-formed identifier authorities — but rejects every shape
/// `from_sddl` would reject too.
const fn is_valid_sid_str(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 5
        || bytes[0] != b'S'
        || bytes[1] != b'-'
        || bytes[2] != b'1'
        || bytes[3] != b'-'
    {
        return false;
    }
    let mut i = 4;
    let mut digits_in_run: u32 = 0;
    let mut runs: u32 = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' => digits_in_run += 1,
            b'-' => {
                if digits_in_run == 0 {
                    return false;
                }
                runs += 1;
                digits_in_run = 0;
            }
            _ => return false,
        }
        i += 1;
    }
    digits_in_run > 0 && runs >= 1
}

/// A protected DACL for a Firezone named pipe.
///
/// The SDDL produced is always prefixed `D:P` and contains only
/// `Allow` (`A`) and `AllowCallback` (`XA`) ACEs.
#[derive(Debug, Default)]
pub struct PipeDacl {
    aces: Vec<PipeAce>,
}

#[derive(Debug)]
enum PipeAce {
    /// `(A;;<rights>;;;<trustee>)`
    Allow {
        rights: FileRights,
        trustee: Trustee,
    },
    /// `(XA;;<rights>;;;<trustee>;(Member_of {SID(<scope>)}))`
    AllowIfMemberOf {
        rights: FileRights,
        trustee: Trustee,
        scope: Trustee,
    },
}

impl PipeDacl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Plain `(A;;<rights>;;;<trustee>)` ACE.
    pub fn allow(mut self, rights: FileRights, trustee: Trustee) -> Self {
        self.aces.push(PipeAce::Allow { rights, trustee });
        self
    }

    /// Callback-allow ACE: `<rights>` granted to `<trustee>` only
    /// when the requestor's token is a member of `<scope>`.
    pub fn allow_if_member_of(
        mut self,
        rights: FileRights,
        trustee: Trustee,
        scope: Trustee,
    ) -> Self {
        self.aces.push(PipeAce::AllowIfMemberOf {
            rights,
            trustee,
            scope,
        });
        self
    }

    /// Render the DACL as an SDDL string (`D:P(A;;…)(XA;;…;(…))…`).
    /// Useful for tests and `tracing` payloads; production builds
    /// usually call [`Self::build`] directly.
    pub fn to_sddl(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::from("D:P");
        for ace in &self.aces {
            match ace {
                PipeAce::Allow { rights, trustee } => {
                    let _ = write!(out, "(A;;{};;;{})", rights.as_sddl(), trustee.as_sddl_str());
                }
                PipeAce::AllowIfMemberOf {
                    rights,
                    trustee,
                    scope,
                } => {
                    let _ = write!(
                        out,
                        "(XA;;{};;;{};(Member_of {{SID({})}}))",
                        rights.as_sddl(),
                        trustee.as_sddl_str(),
                        scope.as_sddl_str(),
                    );
                }
            }
        }
        out
    }

    /// Parse the rendered SDDL into a [`SecurityDescriptor`].
    ///
    /// The SDDL is syntactically valid by construction — every field
    /// comes from a typed primitive — so the only failure mode left
    /// is the Windows kernel rejecting the conditional-ACE form (a
    /// pre-21H2 build without `Member_of` support). Caller is
    /// expected to surface that as a degradation, not a panic.
    pub fn build(&self) -> Result<SecurityDescriptor> {
        SecurityDescriptor::from_sddl(&self.to_sddl())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dacl_renders_protected_only() {
        assert_eq!(PipeDacl::new().to_sddl(), "D:P");
    }

    #[test]
    fn allow_renders_plain_ace() {
        let s = PipeDacl::new()
            .allow(FileRights::FullAccess, Trustee::local_system())
            .allow(FileRights::ReadWrite, Trustee::builtin_users())
            .to_sddl();
        assert_eq!(s, "D:P(A;;FA;;;SY)(A;;FRFW;;;BU)");
    }

    #[test]
    fn allow_if_member_of_renders_callback_ace() {
        const FAKE_PACKAGE_SID: &str = "S-1-15-2-1-2-3-4-5";
        const FAKE_LOGON_SID: &str = "S-1-5-5-0-12345";
        let s = PipeDacl::new()
            .allow_if_member_of(
                FileRights::ReadWrite,
                Trustee::from_static_sid(FAKE_PACKAGE_SID),
                Trustee::from_static_sid(FAKE_LOGON_SID),
            )
            .to_sddl();
        assert_eq!(
            s,
            "D:P(XA;;FRFW;;;S-1-15-2-1-2-3-4-5;(Member_of {SID(S-1-5-5-0-12345)}))"
        );
    }

    #[test]
    fn from_static_sid_round_trips_via_as_sddl_str() {
        const S: &str = "S-1-15-2-1-2-3-4-5";
        assert_eq!(Trustee::from_static_sid(S).as_sddl_str(), S);
    }

    #[test]
    fn validator_accepts_well_formed_sids() {
        assert!(is_valid_sid_str("S-1-5-18"));
        assert!(is_valid_sid_str("S-1-5-21-1-2-3-4"));
        assert!(is_valid_sid_str(
            "S-1-15-2-3854551971-16918785-1480441428-98749325-29286222"
        ));
    }

    #[test]
    fn validator_rejects_malformed() {
        assert!(!is_valid_sid_str(""));
        assert!(!is_valid_sid_str("S-2-5-18"));
        assert!(!is_valid_sid_str("S-1-"));
        assert!(!is_valid_sid_str("S-1--5-18"));
        assert!(!is_valid_sid_str("S-1-5-18-"));
        assert!(!is_valid_sid_str("S-1-5-foo"));
        assert!(!is_valid_sid_str("not a sid"));
    }

    /// The end-to-end shape `pipe_dacl` produces for the GUI pipe:
    /// `D:P(A;;FA;;;SY)(A;;FA;;;BA)(XA;;FRFW;;;<pkg>;(Member_of
    /// {SID(<scope>)}))`. Round-tripping it through `from_sddl`
    /// confirms the kernel accepts every shape this builder can emit.
    #[test]
    fn round_trips_through_security_descriptor() {
        const FAKE_PKG: &str = "S-1-15-2-1-2-3-4-5";
        const FAKE_SCOPE: &str = "S-1-5-5-0-12345";
        let dacl = PipeDacl::new()
            .allow(FileRights::FullAccess, Trustee::local_system())
            .allow(FileRights::FullAccess, Trustee::builtin_administrators())
            .allow_if_member_of(
                FileRights::ReadWrite,
                Trustee::from_static_sid(FAKE_PKG),
                Trustee::from_static_sid(FAKE_SCOPE),
            );
        dacl.build().expect("kernel should accept builder output");
    }
}

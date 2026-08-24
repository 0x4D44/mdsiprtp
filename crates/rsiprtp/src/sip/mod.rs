//! SIP message parsing and building for rsiprtp.
//!
//! Built on the in-tree parser at [`parser`]; exposes higher-level
//! request/response value types and builders for common SIP operations.

pub(crate) mod auth;
pub(crate) mod headers;
pub(crate) mod message;
// Exposed `pub` (with `#[doc(hidden)]`) so the in-tree integration test
// `tests/parser_diff.rs` can reach the in-progress parser. Public-API
// stability is not a concern: nothing inside `parser/` is part of our
// committed public surface yet (M7 owns that). The hide marker keeps
// it out of rustdoc.
#[doc(hidden)]
pub mod parser;
pub(crate) mod uri;

#[cfg(test)]
mod tests;

// Re-export main types
pub use message::{
    generate_branch, generate_call_id, generate_tag, Method, SipMessage, SipRequest,
    SipRequestBuilder, SipResponse, SipResponseBuilder,
};

// Re-export auth types
pub use auth::{
    derive_akav2_password, Algorithm, DigestAuthError, DigestChallenge, DigestCredentials,
    DigestResponse, Qop,
};

// Re-export header types
pub use headers::{
    Contact, MinSe, RAck, RSeq, RecordRoute, Refresher, Require, Route, RouteSet, SessionExpires,
    Supported, Via,
};

// Re-export URI types
pub use uri::{Scheme, SipUri, SipUriBuilder};

//! SIP message types and wrappers.
//!
//! M8: cut over to the in-tree parser. Storage holds `parser::Request`
//! / `parser::Response` directly; `rsip` is no longer touched on the
//! hot path. The public API surface is frozen at the M7 contract — all
//! accessor signatures remain unchanged.

use crate::core::{Result, SipError};
use crate::sip::parser::header::Header as PHeader;
use crate::sip::parser::header::Headers as PHeaders;
use crate::sip::parser::method::Method as PMethod;
use crate::sip::parser::status::StatusCode as PStatusCode;
use crate::sip::parser::typed::{Contact as PContact, From as PFrom, To as PTo, Via as PVia};
use crate::sip::parser::{Message as PMessage, Request as PRequest, Response as PResponse};
use crate::sip::uri::SipUri;
use bytes::Bytes;
use std::fmt;
use std::str::FromStr;

#[cfg(coverage)]
#[inline(always)]
fn cover_none_case() {
    std::hint::black_box(());
}

#[cfg(not(coverage))]
#[inline(always)]
fn cover_none_case() {}

/// Look up the value of a non-standard header (carried as `Header::Other`)
/// by name, case-insensitively. Returns the trimmed value if present.
fn find_other_header(headers: &PHeaders, name: &str) -> Option<String> {
    for header in headers.iter() {
        if let PHeader::Other(key, value) = header {
            if key.eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Find and parse `Require` header(s). Handles both the native
/// (`Header::Require`) and the generic `Header::Other` form for
/// `name_matches("Require")`.
///
/// Per RFC 3261 §7.3.1, multiple `Require` lines are equivalent to a single
/// comma-separated value, so we concat option-tags from every matching
/// header line in wire order. Duplicates are preserved — the consumer
/// decides whether to deduplicate.
fn find_require(headers: &PHeaders) -> Option<crate::sip::headers::Require> {
    let mut tags: Vec<String> = Vec::new();
    for header in headers.iter() {
        match header {
            PHeader::Require(value) => {
                if let Ok(parsed) = crate::sip::headers::Require::parse(value) {
                    tags.extend(parsed.0);
                }
            }
            PHeader::Other(key, value) if key.eq_ignore_ascii_case("Require") => {
                if let Ok(parsed) = crate::sip::headers::Require::parse(value) {
                    tags.extend(parsed.0);
                }
            }
            _ => {}
        }
    }
    if tags.is_empty() {
        None
    } else {
        Some(crate::sip::headers::Require(tags))
    }
}

/// Find and parse `Allow` header(s) into a `Vec<Method>`.
///
/// Multiple `Allow` lines are equivalent to a single comma-separated value
/// per RFC 3261 §7.3.1; method tokens from every matching line are
/// concatenated in wire order. Unknown method tokens are skipped silently
/// rather than failing the whole header — this is a read-side normalization
/// only. Returns `None` when no `Allow` header is present at all (so the
/// caller can distinguish "absent" from "present but empty/all-unknown").
fn find_allow(headers: &PHeaders) -> Option<Vec<Method>> {
    let mut values: Vec<String> = Vec::new();
    for header in headers.iter() {
        match header {
            PHeader::Allow(value) => values.push(value.clone()),
            PHeader::Other(key, value) if key.eq_ignore_ascii_case("Allow") => {
                values.push(value.clone());
            }
            _ => {}
        }
    }
    if values.is_empty() {
        return None;
    }
    let mut methods: Vec<Method> = Vec::new();
    for raw in values {
        for tok in raw.split(',') {
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                continue;
            }
            // `Method::from_str` is case-insensitive; unknown method
            // tokens are skipped silently per the doc above.
            if let Ok(m) = Method::from_str(trimmed) {
                methods.push(m);
            }
        }
    }
    Some(methods)
}

/// Find and parse `Supported` header(s).
///
/// Per RFC 3261 §7.3.1, multiple `Supported` lines are equivalent to a
/// single comma-separated value; tags from every matching line are
/// concatenated in wire order. Duplicates are preserved.
fn find_supported(headers: &PHeaders) -> Option<crate::sip::headers::Supported> {
    let mut tags: Vec<String> = Vec::new();
    for header in headers.iter() {
        match header {
            PHeader::Supported(value) => {
                if let Ok(parsed) = crate::sip::headers::Supported::parse(value) {
                    tags.extend(parsed.0);
                }
            }
            PHeader::Other(key, value) if key.eq_ignore_ascii_case("Supported") => {
                if let Ok(parsed) = crate::sip::headers::Supported::parse(value) {
                    tags.extend(parsed.0);
                }
            }
            _ => {}
        }
    }
    if tags.is_empty() {
        None
    } else {
        Some(crate::sip::headers::Supported(tags))
    }
}

/// SIP message (either request or response).
#[derive(Debug, Clone)]
pub enum SipMessage {
    /// A SIP request (INVITE, REGISTER, BYE, ...).
    Request(SipRequest),
    /// A SIP response (1xx-6xx status).
    Response(SipResponse),
}

impl SipMessage {
    /// Parse a SIP message from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let msg = PMessage::parse(data).map_err(|e| SipError::Parse(e.to_string()))?;

        match msg {
            PMessage::Request(req) => Ok(SipMessage::Request(SipRequest { inner: req })),
            PMessage::Response(resp) => Ok(SipMessage::Response(SipResponse { inner: resp })),
        }
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Bytes {
        match self {
            SipMessage::Request(req) => req.to_bytes(),
            SipMessage::Response(resp) => resp.to_bytes(),
        }
    }

    /// Check if this is a request.
    pub fn is_request(&self) -> bool {
        matches!(self, SipMessage::Request(_))
    }

    /// Check if this is a response.
    pub fn is_response(&self) -> bool {
        matches!(self, SipMessage::Response(_))
    }

    /// Get as request if it is one.
    pub fn as_request(&self) -> Option<&SipRequest> {
        match self {
            SipMessage::Request(req) => Some(req),
            _ => None,
        }
    }

    /// Get as response if it is one.
    pub fn as_response(&self) -> Option<&SipResponse> {
        match self {
            SipMessage::Response(resp) => Some(resp),
            _ => None,
        }
    }
}

/// SIP request wrapper.
#[derive(Debug, Clone)]
pub struct SipRequest {
    pub(crate) inner: PRequest,
}

impl SipRequest {
    /// Get the request method.
    pub fn method(&self) -> Method {
        method_from_parser(self.inner.method)
    }

    /// Get the request URI.
    ///
    /// Returns an owned [`SipUri`]. M8 makes this a thin wrapper over
    /// the parser-side raw URI string; M3's `SipUri::parse` is the
    /// owned-form decoder. The framing layer validates the
    /// Request-URI through `SipUri::parse` before storing it, so by
    /// the time we get here the call is infallible — a panic here
    /// would be an internal invariant violation, not user input.
    pub fn uri(&self) -> SipUri {
        SipUri::parse(&self.inner.uri)
            .expect("parser-accepted URI round-trips through SipUri::parse")
    }

    /// Get the Call-ID header value.
    pub fn call_id(&self) -> Result<String> {
        self.inner
            .headers
            .get_first("Call-ID")
            .map(|h| h.value().to_string())
            .ok_or_else(|| SipError::MissingHeader("Call-ID".to_string()).into())
    }

    /// Get the From tag.
    pub fn from_tag(&self) -> Result<String> {
        let from_value = self
            .inner
            .headers
            .get_first("From")
            .ok_or_else(|| SipError::MissingHeader("From".to_string()))?
            .value();
        let typed_from = PFrom::parse(from_value).map_err(|e| SipError::Parse(e.to_string()))?;
        let tag = typed_from
            .tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()))?;
        Ok(tag)
    }

    /// Get the From tag and URI with a single parse.
    pub fn from_tag_and_uri(&self) -> Result<(String, SipUri)> {
        let from_value = self
            .inner
            .headers
            .get_first("From")
            .ok_or_else(|| SipError::MissingHeader("From".to_string()))?
            .value();
        let typed_from = PFrom::parse(from_value).map_err(|e| SipError::Parse(e.to_string()))?;
        let tag = typed_from
            .tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()))?;
        Ok((tag, typed_from.uri))
    }

    /// Get the To tag (may not exist in requests).
    pub fn to_tag(&self) -> Option<String> {
        let to_value = self.inner.headers.get_first("To").map(|h| h.value())?;
        let typed_to = PTo::parse(to_value).ok()?;
        typed_to.tag().map(|t| t.to_string())
    }

    /// Get the Via branch parameter.
    pub fn via_branch(&self) -> Result<String> {
        let via_value = self
            .inner
            .headers
            .get_first("Via")
            .ok_or_else(|| SipError::MissingHeader("Via".to_string()))?
            .value();
        let typed_via = PVia::parse(via_value).map_err(|e| SipError::Parse(e.to_string()))?;
        let branch = typed_via
            .branch()
            .map(|b| b.to_string())
            .ok_or_else(|| SipError::InvalidHeader("Via header missing branch".to_string()))?;
        Ok(branch)
    }

    /// Get the CSeq number.
    pub fn cseq(&self) -> Result<u32> {
        let cseq_value = self
            .inner
            .headers
            .get_first("CSeq")
            .ok_or_else(|| SipError::MissingHeader("CSeq".to_string()))?
            .value();
        let typed_cseq = crate::sip::parser::typed::CSeq::parse(cseq_value)
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_cseq.seq)
    }

    /// Get the CSeq method.
    pub fn cseq_method(&self) -> Result<Method> {
        let cseq_value = self
            .inner
            .headers
            .get_first("CSeq")
            .ok_or_else(|| SipError::MissingHeader("CSeq".to_string()))?
            .value();
        let typed_cseq = crate::sip::parser::typed::CSeq::parse(cseq_value)
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(method_from_parser(typed_cseq.method))
    }

    /// Get the From URI.
    pub fn from_uri(&self) -> Result<SipUri> {
        let from_value = self
            .inner
            .headers
            .get_first("From")
            .ok_or_else(|| SipError::MissingHeader("From".to_string()))?
            .value();
        let typed_from = PFrom::parse(from_value).map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_from.uri)
    }

    /// Get the To URI.
    pub fn to_uri(&self) -> Result<SipUri> {
        let to_value = self
            .inner
            .headers
            .get_first("To")
            .ok_or_else(|| SipError::MissingHeader("To".to_string()))?
            .value();
        let typed_to = PTo::parse(to_value).map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_to.uri)
    }

    /// Get the Contact URI if present.
    pub fn contact_uri(&self) -> Option<SipUri> {
        let value = self.inner.headers.get_first("Contact").map(|h| h.value())?;
        match PContact::parse(value).ok()? {
            PContact::Wildcard { .. } => None,
            PContact::Addr(addr) => Some(addr.uri),
        }
    }

    /// Get the message body.
    pub fn body(&self) -> &[u8] {
        &self.inner.body
    }

    /// Get the Content-Type header.
    pub fn content_type(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let PHeader::ContentType(ct) = header {
                return Some(ct.clone());
            }
        }
        None
    }

    /// Get Record-Route headers as bare value strings.
    ///
    /// Returns a vector of Record-Route header *values* (not full
    /// header lines). The returned strings are bare URI values
    /// (e.g. `<sip:proxy.example.com;lr>`), suitable for feeding
    /// straight into `RouteSet::from_record_route_values`.
    pub fn record_routes(&self) -> Vec<String> {
        let mut routes = Vec::new();
        for header in self.inner.headers.iter() {
            if let PHeader::RecordRoute(rr) = header {
                routes.push(rr.clone());
            }
        }
        routes
    }

    /// Get Via headers as string values (the typed-form `Display`
    /// reproduction — "SIP/2.0/UDP host:port;branch=...").
    pub fn via_headers_raw(&self) -> Vec<String> {
        let mut vias = Vec::new();
        for header in self.inner.headers.iter() {
            if let PHeader::Via(v) = header {
                // Match rsip's `Via.to_string()` which emitted just the
                // raw value (without "Via: " prefix). The typed Display
                // round-trips the protocol/transport/sent-by + params
                // for callers that need a normalized form; for the bare
                // wire-shape passthrough we use the stored value
                // directly.
                vias.push(v.clone());
            }
        }
        vias
    }

    /// Get the `Require` header (RFC 3261 §20.32) if present.
    pub fn require(&self) -> Option<crate::sip::headers::Require> {
        find_require(&self.inner.headers)
    }

    /// Get the `Supported` header (RFC 3261 §20.37) if present.
    pub fn supported(&self) -> Option<crate::sip::headers::Supported> {
        find_supported(&self.inner.headers)
    }

    /// Get the `Session-Expires` header (RFC 4028 §4) if present.
    ///
    /// Per RFC 4028 §4 ABNF, the long form `Session-Expires` and compact
    /// form `x` are equivalent; we accept either on read.
    pub fn session_expires(&self) -> Option<crate::sip::headers::SessionExpires> {
        find_other_header(&self.inner.headers, "Session-Expires")
            .or_else(|| find_other_header(&self.inner.headers, "x"))
            .and_then(|v| crate::sip::headers::SessionExpires::parse(&v).ok())
    }

    /// Get the `Min-SE` header (RFC 4028 §5) if present.
    pub fn min_se(&self) -> Option<crate::sip::headers::MinSe> {
        find_other_header(&self.inner.headers, "Min-SE")
            .and_then(|v| crate::sip::headers::MinSe::parse(&v).ok())
    }

    /// Get the `RAck` header (RFC 3262 §7.2) if present.
    ///
    /// Only meaningful on PRACK requests.
    pub fn rack(&self) -> Option<crate::sip::headers::RAck> {
        find_other_header(&self.inner.headers, "RAck")
            .and_then(|v| crate::sip::headers::RAck::parse(&v).ok())
    }

    /// Get the `Allow` header (RFC 3261 §20.5) if present, parsed as a list
    /// of methods. Unknown method tokens are skipped silently.
    pub fn allow(&self) -> Option<Vec<Method>> {
        find_allow(&self.inner.headers)
    }

    /// Get all `Route` header values (RFC 3261 §20.34) in wire order,
    /// each as the raw header value (e.g. `<sip:proxy.example.com;lr>`).
    /// Returns an empty Vec if no Route headers are present.
    pub fn route_headers(&self) -> Vec<String> {
        let mut routes = Vec::new();
        for header in self.inner.headers.iter() {
            if let PHeader::Route(r) = header {
                routes.push(r.trim().to_string());
            }
        }
        routes
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.inner.to_bytes())
    }

    /// Create a builder for a new request.
    pub fn builder() -> SipRequestBuilder {
        SipRequestBuilder::new()
    }
}

/// SIP response wrapper.
#[derive(Debug, Clone)]
pub struct SipResponse {
    pub(crate) inner: PResponse,
}

impl SipResponse {
    /// Get the status code.
    pub fn status_code(&self) -> u16 {
        self.inner.status_code.as_u16()
    }

    /// Get the reason phrase.
    pub fn reason(&self) -> String {
        // Mirror M7 behavior: prefer the wire-supplied reason text if
        // present, otherwise fall back to the canonical phrase for the
        // numeric code.
        if !self.inner.reason.is_empty() {
            self.inner.reason.clone()
        } else {
            self.inner.status_code.reason_phrase().to_string()
        }
    }

    /// Check if this is a provisional response (1xx).
    pub fn is_provisional(&self) -> bool {
        let code = self.status_code();
        (100..200).contains(&code)
    }

    /// Check if this is a success response (2xx).
    pub fn is_success(&self) -> bool {
        let code = self.status_code();
        (200..300).contains(&code)
    }

    /// Check if this is a failure response (3xx-6xx).
    pub fn is_failure(&self) -> bool {
        let code = self.status_code();
        code >= 300
    }

    /// Get the Call-ID header value.
    pub fn call_id(&self) -> Result<String> {
        self.inner
            .headers
            .get_first("Call-ID")
            .map(|h| h.value().to_string())
            .ok_or_else(|| SipError::MissingHeader("Call-ID".to_string()).into())
    }

    /// Get the From tag.
    pub fn from_tag(&self) -> Result<String> {
        let from_value = self
            .inner
            .headers
            .get_first("From")
            .ok_or_else(|| SipError::MissingHeader("From".to_string()))?
            .value();
        let typed_from = PFrom::parse(from_value).map_err(|e| SipError::Parse(e.to_string()))?;
        let tag = typed_from
            .tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()))?;
        Ok(tag)
    }

    /// Get the To tag.
    pub fn to_tag(&self) -> Option<String> {
        let to_value = self.inner.headers.get_first("To").map(|h| h.value())?;
        let typed_to = PTo::parse(to_value).ok()?;
        typed_to.tag().map(|t| t.to_string())
    }

    /// Get the Via branch parameter.
    pub fn via_branch(&self) -> Result<String> {
        let via_value = self
            .inner
            .headers
            .get_first("Via")
            .ok_or_else(|| SipError::MissingHeader("Via".to_string()))?
            .value();
        let typed_via = PVia::parse(via_value).map_err(|e| SipError::Parse(e.to_string()))?;
        let branch = typed_via
            .branch()
            .map(|b| b.to_string())
            .ok_or_else(|| SipError::InvalidHeader("Via header missing branch".to_string()))?;
        Ok(branch)
    }

    /// Get the CSeq number.
    pub fn cseq(&self) -> Result<u32> {
        let cseq_value = self
            .inner
            .headers
            .get_first("CSeq")
            .ok_or_else(|| SipError::MissingHeader("CSeq".to_string()))?
            .value();
        let typed_cseq = crate::sip::parser::typed::CSeq::parse(cseq_value)
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_cseq.seq)
    }

    /// Get the CSeq method.
    pub fn cseq_method(&self) -> Result<Method> {
        let cseq_value = self
            .inner
            .headers
            .get_first("CSeq")
            .ok_or_else(|| SipError::MissingHeader("CSeq".to_string()))?
            .value();
        let typed_cseq = crate::sip::parser::typed::CSeq::parse(cseq_value)
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(method_from_parser(typed_cseq.method))
    }

    /// Get the Contact URI if present.
    pub fn contact_uri(&self) -> Option<SipUri> {
        let value = self.inner.headers.get_first("Contact").map(|h| h.value())?;
        match PContact::parse(value).ok()? {
            PContact::Wildcard { .. } => None,
            PContact::Addr(addr) => Some(addr.uri),
        }
    }

    /// Get the message body.
    pub fn body(&self) -> &[u8] {
        &self.inner.body
    }

    /// Get the Content-Type header.
    pub fn content_type(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let PHeader::ContentType(ct) = header {
                return Some(ct.clone());
            }
        }
        None
    }

    /// Get Record-Route headers as bare value strings.
    pub fn record_routes(&self) -> Vec<String> {
        let mut routes = Vec::new();
        for header in self.inner.headers.iter() {
            if let PHeader::RecordRoute(rr) = header {
                routes.push(rr.clone());
            }
        }
        routes
    }

    /// Get Via headers as string values.
    pub fn via_headers_raw(&self) -> Vec<String> {
        let mut vias = Vec::new();
        for header in self.inner.headers.iter() {
            if let PHeader::Via(v) = header {
                vias.push(v.clone());
            }
        }
        vias
    }

    /// Get the WWW-Authenticate header value.
    ///
    /// Used to extract digest authentication challenge from 401 responses.
    pub fn www_authenticate(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let PHeader::WwwAuthenticate(auth) = header {
                return Some(auth.clone());
            }
        }
        None
    }

    /// Get the Proxy-Authenticate header value.
    ///
    /// Used to extract digest authentication challenge from 407 responses.
    pub fn proxy_authenticate(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let PHeader::ProxyAuthenticate(auth) = header {
                return Some(auth.clone());
            }
        }
        None
    }

    /// Get the `Security-Server` header value (3GPP TS 33.203 §7.1,
    /// via RFC 3329's `Security-Server` header) if present.
    ///
    /// Not part of RFC 3261's typed header model — carried as
    /// `Header::Other`, matched case-insensitively. Used to read the
    /// P-CSCF's IPsec algorithm/SPI/port proposal out of the 401
    /// response during IMS AKA registration.
    pub fn security_server(&self) -> Option<String> {
        find_other_header(&self.inner.headers, "Security-Server")
    }

    /// Get the `Require` header (RFC 3261 §20.32) if present.
    pub fn require(&self) -> Option<crate::sip::headers::Require> {
        find_require(&self.inner.headers)
    }

    /// Get the `Supported` header (RFC 3261 §20.37) if present.
    pub fn supported(&self) -> Option<crate::sip::headers::Supported> {
        find_supported(&self.inner.headers)
    }

    /// Get the `Session-Expires` header (RFC 4028 §4) if present.
    ///
    /// Per RFC 4028 §4 ABNF, the long form `Session-Expires` and compact
    /// form `x` are equivalent; we accept either on read.
    pub fn session_expires(&self) -> Option<crate::sip::headers::SessionExpires> {
        find_other_header(&self.inner.headers, "Session-Expires")
            .or_else(|| find_other_header(&self.inner.headers, "x"))
            .and_then(|v| crate::sip::headers::SessionExpires::parse(&v).ok())
    }

    /// Get the `Min-SE` header (RFC 4028 §5) if present.
    pub fn min_se(&self) -> Option<crate::sip::headers::MinSe> {
        find_other_header(&self.inner.headers, "Min-SE")
            .and_then(|v| crate::sip::headers::MinSe::parse(&v).ok())
    }

    /// Get the `RSeq` header (RFC 3262 §7.1) if present.
    ///
    /// Only meaningful on reliable provisional responses.
    pub fn rseq(&self) -> Option<crate::sip::headers::RSeq> {
        find_other_header(&self.inner.headers, "RSeq")
            .and_then(|v| crate::sip::headers::RSeq::parse(&v).ok())
    }

    /// Get the `Allow` header (RFC 3261 §20.5) if present, parsed as a list
    /// of methods. Unknown method tokens are skipped silently.
    pub fn allow(&self) -> Option<Vec<Method>> {
        find_allow(&self.inner.headers)
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.inner.to_bytes())
    }

    /// Mutable access to the underlying parser response. Used by the
    /// transaction layer to inject reliable-provisional headers (RFC 3262
    /// §4) into a TU-built response without round-tripping through the
    /// wire-byte representation.
    ///
    /// Restricted to crate visibility — external callers must not mutate
    /// `Via` / status code / etc. on a constructed response.
    pub(crate) fn inner_mut(&mut self) -> &mut PResponse {
        &mut self.inner
    }

    /// Create a builder for a new response.
    pub fn builder() -> SipResponseBuilder {
        SipResponseBuilder::new()
    }
}

/// SIP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// INVITE — initiates a session (RFC 3261 §13).
    Invite,
    /// ACK — confirms receipt of a final response to INVITE (RFC 3261 §17).
    Ack,
    /// BYE — terminates an established session (RFC 3261 §15).
    Bye,
    /// CANCEL — cancels an in-flight request (RFC 3261 §9).
    Cancel,
    /// REGISTER — binds a contact address to an address-of-record (RFC 3261 §10).
    Register,
    /// OPTIONS — queries a peer's capabilities (RFC 3261 §11).
    Options,
    /// PRACK — provisional response acknowledgement (RFC 3262).
    Prack,
    /// SUBSCRIBE — requests notification of an event package (RFC 3265/6665).
    Subscribe,
    /// NOTIFY — delivers an event-package notification to a subscriber (RFC 3265/6665).
    Notify,
    /// PUBLISH — publishes event state to a server (RFC 3903).
    Publish,
    /// INFO — sends mid-dialog application information (RFC 6086).
    Info,
    /// REFER — asks the recipient to issue a request to a third party (RFC 3515).
    Refer,
    /// MESSAGE — carries an instant message payload (RFC 3428).
    Message,
    /// UPDATE — modifies session state without affecting dialog state (RFC 3311).
    Update,
}

impl Method {
    /// Check if this method creates a dialog.
    pub fn creates_dialog(&self) -> bool {
        matches!(self, Method::Invite | Method::Subscribe)
    }

    /// Check if this is an INVITE method.
    pub fn is_invite(&self) -> bool {
        matches!(self, Method::Invite)
    }
}

/// Internal: bridge `parser::Method` ↔ wrapper `Method`. M8 keeps a
/// thin one-to-one mapping; both enums have the same 14 canonical
/// variants so the conversion is total and lossless.
fn method_from_parser(m: PMethod) -> Method {
    match m {
        PMethod::Invite => Method::Invite,
        PMethod::Ack => Method::Ack,
        PMethod::Bye => Method::Bye,
        PMethod::Cancel => Method::Cancel,
        PMethod::Register => Method::Register,
        PMethod::Options => Method::Options,
        PMethod::Prack => Method::Prack,
        PMethod::Subscribe => Method::Subscribe,
        PMethod::Notify => Method::Notify,
        PMethod::Publish => Method::Publish,
        PMethod::Info => Method::Info,
        PMethod::Refer => Method::Refer,
        PMethod::Message => Method::Message,
        PMethod::Update => Method::Update,
    }
}

fn method_to_parser(m: Method) -> PMethod {
    match m {
        Method::Invite => PMethod::Invite,
        Method::Ack => PMethod::Ack,
        Method::Bye => PMethod::Bye,
        Method::Cancel => PMethod::Cancel,
        Method::Register => PMethod::Register,
        Method::Options => PMethod::Options,
        Method::Prack => PMethod::Prack,
        Method::Subscribe => PMethod::Subscribe,
        Method::Notify => PMethod::Notify,
        Method::Publish => PMethod::Publish,
        Method::Info => PMethod::Info,
        Method::Refer => PMethod::Refer,
        Method::Message => PMethod::Message,
        Method::Update => PMethod::Update,
    }
}

impl FromStr for Method {
    type Err = SipError;

    /// Parse a SIP method name from its canonical token, case-insensitively.
    ///
    /// Matches the parser-layer `Method::from_str` semantics — RFC 3261
    /// §7.1 declares method names case-sensitive on the wire, but liberal
    /// acceptance on parse is the correct robustness stance.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        const ALL: &[(Method, &str)] = &[
            (Method::Invite, "INVITE"),
            (Method::Ack, "ACK"),
            (Method::Bye, "BYE"),
            (Method::Cancel, "CANCEL"),
            (Method::Register, "REGISTER"),
            (Method::Options, "OPTIONS"),
            (Method::Prack, "PRACK"),
            (Method::Subscribe, "SUBSCRIBE"),
            (Method::Notify, "NOTIFY"),
            (Method::Publish, "PUBLISH"),
            (Method::Info, "INFO"),
            (Method::Refer, "REFER"),
            (Method::Message, "MESSAGE"),
            (Method::Update, "UPDATE"),
        ];
        for (m, name) in ALL {
            if s.eq_ignore_ascii_case(name) {
                return Ok(*m);
            }
        }
        Err(SipError::Parse(format!("unknown SIP method: {s}")))
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Prack => "PRACK",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Publish => "PUBLISH",
            Method::Info => "INFO",
            Method::Refer => "REFER",
            Method::Message => "MESSAGE",
            Method::Update => "UPDATE",
        };
        write!(f, "{}", s)
    }
}

/// Builder for SIP requests.
#[derive(Debug, Default)]
pub struct SipRequestBuilder {
    method: Option<PMethod>,
    /// Request URI as a parsed `SipUri`. We store the parsed form so
    /// the builder can validate at field-set time and surface the
    /// error on `build()`.
    uri: Option<SipUri>,
    uri_error: Option<String>,
    via_branch: Option<String>,
    via_host: Option<String>,
    via_port: Option<u16>,
    via_transport: Option<String>,
    from_uri: Option<SipUri>,
    from_uri_error: Option<String>,
    from_tag: Option<String>,
    from_display: Option<String>,
    to_uri: Option<SipUri>,
    to_uri_error: Option<String>,
    to_tag: Option<String>,
    call_id: Option<String>,
    cseq: Option<u32>,
    contact_uri: Option<SipUri>,
    max_forwards: Option<u32>,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) content_type: Option<String>,
    authorization: Option<String>,
    proxy_authorization: Option<String>,
    expires: Option<u32>,
    require: Option<crate::sip::headers::Require>,
    supported: Option<crate::sip::headers::Supported>,
    session_expires: Option<crate::sip::headers::SessionExpires>,
    min_se: Option<crate::sip::headers::MinSe>,
    rack: Option<crate::sip::headers::RAck>,
    allow: Option<Vec<Method>>,
    routes: Option<Vec<String>>,
    other_headers: Vec<(String, String)>,
}

impl SipRequestBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the method.
    pub fn method(mut self, method: Method) -> Self {
        self.method = Some(method_to_parser(method));
        self
    }

    /// Set the request URI.
    ///
    /// The URI should be a valid SIP URI (e.g., "sip:user@host").
    /// If the URI is invalid, an error will be returned when `build()` is called.
    pub fn uri(mut self, uri: &str) -> Self {
        match SipUri::parse(uri) {
            Ok(u) => {
                self.uri = Some(u);
                self.uri_error = None;
            }
            Err(e) => {
                self.uri_error = Some(format!("Invalid request URI '{}': {}", uri, e));
            }
        }
        self
    }

    /// Set the Via header.
    pub fn via(mut self, host: &str, port: u16, transport: &str, branch: &str) -> Self {
        self.via_host = Some(host.to_string());
        self.via_port = Some(port);
        self.via_transport = Some(transport.to_string());
        self.via_branch = Some(branch.to_string());
        self
    }

    /// Set the From header.
    ///
    /// The URI should be a valid SIP URI (e.g., "sip:user@host").
    pub fn from(mut self, uri: &str, tag: &str) -> Self {
        match SipUri::parse(uri) {
            Ok(u) => {
                self.from_uri = Some(u);
                self.from_uri_error = None;
            }
            Err(e) => {
                self.from_uri_error = Some(format!("Invalid From URI '{}': {}", uri, e));
            }
        }
        self.from_tag = Some(tag.to_string());
        self
    }

    /// Set the From display name.
    pub fn from_display(mut self, name: &str) -> Self {
        self.from_display = Some(name.to_string());
        self
    }

    /// Set the To header.
    ///
    /// The URI should be a valid SIP URI (e.g., "sip:user@host").
    pub fn to(mut self, uri: &str) -> Self {
        match SipUri::parse(uri) {
            Ok(u) => {
                self.to_uri = Some(u);
                self.to_uri_error = None;
            }
            Err(e) => {
                self.to_uri_error = Some(format!("Invalid To URI '{}': {}", uri, e));
            }
        }
        self
    }

    /// Set the To tag.
    pub fn to_tag(mut self, tag: &str) -> Self {
        self.to_tag = Some(tag.to_string());
        self
    }

    /// Set the Call-ID.
    pub fn call_id(mut self, call_id: &str) -> Self {
        self.call_id = Some(call_id.to_string());
        self
    }

    /// Set the CSeq.
    pub fn cseq(mut self, seq: u32) -> Self {
        self.cseq = Some(seq);
        self
    }

    /// Set the Contact header.
    pub fn contact(mut self, uri: &str) -> Self {
        if let Ok(u) = SipUri::parse(uri) {
            self.contact_uri = Some(u);
        }
        self
    }

    /// Set Max-Forwards.
    pub fn max_forwards(mut self, mf: u32) -> Self {
        self.max_forwards = Some(mf);
        self
    }

    /// Set the body.
    pub fn body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.body = Some(body);
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Set the Authorization header for digest authentication.
    pub fn authorization(mut self, auth: &str) -> Self {
        self.authorization = Some(auth.to_string());
        self
    }

    /// Set the Proxy-Authorization header for proxy digest authentication.
    pub fn proxy_authorization(mut self, auth: &str) -> Self {
        self.proxy_authorization = Some(auth.to_string());
        self
    }

    /// Set the Expires header (used for REGISTER).
    pub fn expires(mut self, seconds: u32) -> Self {
        self.expires = Some(seconds);
        self
    }

    /// Set the `Require` header (RFC 3261 §20.32) to the given option-tags.
    pub fn require(mut self, tags: &[&str]) -> Self {
        if tags.is_empty() {
            self.require = None;
        } else {
            self.require = Some(crate::sip::headers::Require(
                tags.iter().map(|t| t.to_string()).collect(),
            ));
        }
        self
    }

    /// Set the `Supported` header (RFC 3261 §20.37).
    pub fn supported(mut self, tags: &[&str]) -> Self {
        if tags.is_empty() {
            self.supported = None;
        } else {
            self.supported = Some(crate::sip::headers::Supported(
                tags.iter().map(|t| t.to_string()).collect(),
            ));
        }
        self
    }

    /// Set the `Session-Expires` header (RFC 4028 §4).
    pub fn session_expires(
        mut self,
        secs: u32,
        refresher: Option<crate::sip::headers::Refresher>,
    ) -> Self {
        self.session_expires = Some(crate::sip::headers::SessionExpires {
            delta_seconds: secs,
            refresher,
        });
        self
    }

    /// Set the `Min-SE` header (RFC 4028 §5).
    pub fn min_se(mut self, secs: u32) -> Self {
        self.min_se = Some(crate::sip::headers::MinSe(secs));
        self
    }

    /// Set the `RAck` header (RFC 3262 §7.2). Used on PRACK requests.
    pub fn rack(mut self, rseq: u32, cseq: u32, method: Method) -> Self {
        self.rack = Some(crate::sip::headers::RAck { rseq, cseq, method });
        self
    }

    /// Set the Allow header (RFC 3261 §20.5).
    pub fn allow(mut self, methods: &[Method]) -> Self {
        if methods.is_empty() {
            self.allow = None;
        } else {
            self.allow = Some(methods.to_vec());
        }
        self
    }

    /// Set the `Route` headers (RFC 3261 §12.2.1.1). One Route header is
    /// emitted per entry, in the order given. Each entry must be a complete
    /// Route header value (e.g. `<sip:proxy.example.com;lr>`). Empty slice
    /// clears any previously set routes. Calling again replaces the
    /// previous value.
    pub fn route(mut self, routes: &[String]) -> Self {
        if routes.is_empty() {
            self.routes = None;
        } else {
            self.routes = Some(routes.to_vec());
        }
        self
    }

    /// Append an arbitrary header by name and value.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.other_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Build the request.
    pub fn build(self) -> Result<SipRequest> {
        // Check for URI parsing errors first (more informative than "Missing URI")
        if let Some(err) = self.uri_error {
            return Err(SipError::InvalidHeader(err).into());
        }
        if let Some(err) = self.from_uri_error {
            return Err(SipError::InvalidHeader(err).into());
        }
        if let Some(err) = self.to_uri_error {
            return Err(SipError::InvalidHeader(err).into());
        }

        let method = self
            .method
            .ok_or_else(|| SipError::InvalidHeader("Missing method".to_string()))?;
        let uri = self
            .uri
            .ok_or_else(|| SipError::InvalidHeader("Missing request URI".to_string()))?;
        let from_uri = self
            .from_uri
            .ok_or_else(|| SipError::InvalidHeader("Missing From URI".to_string()))?;
        let from_tag = self
            .from_tag
            .ok_or_else(|| SipError::InvalidHeader("Missing From tag".to_string()))?;
        let to_uri = self
            .to_uri
            .ok_or_else(|| SipError::InvalidHeader("Missing To URI".to_string()))?;
        let call_id = self
            .call_id
            .ok_or_else(|| SipError::InvalidHeader("Missing Call-ID".to_string()))?;
        let cseq = self
            .cseq
            .ok_or_else(|| SipError::InvalidHeader("Missing CSeq".to_string()))?;
        let via_host = self
            .via_host
            .ok_or_else(|| SipError::InvalidHeader("Missing Via host".to_string()))?;
        let via_branch = self
            .via_branch
            .ok_or_else(|| SipError::InvalidHeader("Missing Via branch".to_string()))?;

        let mut headers = PHeaders::new();

        // Via header
        let via_port = self.via_port.unwrap_or(5060);
        let via_transport = self.via_transport.unwrap_or_else(|| "UDP".to_string());
        let via_str = format!(
            "SIP/2.0/{} {}:{};branch={}",
            via_transport, via_host, via_port, via_branch
        );
        headers
            .push(PHeader::Via(via_str))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // From header
        let from_str = if let Some(display) = &self.from_display {
            format!("\"{}\" <{}>;tag={}", display, from_uri, from_tag)
        } else {
            format!("<{}>;tag={}", from_uri, from_tag)
        };
        headers
            .push(PHeader::From(from_str))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // To header
        let to_str = if let Some(tag) = &self.to_tag {
            format!("<{}>;tag={}", to_uri, tag)
        } else {
            format!("<{}>", to_uri)
        };
        headers
            .push(PHeader::To(to_str))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // Call-ID header
        headers
            .push(PHeader::CallId(call_id))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // CSeq header — emit using the wrapper Display for the method
        // token (canonical uppercase, matches the previous behavior).
        let cseq_str = format!("{} {}", cseq, method_from_parser(method));
        headers
            .push(PHeader::CSeq(cseq_str))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // Max-Forwards
        let mf = self.max_forwards.unwrap_or(70);
        headers
            .push(PHeader::MaxForwards(mf.to_string()))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // Contact header
        if let Some(contact) = self.contact_uri {
            let contact_str = format!("<{}>", contact);
            headers
                .push(PHeader::Contact(contact_str))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Authorization header
        if let Some(auth) = self.authorization {
            headers
                .push(PHeader::Authorization(auth))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Proxy-Authorization header
        if let Some(auth) = self.proxy_authorization {
            headers
                .push(PHeader::ProxyAuthorization(auth))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Expires header
        if let Some(expires) = self.expires {
            headers
                .push(PHeader::Expires(expires.to_string()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Require header (RFC 3261 §20.32)
        if let Some(require) = self.require {
            headers
                .push(PHeader::Require(require.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Supported header (RFC 3261 §20.37)
        if let Some(supported) = self.supported {
            headers
                .push(PHeader::Supported(supported.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Session-Expires header (RFC 4028 §4)
        if let Some(se) = self.session_expires {
            headers
                .push(PHeader::Other(
                    "Session-Expires".to_string(),
                    se.to_header_value(),
                ))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Min-SE header (RFC 4028 §5)
        if let Some(m) = self.min_se {
            headers
                .push(PHeader::Other("Min-SE".to_string(), m.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // RAck header (RFC 3262 §7.2)
        if let Some(rack) = self.rack {
            headers
                .push(PHeader::Other("RAck".to_string(), rack.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Allow header (RFC 3261 §20.5)
        if let Some(methods) = &self.allow {
            let value = methods
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            headers
                .push(PHeader::Allow(value))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Route headers (RFC 3261 §12.2.1.1)
        if let Some(routes) = &self.routes {
            for r in routes {
                headers
                    .push(PHeader::Route(r.clone()))
                    .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
            }
        }

        // Arbitrary `Other` headers (e.g. Reason, RFC 3326).
        for (name, value) in &self.other_headers {
            headers
                .push(PHeader::Other(name.clone(), value.clone()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Content-Type and Content-Length
        let body = self.body.unwrap_or_default();
        if !body.is_empty() {
            if let Some(ct) = self.content_type {
                headers
                    .push(PHeader::ContentType(ct))
                    .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
            } else {
                cover_none_case();
            }
        }
        headers
            .push(PHeader::ContentLength(body.len().to_string()))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        let req = PRequest {
            method,
            uri: uri.to_string(),
            version: "SIP/2.0".to_string(),
            headers,
            body,
        };

        Ok(SipRequest { inner: req })
    }
}

/// Builder for SIP responses.
#[derive(Debug, Default)]
pub struct SipResponseBuilder {
    status_code: Option<u16>,
    reason: Option<String>,
    via: Vec<String>,
    from: Option<String>,
    to: Option<String>,
    call_id: Option<String>,
    cseq: Option<String>,
    contact_uri: Option<SipUri>,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) content_type: Option<String>,
    require: Option<crate::sip::headers::Require>,
    supported: Option<crate::sip::headers::Supported>,
    session_expires: Option<crate::sip::headers::SessionExpires>,
    min_se: Option<crate::sip::headers::MinSe>,
    rseq: Option<crate::sip::headers::RSeq>,
    allow: Option<Vec<Method>>,
}

impl SipResponseBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the status code and reason.
    pub fn status(mut self, code: u16, reason: &str) -> Self {
        self.status_code = Some(code);
        self.reason = Some(reason.to_string());
        self
    }

    /// Copy headers from a request (for building response to request).
    pub fn from_request(mut self, req: &SipRequest) -> Self {
        // Copy Via headers
        for header in req.inner.headers.iter() {
            if let PHeader::Via(v) = header {
                self.via.push(v.clone());
            }
        }

        // Copy From
        for header in req.inner.headers.iter() {
            if let PHeader::From(f) = header {
                self.from = Some(f.clone());
                break;
            }
        }

        // Copy To
        for header in req.inner.headers.iter() {
            if let PHeader::To(t) = header {
                self.to = Some(t.clone());
                break;
            }
        }

        // Copy Call-ID
        for header in req.inner.headers.iter() {
            if let PHeader::CallId(c) = header {
                self.call_id = Some(c.clone());
                break;
            }
        }

        // Copy CSeq — prefer the typed re-emit (canonical "<seq> <METHOD>")
        // when parseable, otherwise pass the raw value through verbatim
        // so the response continues to mirror what the request sent.
        for header in req.inner.headers.iter() {
            if let PHeader::CSeq(c) = header {
                if let (Ok(seq), Ok(method)) = (req.cseq(), req.cseq_method()) {
                    self.cseq = Some(format!("{} {}", seq, method));
                } else {
                    self.cseq = Some(c.clone());
                }
                break;
            }
        }

        self
    }

    /// Set the To tag.
    pub fn to_tag(mut self, tag: &str) -> Self {
        if let Some(ref mut to) = self.to {
            if !to.contains("tag=") {
                *to = format!("{};tag={}", to, tag);
            }
        } else {
            cover_none_case();
        }
        self
    }

    /// Set the Contact header.
    pub fn contact(mut self, uri: &str) -> Self {
        if let Ok(u) = SipUri::parse(uri) {
            self.contact_uri = Some(u);
        }
        self
    }

    /// Set the body.
    pub fn body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.body = Some(body);
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Set the `Require` header (RFC 3261 §20.32).
    pub fn require(mut self, tags: &[&str]) -> Self {
        if tags.is_empty() {
            self.require = None;
        } else {
            self.require = Some(crate::sip::headers::Require(
                tags.iter().map(|t| t.to_string()).collect(),
            ));
        }
        self
    }

    /// Set the `Supported` header (RFC 3261 §20.37).
    pub fn supported(mut self, tags: &[&str]) -> Self {
        if tags.is_empty() {
            self.supported = None;
        } else {
            self.supported = Some(crate::sip::headers::Supported(
                tags.iter().map(|t| t.to_string()).collect(),
            ));
        }
        self
    }

    /// Set the `Session-Expires` header (RFC 4028 §4).
    pub fn session_expires(
        mut self,
        secs: u32,
        refresher: Option<crate::sip::headers::Refresher>,
    ) -> Self {
        self.session_expires = Some(crate::sip::headers::SessionExpires {
            delta_seconds: secs,
            refresher,
        });
        self
    }

    /// Set the `Min-SE` header (RFC 4028 §5).
    pub fn min_se(mut self, secs: u32) -> Self {
        self.min_se = Some(crate::sip::headers::MinSe(secs));
        self
    }

    /// Set the `RSeq` header (RFC 3262 §7.1). Used on reliable provisionals.
    pub fn rseq(mut self, rseq: u32) -> Self {
        self.rseq = Some(crate::sip::headers::RSeq(rseq));
        self
    }

    /// Set the Allow header (RFC 3261 §20.5).
    pub fn allow(mut self, methods: &[Method]) -> Self {
        if methods.is_empty() {
            self.allow = None;
        } else {
            self.allow = Some(methods.to_vec());
        }
        self
    }

    /// Build the response.
    pub fn build(self) -> Result<SipResponse> {
        let status_code = self
            .status_code
            .ok_or_else(|| SipError::InvalidHeader("Missing status code".to_string()))?;

        let mut headers = PHeaders::new();

        // Via headers (in order)
        for via in &self.via {
            headers
                .push(PHeader::Via(via.clone()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // From header
        if let Some(from) = self.from {
            headers
                .push(PHeader::From(from))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // To header
        if let Some(to) = self.to {
            headers
                .push(PHeader::To(to))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Call-ID header
        if let Some(call_id) = self.call_id {
            headers
                .push(PHeader::CallId(call_id))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // CSeq header
        if let Some(cseq) = self.cseq {
            headers
                .push(PHeader::CSeq(cseq))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Contact header
        if let Some(contact) = self.contact_uri {
            let contact_str = format!("<{}>", contact);
            headers
                .push(PHeader::Contact(contact_str))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Require header (RFC 3261 §20.32)
        if let Some(require) = self.require {
            headers
                .push(PHeader::Require(require.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Supported header (RFC 3261 §20.37)
        if let Some(supported) = self.supported {
            headers
                .push(PHeader::Supported(supported.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Session-Expires header (RFC 4028 §4)
        if let Some(se) = self.session_expires {
            headers
                .push(PHeader::Other(
                    "Session-Expires".to_string(),
                    se.to_header_value(),
                ))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Min-SE header (RFC 4028 §5)
        if let Some(m) = self.min_se {
            headers
                .push(PHeader::Other("Min-SE".to_string(), m.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // RSeq header (RFC 3262 §7.1)
        if let Some(rseq) = self.rseq {
            headers
                .push(PHeader::Other("RSeq".to_string(), rseq.to_header_value()))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Allow header (RFC 3261 §20.5)
        if let Some(methods) = &self.allow {
            let value = methods
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            headers
                .push(PHeader::Allow(value))
                .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
        }

        // Content-Type and Content-Length
        let body = self.body.unwrap_or_default();
        if !body.is_empty() {
            if let Some(ct) = self.content_type {
                headers
                    .push(PHeader::ContentType(ct))
                    .map_err(|e| SipError::InvalidHeader(e.to_string()))?;
            } else {
                cover_none_case();
            }
        }
        headers
            .push(PHeader::ContentLength(body.len().to_string()))
            .map_err(|e| SipError::InvalidHeader(e.to_string()))?;

        // Reason phrase: prefer the explicit one set via `.status(code,
        // reason)`, otherwise derive from the canonical phrase table.
        let reason = self
            .reason
            .unwrap_or_else(|| PStatusCode::new(status_code).reason_phrase().to_string());

        let resp = PResponse {
            version: "SIP/2.0".to_string(),
            status_code: PStatusCode::new(status_code),
            reason,
            headers,
            body,
        };

        Ok(SipResponse { inner: resp })
    }
}

/// Generate a unique branch parameter for Via header.
pub fn generate_branch() -> String {
    format!("z9hG4bK{}", uuid::Uuid::new_v4().simple())
}

/// Generate a unique tag for From/To headers.
///
/// Uses 64 bits of OS-seeded randomness via `rand::thread_rng()` so that
/// rapid-fire calls cannot collide. The previous implementation derived the
/// tag purely from `SystemTime::now()`, which produced duplicates on
/// platforms where the wall-clock resolution was coarser than the time
/// between two adjacent calls (observed on macOS).
pub fn generate_tag() -> String {
    use rand::RngCore;
    format!("{:x}", rand::thread_rng().next_u64())
}

/// Generate a unique Call-ID.
pub fn generate_call_id(domain: &str) -> String {
    format!("{}@{}", uuid::Uuid::new_v4().simple(), domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE_MSG: &[u8] = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\
\r\n";

    const RESPONSE_MSG: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.0.2.4>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\
\r\n";

    fn replace_header(msg: &[u8], old: &str, new: &str) -> Vec<u8> {
        let msg_str = String::from_utf8_lossy(msg);
        msg_str.replace(old, new).into_bytes()
    }

    // SipMessage tests
    #[test]
    fn test_parse_invite() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(msg.is_request());

        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Invite);
        assert!(req.call_id().unwrap().contains("a84b4c76e66710"));
        assert_eq!(req.from_tag().unwrap(), "1928301774");
        assert!(req.to_tag().is_none());
        assert_eq!(req.via_branch().unwrap(), "z9hG4bK776asdhds");
        assert_eq!(req.cseq().unwrap(), 314159);
        assert_eq!(req.cseq_method().unwrap(), Method::Invite);
    }

    #[test]
    fn test_parse_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(msg.is_response());

        let resp = msg.as_response().unwrap();
        assert_eq!(resp.status_code(), 200);
        assert!(resp.is_success());
        assert!(!resp.is_provisional());
        assert!(!resp.is_failure());
        assert!(resp.call_id().unwrap().contains("a84b4c76e66710"));
        assert_eq!(resp.from_tag().unwrap(), "1928301774");
        assert_eq!(resp.to_tag(), Some("a6c85cf".to_string()));
        assert_eq!(resp.via_branch().unwrap(), "z9hG4bK776asdhds");
    }

    #[test]
    fn test_sip_message_parse_invalid() {
        let result = SipMessage::parse(b"invalid data");
        assert!(result.is_err());
    }

    #[test]
    fn test_sip_message_is_request_on_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(!msg.is_request());
    }

    #[test]
    fn test_sip_message_is_request_on_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(msg.is_request());
    }

    #[test]
    fn test_sip_message_is_response_on_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(!msg.is_response());
    }

    #[test]
    fn test_sip_message_is_response_on_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(msg.is_response());
    }

    #[test]
    fn test_sip_message_as_request_on_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(msg.as_request().is_none());
    }

    #[test]
    fn test_sip_message_as_response_on_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(msg.as_response().is_none());
    }

    #[test]
    fn test_sip_message_to_bytes_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.starts_with(b"INVITE"));
    }

    #[test]
    fn test_sip_message_to_bytes_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.starts_with(b"SIP/2.0"));
    }

    #[test]
    fn test_sip_message_clone() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let cloned = msg.clone();
        assert!(cloned.is_request());
    }

    // SipRequest tests
    #[test]
    fn test_request_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let uri = req.uri();
        assert!(uri.to_string().contains("bob@biloxi.com"));
    }

    #[test]
    fn test_request_from_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let uri = req.from_uri().unwrap();
        assert!(uri.to_string().contains("alice@atlanta.com"));
    }

    #[test]
    fn test_request_to_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let uri = req.to_uri().unwrap();
        assert!(uri.to_string().contains("bob@biloxi.com"));
    }

    #[test]
    fn test_request_contact_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let contact = req.contact_uri();
        assert!(contact.is_some());
    }

    #[test]
    fn test_request_body() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.body().is_empty());
    }

    #[test]
    fn test_request_content_type() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let ct = req.content_type();
        assert!(ct.is_some());
        assert!(ct.unwrap().contains("application/sdp"));
    }

    #[test]
    fn test_request_record_routes() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let routes = req.record_routes();
        // INVITE_MSG doesn't have Record-Route headers
        assert!(routes.is_empty());
    }

    #[test]
    fn test_request_via_headers_raw() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let vias = req.via_headers_raw();
        assert!(!vias.is_empty());
        assert!(vias[0].contains("pc33.atlanta.com"));
    }

    #[test]
    fn test_request_from_tag_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_from_tag_missing_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag().unwrap_err();
        assert!(err.to_string().contains("Missing required header"));
    }

    #[test]
    fn test_request_from_tag_and_uri_success() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let (tag, uri) = req.from_tag_and_uri().unwrap();
        assert_eq!(tag, "1928301774");
        assert_eq!(uri.to_string(), "sip:alice@atlanta.com");
    }

    #[test]
    fn test_request_from_tag_and_uri_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag_and_uri().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_from_tag_and_uri_missing_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag_and_uri().unwrap_err();
        assert!(err.to_string().contains("Missing required header"));
    }

    #[test]
    fn test_request_from_tag_and_uri_missing_tag() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: Alice <sip:alice@atlanta.com>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag_and_uri().unwrap_err();
        assert!(err.to_string().to_lowercase().contains("missing tag"));
    }

    #[test]
    fn test_request_from_uri_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_uri().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_to_uri_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "To: Bob <sip:bob@biloxi.com>\r\n",
            "To: <sip:bob@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.to_uri().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_via_branch_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n",
            "Via: invalid\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.via_branch().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    // SipResponse tests
    #[test]
    fn test_response_reason() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let reason = resp.reason();
        assert!(reason.contains("OK"));
    }

    #[test]
    fn test_response_is_provisional() {
        let provisional = b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(provisional).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_provisional());
        assert!(!resp.is_success());
        assert!(!resp.is_failure());
    }

    #[test]
    fn test_response_is_failure() {
        let failure = b"SIP/2.0 404 Not Found\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(failure).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_response_cseq() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert_eq!(resp.cseq().unwrap(), 314159);
    }

    #[test]
    fn test_response_cseq_method() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert_eq!(resp.cseq_method().unwrap(), Method::Invite);
    }

    #[test]
    fn test_response_from_tag_invalid_header() {
        let msg = replace_header(
            RESPONSE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.from_tag().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_from_tag_missing_header() {
        let msg = replace_header(
            RESPONSE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.from_tag().unwrap_err();
        assert!(err.to_string().contains("Missing required header"));
    }

    #[test]
    fn test_response_via_branch_invalid_header() {
        let msg = replace_header(
            RESPONSE_MSG,
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n",
            "Via: invalid\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.via_branch().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_cseq_invalid_header() {
        let msg = replace_header(RESPONSE_MSG, "CSeq: 314159 INVITE\r\n", "CSeq: invalid\r\n");
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.cseq().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_cseq_method_invalid_header() {
        let msg = replace_header(RESPONSE_MSG, "CSeq: 314159 INVITE\r\n", "CSeq: invalid\r\n");
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.cseq_method().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_contact_uri() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let contact = resp.contact_uri();
        assert!(contact.is_some());
    }

    #[test]
    fn test_response_body() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.body().is_empty());
    }

    #[test]
    fn test_response_content_type() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let ct = resp.content_type();
        assert!(ct.is_some());
    }

    #[test]
    fn test_response_record_routes() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let routes = resp.record_routes();
        assert!(routes.is_empty());
    }

    #[test]
    fn test_response_via_headers_raw() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let vias = resp.via_headers_raw();
        assert!(!vias.is_empty());
    }

    #[test]
    fn test_response_www_authenticate_none() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.www_authenticate().is_none());
    }

    #[test]
    fn test_response_proxy_authenticate_none() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.proxy_authenticate().is_none());
    }

    // Method tests
    #[test]
    fn test_method_display() {
        assert_eq!(format!("{}", Method::Invite), "INVITE");
        assert_eq!(format!("{}", Method::Ack), "ACK");
        assert_eq!(format!("{}", Method::Register), "REGISTER");
        assert_eq!(format!("{}", Method::Bye), "BYE");
        assert_eq!(format!("{}", Method::Cancel), "CANCEL");
        assert_eq!(format!("{}", Method::Options), "OPTIONS");
        assert_eq!(format!("{}", Method::Prack), "PRACK");
        assert_eq!(format!("{}", Method::Subscribe), "SUBSCRIBE");
        assert_eq!(format!("{}", Method::Notify), "NOTIFY");
        assert_eq!(format!("{}", Method::Publish), "PUBLISH");
        assert_eq!(format!("{}", Method::Info), "INFO");
        assert_eq!(format!("{}", Method::Refer), "REFER");
        assert_eq!(format!("{}", Method::Message), "MESSAGE");
        assert_eq!(format!("{}", Method::Update), "UPDATE");
    }

    #[test]
    fn test_method_creates_dialog() {
        assert!(Method::Invite.creates_dialog());
        assert!(Method::Subscribe.creates_dialog());
        assert!(!Method::Register.creates_dialog());
        assert!(!Method::Options.creates_dialog());
    }

    #[test]
    fn test_method_is_invite() {
        assert!(Method::Invite.is_invite());
        assert!(!Method::Register.is_invite());
        assert!(!Method::Bye.is_invite());
    }

    /// `Method::from_str` round-trips every method via its canonical
    /// uppercase token, case-insensitively. This is the wrapper-side
    /// counterpart of the parser-layer `Method::from_str` at
    /// RFC 3261 §7.1.
    #[test]
    fn test_method_from_str_round_trip() {
        use std::str::FromStr;
        const ALL: &[Method] = &[
            Method::Invite,
            Method::Ack,
            Method::Bye,
            Method::Cancel,
            Method::Register,
            Method::Options,
            Method::Prack,
            Method::Subscribe,
            Method::Notify,
            Method::Publish,
            Method::Info,
            Method::Refer,
            Method::Message,
            Method::Update,
        ];
        for m in ALL {
            let display = m.to_string();
            assert_eq!(Method::from_str(&display).unwrap(), *m);
            // Case-insensitive on parse.
            assert_eq!(Method::from_str(&display.to_lowercase()).unwrap(), *m);
        }
        // Unknown tokens fail.
        assert!(Method::from_str("BOGUS").is_err());
        assert!(Method::from_str("").is_err());
    }

    #[test]
    fn test_method_clone() {
        let m = Method::Invite;
        let cloned = m;
        assert_eq!(m, cloned);
    }

    #[test]
    fn test_method_debug() {
        let m = Method::Invite;
        let debug = format!("{:?}", m);
        assert!(debug.contains("Invite"));
    }

    // Builder tests
    #[test]
    fn test_build_request() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest123")
            .from("sip:alice@example.com", "fromtag1")
            .to("sip:bob@example.com")
            .call_id("testcall@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        assert_eq!(req.method(), Method::Invite);
        assert!(req.call_id().unwrap().contains("testcall"));
        assert_eq!(req.from_tag().unwrap(), "fromtag1");
        assert_eq!(req.cseq().unwrap(), 1);
    }

    #[test]
    fn test_build_request_with_display_name() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .from_display("Alice")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("\"Alice\""));
    }

    #[test]
    fn test_build_request_with_to_tag() {
        let req = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .to_tag("totag1")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("tag=totag1"));
    }

    #[test]
    fn test_build_request_with_body() {
        let sdp = b"v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\n".to_vec();
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .body(sdp.clone(), "application/sdp")
            .build()
            .unwrap();

        assert_eq!(req.body(), &sdp[..]);
    }

    #[test]
    fn test_build_request_with_authorization() {
        let req = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:alice@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .authorization("Digest username=\"alice\"")
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Authorization"));
    }

    #[test]
    fn test_build_request_with_proxy_authorization() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .proxy_authorization("Digest username=\"alice\"")
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Proxy-Authorization"));
    }

    #[test]
    fn test_build_request_with_expires() {
        let req = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:alice@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .expires(3600)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Expires"));
    }

    #[test]
    fn test_build_request_with_max_forwards() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .max_forwards(50)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Max-Forwards: 50"));
    }

    #[test]
    fn test_build_request_missing_method() {
        let result = SipRequest::builder()
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_uri() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_from() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_to() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_response() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag("totag123")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        assert_eq!(resp.status_code(), 200);
        assert!(resp.is_success());
        assert!(resp.call_id().unwrap().contains("a84b4c76e66710"));
        assert_eq!(resp.to_tag(), Some("totag123".to_string()));
    }

    #[test]
    fn test_build_response_with_body() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let sdp = b"v=0\r\n".to_vec();
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .body(sdp.clone(), "application/sdp")
            .build()
            .unwrap();

        assert_eq!(resp.body(), &sdp[..]);
    }

    #[test]
    fn test_build_response_body_without_content_type() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let mut builder = SipResponse::builder().status(200, "OK").from_request(req);
        builder.body = Some(b"payload".to_vec());
        builder.content_type = None;

        let resp = builder.build().unwrap();
        assert_eq!(resp.body(), b"payload");
        assert!(resp.content_type().is_none());
    }

    #[test]
    fn test_build_response_invalid_contact_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .contact("sip:alice@[::1")
            .build()
            .unwrap();

        assert!(resp.contact_uri().is_none());
    }

    #[test]
    fn test_build_response_valid_contact_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag("totag")
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        assert!(resp.contact_uri().is_some());
    }

    #[test]
    fn test_response_builder_from_request_invalid_via() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: invalid-via\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=tag1\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(raw).unwrap();
        let req = msg.as_request().unwrap();
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .build()
            .unwrap();

        // After M8 we probe the parser-side headers directly.
        let vias: Vec<String> = resp
            .inner
            .headers
            .iter()
            .filter_map(|h| {
                if let PHeader::Via(v) = h {
                    Some(v.clone())
                } else {
                    None
                }
            })
            .collect();
        assert!(vias.iter().any(|via| via.contains("invalid-via")));
    }

    #[test]
    fn test_response_builder_from_request_invalid_cseq() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=tag1\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: bad\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(raw).unwrap();
        let req = msg.as_request().unwrap();
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .build()
            .unwrap();

        let cseq = resp
            .inner
            .headers
            .iter()
            .find_map(|h| {
                if let PHeader::CSeq(cseq) = h {
                    Some(cseq.clone())
                } else {
                    None
                }
            })
            .unwrap();
        assert!(cseq.contains("bad"));
    }

    #[test]
    fn test_build_response_missing_status() {
        let result = SipResponse::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_response_to_tag_without_to_header() {
        let resp = SipResponse::builder()
            .status(200, "OK")
            .to_tag("tag1")
            .build()
            .unwrap();

        assert!(resp.to_tag().is_none());
    }

    #[test]
    fn test_build_response_to_tag_already_present() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        // First add a to_tag, then try to add another
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag("first_tag")
            .to_tag("second_tag") // Should not add another tag
            .build()
            .unwrap();

        let to_tag = resp.to_tag();
        assert!(to_tag.is_some());
    }

    #[test]
    fn test_build_response_to_tag_added_when_missing() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(req)
            .to_tag("newtag")
            .build()
            .unwrap();

        assert_eq!(resp.to_tag(), Some("newtag".to_string()));
    }

    #[test]
    fn test_roundtrip() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let bytes = msg.to_bytes();
        let msg2 = SipMessage::parse(&bytes).unwrap();

        let req1 = msg.as_request().unwrap();
        let req2 = msg2.as_request().unwrap();

        assert_eq!(req1.method(), req2.method());
        assert_eq!(req1.call_id().unwrap(), req2.call_id().unwrap());
    }

    // Helper function tests
    #[test]
    fn test_generate_branch() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        assert!(branch.len() > 10);
    }

    #[test]
    fn test_generate_branch_unique() {
        let branch1 = generate_branch();
        let branch2 = generate_branch();
        assert_ne!(branch1, branch2);
    }

    #[test]
    fn test_generate_tag() {
        let tag = generate_tag();
        assert!(!tag.is_empty());
    }

    #[test]
    fn test_generate_tag_unique() {
        let tag1 = generate_tag();
        let tag2 = generate_tag();
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_generate_call_id() {
        let call_id = generate_call_id("example.com");
        assert!(call_id.ends_with("@example.com"));
    }

    #[test]
    fn test_generate_call_id_unique() {
        let call_id1 = generate_call_id("example.com");
        let call_id2 = generate_call_id("example.com");
        assert_ne!(call_id1, call_id2);
    }

    #[test]
    fn test_request_builder_default() {
        let builder = SipRequestBuilder::default();
        let debug = format!("{:?}", builder);
        assert!(debug.contains("SipRequestBuilder"));
    }

    #[test]
    fn test_request_builder_missing_from_tag() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com");
        builder.from_uri = Some(SipUri::parse("sip:alice@example.com").unwrap());
        let err = builder.build().unwrap_err();
        assert!(format!("{err:?}").contains("InvalidHeader"));
    }

    #[test]
    fn test_request_builder_missing_via_branch() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag123")
            .to("sip:bob@example.com")
            .call_id("call-id")
            .cseq(1);
        builder.via_host = Some("example.com".to_string());
        builder.via_port = Some(5060);
        builder.via_transport = Some("UDP".to_string());
        let err = builder.build().unwrap_err();
        assert!(format!("{err:?}").contains("InvalidHeader"));
    }

    #[test]
    fn test_request_builder_default_via_transport() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag123")
            .to("sip:bob@example.com")
            .call_id("call-id")
            .cseq(1);
        builder.via_host = Some("example.com".to_string());
        builder.via_port = Some(5060);
        builder.via_branch = Some("z9hG4bKtest".to_string());
        let request = builder.build().unwrap();
        let bytes = request.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("SIP/2.0/UDP example.com:5060;branch=z9hG4bKtest"));
    }

    #[test]
    fn test_response_builder_default() {
        let builder = SipResponseBuilder::default();
        let debug = format!("{:?}", builder);
        assert!(debug.contains("SipResponseBuilder"));
    }

    // Display trait tests for SipMessage, SipRequest, and SipResponse
    #[test]
    fn test_sip_message_debug_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let debug = format!("{:?}", msg);
        assert!(debug.contains("Request"));
    }

    #[test]
    fn test_sip_message_debug_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let debug = format!("{:?}", msg);
        assert!(debug.contains("Response"));
    }

    #[test]
    fn test_sip_request_debug() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let debug = format!("{:?}", req);
        assert!(debug.contains("SipRequest"));
    }

    #[test]
    fn test_sip_request_clone() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let cloned = req.clone();
        assert_eq!(cloned.method(), req.method());
        assert_eq!(cloned.call_id().unwrap(), req.call_id().unwrap());
    }

    #[test]
    fn test_sip_response_debug() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let debug = format!("{:?}", resp);
        assert!(debug.contains("SipResponse"));
    }

    #[test]
    fn test_sip_response_clone() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.status_code(), resp.status_code());
        assert_eq!(cloned.call_id().unwrap(), resp.call_id().unwrap());
    }

    // Edge case tests for message parsing
    #[test]
    fn test_parse_request_missing_call_id() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.call_id().is_err());
    }

    #[test]
    fn test_parse_request_missing_from() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.from_tag().is_err());
        assert!(req.from_uri().is_err());
    }

    #[test]
    fn test_parse_request_missing_to() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.to_uri().is_err());
    }

    #[test]
    fn test_parse_request_missing_via() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.via_branch().is_err());
    }

    #[test]
    fn test_parse_request_missing_cseq() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.cseq().is_err());
        assert!(req.cseq_method().is_err());
    }

    #[test]
    fn test_parse_request_from_missing_tag() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.from_tag().is_err());
    }

    #[test]
    fn test_parse_request_via_missing_branch() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.via_branch().is_err());
    }

    #[test]
    fn test_parse_request_no_contact() {
        let msg_no_contact = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_no_contact).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.contact_uri().is_none());
    }

    #[test]
    fn test_parse_request_no_content_type() {
        let msg_no_ct = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_no_ct).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.content_type().is_none());
    }

    #[test]
    fn test_parse_request_with_record_route() {
        let msg_with_rr = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
Record-Route: <sip:proxy2.example.com;lr>\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_with_rr).unwrap();
        let req = msg.as_request().unwrap();
        let routes = req.record_routes();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("proxy1.example.com"));
        assert!(routes[1].contains("proxy2.example.com"));
    }

    #[test]
    fn test_parse_request_multiple_via_headers() {
        let msg_multi_via = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bKproxy1\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_multi_via).unwrap();
        let req = msg.as_request().unwrap();
        let vias = req.via_headers_raw();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].contains("proxy1.example.com"));
        assert!(vias[1].contains("pc33.atlanta.com"));
    }

    #[test]
    fn test_parse_request_with_body() {
        let msg_with_body = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 9\r\n\
\r\n\
v=0\r\ntest";
        let msg = SipMessage::parse(msg_with_body).unwrap();
        let req = msg.as_request().unwrap();
        assert!(!req.body().is_empty());
    }

    // Response error handling tests
    #[test]
    fn test_parse_response_missing_call_id() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.call_id().is_err());
    }

    #[test]
    fn test_parse_response_missing_from() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.from_tag().is_err());
    }

    #[test]
    fn test_parse_response_missing_via() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.via_branch().is_err());
    }

    #[test]
    fn test_parse_response_missing_cseq() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.cseq().is_err());
        assert!(resp.cseq_method().is_err());
    }

    #[test]
    fn test_parse_response_from_missing_tag() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.from_tag().is_err());
    }

    #[test]
    fn test_parse_response_via_missing_branch() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.via_branch().is_err());
    }

    #[test]
    fn test_parse_response_no_to_tag() {
        let resp_no_tag = b"SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_no_tag).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.to_tag().is_none());
    }

    #[test]
    fn test_parse_response_no_contact() {
        let resp_no_contact = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_no_contact).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.contact_uri().is_none());
    }

    #[test]
    fn test_parse_response_with_www_authenticate() {
        let resp_with_auth = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\"\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_auth).unwrap();
        let resp = msg.as_response().unwrap();
        let auth = resp.www_authenticate();
        assert!(auth.is_some());
        let auth_str = auth.unwrap();
        assert!(auth_str.contains("Digest"));
        assert!(auth_str.contains("example.com"));
    }

    #[test]
    fn test_parse_response_with_security_server() {
        let resp_with_security = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"ims.example.com\", nonce=\"abc123\", algorithm=AKAv1-MD5\r\n\
Security-Server: ipsec-3gpp;q=0.1;alg=hmac-sha-1-96;spi-c=1111;spi-s=2222;port-c=3333;port-s=4444\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_security).unwrap();
        let resp = msg.as_response().unwrap();
        let security_server = resp.security_server();
        assert!(security_server.is_some());
        let value = security_server.unwrap();
        assert!(value.contains("ipsec-3gpp"));
        assert!(value.contains("spi-c=1111"));
        assert!(value.contains("spi-s=2222"));
    }

    #[test]
    fn test_response_security_server_none() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.security_server().is_none());
    }

    #[test]
    fn test_parse_response_with_proxy_authenticate() {
        let resp_with_auth = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Proxy-Authenticate: Digest realm=\"proxy.example.com\", nonce=\"def456\"\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_auth).unwrap();
        let resp = msg.as_response().unwrap();
        let auth = resp.proxy_authenticate();
        assert!(auth.is_some());
        let auth_str = auth.unwrap();
        assert!(auth_str.contains("Digest"));
        assert!(auth_str.contains("proxy.example.com"));
    }

    #[test]
    fn test_parse_response_with_record_route() {
        let resp_with_rr = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_rr).unwrap();
        let resp = msg.as_response().unwrap();
        let routes = resp.record_routes();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].contains("proxy1.example.com"));
    }

    #[test]
    fn test_parse_response_multiple_via_headers() {
        let resp_multi_via = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bKproxy1\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_multi_via).unwrap();
        let resp = msg.as_response().unwrap();
        let vias = resp.via_headers_raw();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].contains("proxy1.example.com"));
    }

    #[test]
    fn test_parse_response_3xx_is_failure() {
        let redirect = b"SIP/2.0 302 Moved Temporarily\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(redirect).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_parse_response_5xx_is_failure() {
        let server_error = b"SIP/2.0 500 Server Internal Error\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(server_error).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_parse_response_6xx_is_failure() {
        let global_failure = b"SIP/2.0 603 Decline\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(global_failure).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_response_reason_edge_case() {
        // Multi-word reason phrases survive the split — we read what was
        // on the wire when present.
        let resp_long_reason = b"SIP/2.0 488 Not Acceptable Here\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_long_reason).unwrap();
        let resp = msg.as_response().unwrap();
        assert_eq!(resp.status_code(), 488);
        let reason = resp.reason();
        assert!(!reason.is_empty());
    }

    // Builder edge cases and error paths
    #[test]
    fn test_build_request_with_empty_body() {
        // Test request with empty body doesn't add Content-Type
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .body(vec![], "application/sdp")
            .build()
            .unwrap();

        // Empty body should not have content type added
        let bytes = req.to_bytes();
        let msg_str = String::from_utf8_lossy(&bytes);
        // Content-Length should still be present
        assert!(msg_str.contains("Content-Length: 0"));
    }

    #[test]
    fn test_build_request_with_non_empty_body() {
        // Test request with body adds Content-Type
        let body_data = b"test body".to_vec();
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .body(body_data.clone(), "application/test")
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let msg_str = String::from_utf8_lossy(&bytes);
        assert!(msg_str.contains("Content-Type: application/test"));
        assert!(msg_str.contains("Content-Length: 9"));
    }

    #[test]
    fn test_build_request_builder_new() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        assert_eq!(req.method(), Method::Invite);
    }

    #[test]
    fn test_build_request_missing_via_host() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_call_id() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_cseq() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_from_tag() {
        // Using empty string for tag
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        // Should succeed even with empty tag (though not recommended)
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_request_invalid_contact_uri() {
        // Contact URI parsing failure should be silently ignored
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .contact("sip:alice@[::1")
            .build()
            .unwrap();

        // Invalid contact URIs are silently ignored by the builder
        assert!(req.contact_uri().is_none());
    }

    #[test]
    fn test_build_request_valid_contact_uri() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        assert!(req.contact_uri().is_some());
    }

    #[test]
    fn test_build_request_invalid_uri_error() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("<>invalid<>")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_invalid_from_uri_error() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("<>invalid<>", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_invalid_to_uri_error() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag1")
            .to("<>invalid<>")
            .call_id("call@example.com")
            .cseq(1)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_invalid_uri_error_with_required_headers() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@[::1")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid request URI"));
    }

    #[test]
    fn test_build_request_invalid_from_uri_error_with_required_headers() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@[::1", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid From URI"));
    }

    #[test]
    fn test_build_request_invalid_to_uri_error_with_required_headers() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:alice@[::1")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid To URI"));
    }

    #[test]
    fn test_build_request_body_without_content_type() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1);

        builder.body = Some(b"payload".to_vec());
        builder.content_type = None;

        let req = builder.build().unwrap();
        assert_eq!(req.body(), b"payload");
        assert!(req.content_type().is_none());
    }

    #[test]
    fn test_build_request_default_via_port() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("192.168.1.1:5060"));
    }

    #[test]
    fn test_build_request_default_max_forwards() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Max-Forwards: 70"));
    }

    #[test]
    fn test_build_response_empty_via() {
        let resp = SipResponse::builder().status(200, "OK").build().unwrap();
        let vias = resp.via_headers_raw();
        assert!(vias.is_empty());
    }

    // Test different SIP methods
    #[test]
    fn test_parse_register_request() {
        let register = b"REGISTER sip:registrar.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Alice <sip:alice@atlanta.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 REGISTER\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(register).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Register);
        assert_eq!(req.cseq_method().unwrap(), Method::Register);
    }

    #[test]
    fn test_parse_bye_request() {
        let bye = b"BYE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314160 BYE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(bye).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Bye);
        assert_eq!(req.cseq_method().unwrap(), Method::Bye);
    }

    #[test]
    fn test_parse_cancel_request() {
        let cancel = b"CANCEL sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(cancel).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Cancel);
        assert_eq!(req.cseq_method().unwrap(), Method::Cancel);
    }

    #[test]
    fn test_parse_options_request() {
        let options = b"OPTIONS sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(options).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Options);
        assert!(!req.method().creates_dialog());
    }

    #[test]
    fn test_parse_subscribe_request() {
        let subscribe = b"SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 SUBSCRIBE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(subscribe).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Subscribe);
        assert!(req.method().creates_dialog());
    }

    #[test]
    fn test_parse_notify_request() {
        let notify = b"NOTIFY sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 NOTIFY\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(notify).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Notify);
    }

    #[test]
    fn test_parse_ack_request() {
        let ack = b"ACK sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 ACK\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(ack).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Ack);
    }

    // -------------------------------------------------------------------
    // Phase 1 header accessors / builders (Require, Supported,
    // Session-Expires, Min-SE, RSeq, RAck).
    // -------------------------------------------------------------------

    use crate::sip::headers::{MinSe, RSeq, Refresher};

    /// Build a minimal valid INVITE with the listed extra headers and
    /// round-trip it through wire-format to exercise the parser path on
    /// the reader side. Returns the parsed `SipRequest`.
    fn invite_with_headers(extra_headers: &str) -> SipRequest {
        let msg = format!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
{}\
Content-Length: 0\r\n\
\r\n",
            extra_headers
        );
        let parsed = SipMessage::parse(msg.as_bytes()).unwrap();
        match parsed {
            SipMessage::Request(r) => r,
            _ => panic!("expected request"),
        }
    }

    fn response_with_headers(extra_headers: &str) -> SipResponse {
        let msg = format!(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
{}\
Content-Length: 0\r\n\
\r\n",
            extra_headers
        );
        let parsed = SipMessage::parse(msg.as_bytes()).unwrap();
        match parsed {
            SipMessage::Response(r) => r,
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn test_request_require_accessor() {
        let req = invite_with_headers("Require: 100rel\r\n");
        let r = req.require().expect("require should be present");
        assert_eq!(r.0, vec!["100rel".to_string()]);
    }

    #[test]
    fn test_request_supported_accessor() {
        let req = invite_with_headers("Supported: timer, 100rel\r\n");
        let s = req.supported().expect("supported should be present");
        assert_eq!(s.0, vec!["timer".to_string(), "100rel".to_string()]);
    }

    #[test]
    fn test_request_session_expires_accessor() {
        let req = invite_with_headers("Session-Expires: 1800;refresher=uac\r\n");
        let se = req.session_expires().expect("session-expires");
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uac));
    }

    #[test]
    fn test_request_min_se_accessor() {
        let req = invite_with_headers("Min-SE: 90\r\n");
        assert_eq!(req.min_se(), Some(MinSe(90)));
    }

    #[test]
    fn test_request_rack_accessor() {
        let req = invite_with_headers("RAck: 1 314159 INVITE\r\n");
        let rack = req.rack().expect("rack");
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 314159);
        assert_eq!(rack.method, Method::Invite);
    }

    #[test]
    fn test_request_accessors_absent_returns_none() {
        let req = invite_with_headers("");
        assert!(req.require().is_none());
        assert!(req.supported().is_none());
        assert!(req.session_expires().is_none());
        assert!(req.min_se().is_none());
        assert!(req.rack().is_none());
    }

    #[test]
    fn test_request_session_expires_malformed_is_none() {
        let req = invite_with_headers("Session-Expires: notanumber\r\n");
        assert!(req.session_expires().is_none());
    }

    #[test]
    fn test_request_min_se_malformed_is_none() {
        let req = invite_with_headers("Min-SE: bogus\r\n");
        assert!(req.min_se().is_none());
    }

    #[test]
    fn test_request_rack_malformed_is_none() {
        let req = invite_with_headers("RAck: 1 INVITE\r\n");
        assert!(req.rack().is_none());
    }

    #[test]
    fn test_response_require_accessor() {
        let resp = response_with_headers("Require: 100rel\r\n");
        let r = resp.require().expect("require");
        assert_eq!(r.0, vec!["100rel".to_string()]);
    }

    #[test]
    fn test_response_supported_accessor() {
        let resp = response_with_headers("Supported: timer\r\n");
        let s = resp.supported().expect("supported");
        assert_eq!(s.0, vec!["timer".to_string()]);
    }

    #[test]
    fn test_response_session_expires_accessor() {
        let resp = response_with_headers("Session-Expires: 600;refresher=uas\r\n");
        let se = resp.session_expires().expect("session-expires");
        assert_eq!(se.delta_seconds, 600);
        assert_eq!(se.refresher, Some(Refresher::Uas));
    }

    #[test]
    fn test_response_min_se_accessor() {
        let resp = response_with_headers("Min-SE: 1800\r\n");
        assert_eq!(resp.min_se(), Some(MinSe(1800)));
    }

    #[test]
    fn test_response_rseq_accessor() {
        let resp = response_with_headers("RSeq: 42\r\n");
        assert_eq!(resp.rseq(), Some(RSeq(42)));
    }

    #[test]
    fn test_response_accessors_absent_returns_none() {
        let resp = response_with_headers("");
        assert!(resp.require().is_none());
        assert!(resp.supported().is_none());
        assert!(resp.session_expires().is_none());
        assert!(resp.min_se().is_none());
        assert!(resp.rseq().is_none());
    }

    #[test]
    fn test_response_rseq_malformed_is_none() {
        let resp = response_with_headers("RSeq: NaN\r\n");
        assert!(resp.rseq().is_none());
    }

    #[test]
    fn test_request_builder_emits_require() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@biloxi.com")
            .via("pc33.atlanta.com", 5060, "UDP", "z9hG4bKxyz")
            .from("sip:alice@atlanta.com", "1928301774")
            .to("sip:bob@biloxi.com")
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(1)
            .require(&["100rel"])
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let reparsed = SipMessage::parse(&bytes).unwrap();
        let req2 = reparsed.as_request().unwrap();
        assert_eq!(req2.require().unwrap().0, vec!["100rel".to_string()]);
    }

    #[test]
    fn test_request_builder_emits_supported_session_expires_min_se() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@biloxi.com")
            .via("pc33.atlanta.com", 5060, "UDP", "z9hG4bKxyz")
            .from("sip:alice@atlanta.com", "1928301774")
            .to("sip:bob@biloxi.com")
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(1)
            .supported(&["timer", "100rel"])
            .session_expires(1800, Some(Refresher::Uac))
            .min_se(90)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(wire.contains("Supported: timer, 100rel"));
        assert!(wire.contains("Session-Expires: 1800;refresher=uac"));
        assert!(wire.contains("Min-SE: 90"));

        let reparsed = SipMessage::parse(&bytes).unwrap();
        let req2 = reparsed.as_request().unwrap();
        let sup = req2.supported().unwrap();
        assert_eq!(sup.0, vec!["timer".to_string(), "100rel".to_string()]);
        let se = req2.session_expires().unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uac));
        assert_eq!(req2.min_se().unwrap(), MinSe(90));
    }

    #[test]
    fn test_request_builder_emits_rack() {
        let req = SipRequest::builder()
            .method(Method::Prack)
            .uri("sip:bob@biloxi.com")
            .via("pc33.atlanta.com", 5060, "UDP", "z9hG4bKxyz")
            .from("sip:alice@atlanta.com", "1928301774")
            .to("sip:bob@biloxi.com")
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(2)
            .rack(1, 314159, Method::Invite)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(wire.contains("RAck: 1 314159 INVITE"));

        let reparsed = SipMessage::parse(&bytes).unwrap();
        let req2 = reparsed.as_request().unwrap();
        let rack = req2.rack().unwrap();
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 314159);
        assert_eq!(rack.method, Method::Invite);
    }

    #[test]
    fn test_request_builder_empty_tag_lists_clear_headers() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@biloxi.com")
            .via("pc33.atlanta.com", 5060, "UDP", "z9hG4bKxyz")
            .from("sip:alice@atlanta.com", "1928301774")
            .to("sip:bob@biloxi.com")
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(1)
            .require(&["100rel"])
            .require(&[])
            .supported(&["timer"])
            .supported(&[])
            .build()
            .unwrap();
        assert!(req.require().is_none());
        assert!(req.supported().is_none());
    }

    #[test]
    fn test_response_builder_round_trip() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@biloxi.com")
            .via("pc33.atlanta.com", 5060, "UDP", "z9hG4bKxyz")
            .from("sip:alice@atlanta.com", "1928301774")
            .to("sip:bob@biloxi.com")
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(1)
            .build()
            .unwrap();

        let resp = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&req)
            .require(&["100rel"])
            .supported(&["timer"])
            .session_expires(1800, Some(Refresher::Uas))
            .min_se(90)
            .rseq(1)
            .build()
            .unwrap();

        let bytes = resp.to_bytes();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(wire.contains("Require: 100rel"));
        assert!(wire.contains("Supported: timer"));
        assert!(wire.contains("Session-Expires: 1800;refresher=uas"));
        assert!(wire.contains("Min-SE: 90"));
        assert!(wire.contains("RSeq: 1"));

        let reparsed = SipMessage::parse(&bytes).unwrap();
        let resp2 = reparsed.as_response().unwrap();
        assert_eq!(resp2.require().unwrap().0, vec!["100rel".to_string()]);
        assert_eq!(resp2.supported().unwrap().0, vec!["timer".to_string()]);
        let se = resp2.session_expires().unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uas));
        assert_eq!(resp2.min_se().unwrap(), MinSe(90));
        assert_eq!(resp2.rseq().unwrap(), RSeq(1));
    }

    #[test]
    fn test_response_builder_session_expires_no_refresher() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@biloxi.com")
            .via("pc33.atlanta.com", 5060, "UDP", "z9hG4bKxyz")
            .from("sip:alice@atlanta.com", "1928301774")
            .to("sip:bob@biloxi.com")
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(1)
            .build()
            .unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(&req)
            .session_expires(600, None)
            .build()
            .unwrap();

        let bytes = resp.to_bytes();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(wire.contains("Session-Expires: 600\r\n"));

        let reparsed = SipMessage::parse(&bytes).unwrap();
        let resp2 = reparsed.as_response().unwrap();
        let se = resp2.session_expires().unwrap();
        assert_eq!(se.delta_seconds, 600);
        assert!(se.refresher.is_none());
    }

    #[test]
    fn test_request_require_via_header_other() {
        // The accessor must tolerate `Header::Other("Require", ...)` —
        // for instance when manually constructed or arriving via an
        // unrecognized typed channel. After M8 we construct against
        // the parser-side `PHeader`/`PHeaders` directly.
        let mut headers = PHeaders::new();
        headers
            .push(PHeader::Via(
                "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK1".to_string(),
            ))
            .unwrap();
        headers
            .push(PHeader::From("<sip:alice@atlanta.com>;tag=1".to_string()))
            .unwrap();
        headers
            .push(PHeader::To("<sip:bob@biloxi.com>".to_string()))
            .unwrap();
        headers.push(PHeader::CallId("c1".to_string())).unwrap();
        headers.push(PHeader::CSeq("1 INVITE".to_string())).unwrap();
        headers
            .push(PHeader::Other("require".to_string(), "100rel".to_string()))
            .unwrap();
        headers
            .push(PHeader::ContentLength("0".to_string()))
            .unwrap();
        let req = SipRequest {
            inner: PRequest {
                method: PMethod::Invite,
                uri: "sip:bob@biloxi.com".to_string(),
                version: "SIP/2.0".to_string(),
                headers,
                body: vec![],
            },
        };
        let r = req.require().expect("should still find via Header::Other");
        assert_eq!(r.0, vec!["100rel".to_string()]);
    }

    #[test]
    fn test_request_require_merges_multiple_lines() {
        let req = invite_with_headers("Require: 100rel\r\nRequire: timer\r\n");
        let r = req.require().expect("require should be present");
        assert_eq!(r.0, vec!["100rel".to_string(), "timer".to_string()]);
    }

    #[test]
    fn test_request_supported_merges_multiple_lines() {
        let req = invite_with_headers("Supported: timer\r\nSupported: 100rel\r\n");
        let s = req.supported().expect("supported should be present");
        assert_eq!(s.0, vec!["timer".to_string(), "100rel".to_string()]);
    }

    #[test]
    fn test_request_session_expires_compact_form_x() {
        // RFC 4028 §4 ABNF defines `x` as the compact form of
        // `Session-Expires`. Some Cisco/Sonus stacks emit this. Accessor
        // must fall back to `x` when `Session-Expires` is absent.
        let mut headers = PHeaders::new();
        headers
            .push(PHeader::Via(
                "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK1".to_string(),
            ))
            .unwrap();
        headers
            .push(PHeader::From("<sip:alice@atlanta.com>;tag=1".to_string()))
            .unwrap();
        headers
            .push(PHeader::To("<sip:bob@biloxi.com>".to_string()))
            .unwrap();
        headers.push(PHeader::CallId("c1".to_string())).unwrap();
        headers.push(PHeader::CSeq("1 INVITE".to_string())).unwrap();
        headers
            .push(PHeader::Other(
                "x".to_string(),
                "1800;refresher=uac".to_string(),
            ))
            .unwrap();
        headers
            .push(PHeader::ContentLength("0".to_string()))
            .unwrap();
        let req = SipRequest {
            inner: PRequest {
                method: PMethod::Invite,
                uri: "sip:bob@biloxi.com".to_string(),
                version: "SIP/2.0".to_string(),
                headers,
                body: vec![],
            },
        };
        let se = req
            .session_expires()
            .expect("compact form `x` should be recognized");
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(crate::sip::headers::Refresher::Uac));
    }

    #[test]
    fn test_response_session_expires_compact_form_x() {
        let mut headers = PHeaders::new();
        headers
            .push(PHeader::Via(
                "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK1".to_string(),
            ))
            .unwrap();
        headers
            .push(PHeader::From("<sip:alice@atlanta.com>;tag=1".to_string()))
            .unwrap();
        headers
            .push(PHeader::To("<sip:bob@biloxi.com>;tag=2".to_string()))
            .unwrap();
        headers.push(PHeader::CallId("c1".to_string())).unwrap();
        headers.push(PHeader::CSeq("1 INVITE".to_string())).unwrap();
        headers
            .push(PHeader::Other(
                "x".to_string(),
                "600;refresher=uas".to_string(),
            ))
            .unwrap();
        headers
            .push(PHeader::ContentLength("0".to_string()))
            .unwrap();
        let resp = SipResponse {
            inner: PResponse {
                version: "SIP/2.0".to_string(),
                status_code: PStatusCode::OK,
                reason: "OK".to_string(),
                headers,
                body: vec![],
            },
        };
        let se = resp
            .session_expires()
            .expect("compact form `x` should be recognized");
        assert_eq!(se.delta_seconds, 600);
        assert_eq!(se.refresher, Some(crate::sip::headers::Refresher::Uas));
    }

    /// Round-trip Allow through the request builder, the wire, and back
    /// through the parser.
    #[test]
    fn test_request_builder_allow_round_trip() {
        let req = SipRequest::builder()
            .method(Method::Update)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("c1@example.com")
            .cseq(2)
            .allow(&[
                Method::Invite,
                Method::Ack,
                Method::Bye,
                Method::Cancel,
                Method::Options,
                Method::Prack,
                Method::Update,
            ])
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let parsed = SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let allow = parsed_req.allow().expect("Allow must round-trip");
        assert_eq!(
            allow,
            vec![
                Method::Invite,
                Method::Ack,
                Method::Bye,
                Method::Cancel,
                Method::Options,
                Method::Prack,
                Method::Update,
            ]
        );

        // Empty slice clears the header.
        let req2 = SipRequest::builder()
            .method(Method::Update)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("c1@example.com")
            .cseq(2)
            .allow(&[Method::Invite])
            .allow(&[])
            .build()
            .unwrap();
        assert!(req2.allow().is_none(), "empty slice clears Allow");
    }

    /// Mirror for SipResponse. Also exercises the read side with unknown
    /// method tokens — they must be skipped silently rather than failing.
    #[test]
    fn test_response_builder_allow_round_trip_skips_unknown() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("c1@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(&req)
            .to_tag("totag")
            .allow(&[Method::Invite, Method::Bye, Method::Update])
            .build()
            .unwrap();

        let bytes = resp.to_bytes();
        let parsed = SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();

        let allow = parsed_resp.allow().expect("Allow must round-trip");
        assert_eq!(allow, vec![Method::Invite, Method::Bye, Method::Update]);

        // Inject an unknown method token alongside known ones — the parser
        // must skip the unknown rather than fail the whole header.
        let mut resp2 = resp.clone();
        resp2
            .inner_mut()
            .headers
            .push(PHeader::Other(
                "Allow".to_string(),
                "FOO, OPTIONS".to_string(),
            ))
            .unwrap();
        let allow2 = resp2.allow().expect("still parseable with one unknown");
        assert_eq!(
            allow2,
            vec![Method::Invite, Method::Bye, Method::Update, Method::Options],
        );
    }
}

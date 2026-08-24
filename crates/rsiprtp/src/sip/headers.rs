//! SIP header types and utilities.
//!
//! This module provides typed wrappers for common SIP headers,
//! making it easier to extract and manipulate header values.

use crate::core::SipError;
use crate::sip::message::Method;
use crate::sip::uri::SipUri;
use std::fmt;

/// Typed wrapper for Via header (RFC 3261 Section 20.42).
#[derive(Debug, Clone, PartialEq)]
pub struct Via {
    /// Transport protocol (e.g., "UDP", "TCP", "TLS").
    pub protocol: String,
    /// Host address.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Branch parameter (transaction identifier).
    pub branch: String,
    /// Received parameter (actual source IP).
    pub received: Option<String>,
    /// rport parameter (actual source port).
    pub rport: Option<u16>,
}

impl Via {
    /// Parse a Via header value string.
    ///
    /// Format: `SIP/2.0/UDP host:port;branch=xxx[;received=ip][;rport=port]`
    pub fn parse(value: &str) -> Result<Self, SipError> {
        // Parse format: "SIP/2.0/UDP host:port;params"
        let value = value.trim();

        // Split protocol and the rest
        let parts: Vec<&str> = value.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return Err(SipError::Parse("Invalid Via header format".to_string()));
        }

        // Parse protocol (e.g., "SIP/2.0/UDP")
        let protocol_parts: Vec<&str> = parts[0].split('/').collect();
        let protocol = protocol_parts.last().unwrap_or(&"");
        if protocol.is_empty() {
            return Err(SipError::Parse("Missing transport protocol".to_string()));
        }
        let protocol = protocol.to_string();

        // Parse host:port and parameters
        let rest = parts[1];
        let (host_port, params) = if let Some(idx) = rest.find(';') {
            (&rest[..idx], Some(&rest[idx + 1..]))
        } else {
            (rest, None)
        };

        // Parse host and port.
        // IPv6 references are bracketed per RFC 3261 §25.1:
        //   `sent-by = host [ COLON port ]`
        //   `host    = hostname / IPv4address / IPv6reference`
        //   `IPv6reference = "[" IPv6address "]"`
        // For `[2001:db8::1]:5060`, the port separator is the colon
        // AFTER the closing bracket, not the last colon in the string.
        let host_port = host_port.trim();
        let (host, port) = if host_port.starts_with('[') {
            // IPv6 reference — find the closing bracket.
            if let Some(close) = host_port.find(']') {
                let host = host_port[..=close].to_string();
                let after = &host_port[close + 1..];
                if after.is_empty() {
                    // No port: `[::1]`
                    (host, 5060)
                } else if let Some(port_str) = after.strip_prefix(':') {
                    // Has port: `[::1]:5060`
                    (host, port_str.parse().unwrap_or(5060))
                } else {
                    // Malformed (garbage after `]` without `:`)
                    return Err(SipError::Parse(format!(
                        "Via IPv6 sent-by has trailing data after ']': {host_port}"
                    )));
                }
            } else {
                return Err(SipError::Parse(format!(
                    "Via IPv6 sent-by missing closing ']': {host_port}"
                )));
            }
        } else if let Some(idx) = host_port.rfind(':') {
            let port_str = &host_port[idx + 1..];
            if port_str.chars().all(|c| c.is_ascii_digit()) && !port_str.is_empty() {
                (
                    host_port[..idx].to_string(),
                    port_str.parse().unwrap_or(5060),
                )
            } else {
                // Bare IPv6 without brackets (non-conformant but
                // tolerate gracefully) or non-numeric after last colon.
                (host_port.to_string(), 5060)
            }
        } else {
            (host_port.to_string(), 5060)
        };

        // Parse parameters
        let mut branch = String::new();
        let mut received = None;
        let mut rport = None;

        if let Some(params_str) = params {
            for param in params_str.split(';') {
                let param = param.trim();
                if let Some(value) = param.strip_prefix("branch=") {
                    branch = value.to_string();
                } else if let Some(value) = param.strip_prefix("received=") {
                    received = Some(value.to_string());
                } else if let Some(value) = param.strip_prefix("rport=") {
                    rport = value.parse().ok();
                } else if param == "rport" {
                    // rport without value (client requesting rport)
                    rport = None;
                }
            }
        }

        if branch.is_empty() {
            return Err(SipError::Parse(
                "Via header missing branch parameter".to_string(),
            ));
        }

        Ok(Via {
            protocol,
            host,
            port,
            branch,
            received,
            rport,
        })
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        let mut result = format!(
            "SIP/2.0/{} {}:{};branch={}",
            self.protocol, self.host, self.port, self.branch
        );

        if let Some(ref received) = self.received {
            result.push_str(&format!(";received={}", received));
        }

        if let Some(rport) = self.rport {
            result.push_str(&format!(";rport={}", rport));
        }

        result
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for Contact header (RFC 3261 Section 20.10).
#[derive(Debug, Clone, PartialEq)]
pub struct Contact {
    /// Contact URI.
    pub uri: SipUri,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// Expires parameter (optional).
    pub expires: Option<u32>,
    /// q-value for priority (optional, 0.0-1.0).
    pub q: Option<f32>,
}

impl Contact {
    /// Parse a Contact header value string.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();

        let (display_name, uri_part) = if let Some(stripped) = value.strip_prefix('"') {
            // Has display name in quotes
            if let Some(end_quote) = stripped.find('"') {
                let name = stripped[..end_quote].to_string();
                let rest = stripped[end_quote + 1..].trim();
                (Some(name), rest)
            } else {
                (None, value)
            }
        } else if let Some(lt_pos) = value.find('<') {
            // Display name without quotes before <
            let name = value[..lt_pos].trim();
            let rest = &value[lt_pos..];
            if name.is_empty() {
                (None, rest)
            } else {
                (Some(name.to_string()), rest)
            }
        } else {
            (None, value)
        };

        // Extract URI from angle brackets
        let (uri_str, params) = if uri_part.starts_with('<') {
            if let Some(gt_pos) = uri_part.find('>') {
                let uri = &uri_part[1..gt_pos];
                let params = if gt_pos + 1 < uri_part.len() {
                    Some(&uri_part[gt_pos + 1..])
                } else {
                    None
                };
                (uri, params)
            } else {
                return Err(SipError::Parse("Contact URI missing closing >".to_string()));
            }
        } else {
            // URI without angle brackets
            if let Some(semi_pos) = uri_part.find(';') {
                (&uri_part[..semi_pos], Some(&uri_part[semi_pos..]))
            } else {
                (uri_part, None)
            }
        };

        let uri = SipUri::parse(uri_str)?;

        // Parse parameters
        let mut expires = None;
        let mut q = None;

        if let Some(params_str) = params {
            for param in params_str.split(';') {
                let param = param.trim();
                if let Some(value) = param.strip_prefix("expires=") {
                    expires = value.parse().ok();
                } else if let Some(value) = param.strip_prefix("q=") {
                    q = value.parse().ok();
                }
            }
        }

        Ok(Contact {
            uri,
            display_name,
            expires,
            q,
        })
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        let mut result = String::new();

        if let Some(ref name) = self.display_name {
            result.push_str(&format!("\"{}\" ", name));
        }

        result.push('<');
        result.push_str(&self.uri.to_string());
        result.push('>');

        if let Some(expires) = self.expires {
            result.push_str(&format!(";expires={}", expires));
        }

        if let Some(q) = self.q {
            result.push_str(&format!(";q={:.1}", q));
        }

        result
    }
}

impl fmt::Display for Contact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for Record-Route header (RFC 3261 Section 20.30).
#[derive(Debug, Clone, PartialEq)]
pub struct RecordRoute {
    /// Record-Route URI.
    pub uri: SipUri,
    /// Whether the lr (loose routing) parameter is present.
    pub lr: bool,
}

impl RecordRoute {
    /// Parse a Record-Route header value string.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();

        // Extract URI from angle brackets
        let (uri_str, params) = if value.starts_with('<') {
            if let Some(gt_pos) = value.find('>') {
                let uri = &value[1..gt_pos];
                let params = if gt_pos + 1 < value.len() {
                    Some(&value[gt_pos + 1..])
                } else {
                    None
                };
                (uri, params)
            } else {
                return Err(SipError::Parse(
                    "Record-Route URI missing closing >".to_string(),
                ));
            }
        } else {
            return Err(SipError::Parse(
                "Record-Route must have URI in angle brackets".to_string(),
            ));
        };

        let uri = SipUri::parse(uri_str)?;

        // Check for lr parameter
        let lr = params.map(|p| p.contains("lr")).unwrap_or(false);

        Ok(RecordRoute { uri, lr })
    }

    /// Parse multiple Record-Route headers from a comma-separated value or multiple values.
    pub fn parse_all(values: &[String]) -> Vec<Self> {
        let mut routes = Vec::new();

        for value in values {
            // Record-Route can be comma-separated
            for part in value.split(',') {
                if let Ok(rr) = Self::parse(part) {
                    routes.push(rr);
                }
            }
        }

        routes
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        if self.lr {
            format!("<{}>;lr", self.uri)
        } else {
            format!("<{}>", self.uri)
        }
    }
}

impl fmt::Display for RecordRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for Route header (RFC 3261 Section 20.34).
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    /// Route URI.
    pub uri: SipUri,
    /// Whether the lr (loose routing) parameter is present.
    pub lr: bool,
}

impl Route {
    /// Parse a Route header value string.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();

        // Extract URI from angle brackets
        let (uri_str, params) = if value.starts_with('<') {
            if let Some(gt_pos) = value.find('>') {
                let uri = &value[1..gt_pos];
                let params = if gt_pos + 1 < value.len() {
                    Some(&value[gt_pos + 1..])
                } else {
                    None
                };
                (uri, params)
            } else {
                return Err(SipError::Parse("Route URI missing closing >".to_string()));
            }
        } else {
            return Err(SipError::Parse(
                "Route must have URI in angle brackets".to_string(),
            ));
        };

        let uri = SipUri::parse(uri_str)?;

        // Check for lr parameter
        let lr = params.map(|p| p.contains("lr")).unwrap_or(false);

        Ok(Route { uri, lr })
    }

    /// Parse multiple Route headers from a comma-separated value or multiple values.
    pub fn parse_all(values: &[String]) -> Vec<Self> {
        let mut routes = Vec::new();

        for value in values {
            for part in value.split(',') {
                if let Ok(r) = Self::parse(part) {
                    routes.push(r);
                }
            }
        }

        routes
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        if self.lr {
            format!("<{}>;lr", self.uri)
        } else {
            format!("<{}>", self.uri)
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Route set for dialog routing (RFC 3261 Section 12.2).
#[derive(Debug, Clone, Default)]
pub struct RouteSet {
    routes: Vec<Route>,
}

impl RouteSet {
    /// Create an empty route set.
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Create a route set from Record-Route headers.
    ///
    /// For UAC (caller), reverse should be true (routes are reversed).
    /// For UAS (callee), reverse should be false.
    pub fn from_record_routes(record_routes: Vec<RecordRoute>, reverse: bool) -> Self {
        let mut routes: Vec<Route> = record_routes
            .into_iter()
            .map(|rr| Route {
                uri: rr.uri,
                lr: rr.lr,
            })
            .collect();

        if reverse {
            routes.reverse();
        }

        Self { routes }
    }

    /// Check if the route set is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Get the number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Get the routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Get the first route (for determining request URI in loose routing).
    pub fn first(&self) -> Option<&Route> {
        self.routes.first()
    }

    /// Add a route to the set.
    pub fn push(&mut self, route: Route) {
        self.routes.push(route);
    }
}

/// Refresher role for `Session-Expires` (RFC 4028 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresher {
    /// The UAC will refresh the session before each interval expires.
    Uac,
    /// The UAS will refresh the session before each interval expires.
    Uas,
}

impl fmt::Display for Refresher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refresher::Uac => write!(f, "uac"),
            Refresher::Uas => write!(f, "uas"),
        }
    }
}

impl Refresher {
    /// Parse a refresher token (case-insensitive).
    pub fn parse(value: &str) -> Result<Self, SipError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "uac" => Ok(Refresher::Uac),
            "uas" => Ok(Refresher::Uas),
            other => Err(SipError::Parse(format!(
                "Invalid refresher value '{}'",
                other
            ))),
        }
    }
}

/// Typed wrapper for `Require` header (RFC 3261 §20.32).
///
/// Comma-separated list of option-tags. Empty lists are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Require(pub Vec<String>);

impl Require {
    /// Parse a `Require` header value.
    ///
    /// Accepts extra whitespace and lowercases option-tags. Rejects empty
    /// lists (a `Require` header with no tags is malformed).
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let tags = parse_option_tags(value)?;
        Ok(Require(tags))
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        self.0.join(", ")
    }
}

impl fmt::Display for Require {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for `Supported` header (RFC 3261 §20.37).
///
/// Comma-separated list of option-tags. Empty lists are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supported(pub Vec<String>);

impl Supported {
    /// Parse a `Supported` header value.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let tags = parse_option_tags(value)?;
        Ok(Supported(tags))
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        self.0.join(", ")
    }
}

impl fmt::Display for Supported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Shared parser for comma-separated option-tag lists (Require/Supported).
fn parse_option_tags(value: &str) -> Result<Vec<String>, SipError> {
    let tags: Vec<String> = value
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();

    if tags.is_empty() {
        return Err(SipError::Parse(
            "Option-tag list must not be empty".to_string(),
        ));
    }
    Ok(tags)
}

/// Typed wrapper for `Session-Expires` header (RFC 4028 §4).
///
/// Format: `Session-Expires: <delta-seconds>[;refresher=uac|uas]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExpires {
    /// Session refresh interval in seconds.
    pub delta_seconds: u32,
    /// Which side refreshes; absent if not specified by the offerer.
    pub refresher: Option<Refresher>,
}

impl SessionExpires {
    /// Parse a `Session-Expires` header value.
    ///
    /// Accepts extra whitespace and ignores parameters other than
    /// `refresher`. If `refresher` is absent the field is left `None`.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();
        let (head, params) = match value.find(';') {
            Some(idx) => (&value[..idx], Some(&value[idx + 1..])),
            None => (value, None),
        };

        let delta_seconds: u32 = head.trim().parse().map_err(|_| {
            SipError::Parse(format!(
                "Invalid Session-Expires delta-seconds '{}'",
                head.trim()
            ))
        })?;

        let mut refresher = None;
        if let Some(params_str) = params {
            for param in params_str.split(';') {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }
                // RFC 3261 ABNF: EQUAL = SWS "=" SWS — whitespace allowed
                // around `=`. Split once, trim both sides.
                if let Some((key, value)) = param.split_once('=') {
                    if key.trim().eq_ignore_ascii_case("refresher") {
                        refresher = Some(Refresher::parse(value.trim())?);
                    }
                    // Other params are tolerated and ignored.
                }
            }
        }

        Ok(SessionExpires {
            delta_seconds,
            refresher,
        })
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        match self.refresher {
            Some(r) => format!("{};refresher={}", self.delta_seconds, r),
            None => self.delta_seconds.to_string(),
        }
    }
}

impl fmt::Display for SessionExpires {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for `Min-SE` header (RFC 4028 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinSe(pub u32);

impl MinSe {
    /// Parse a `Min-SE` header value.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        // Min-SE is `delta-seconds *(;generic-param)`. Strip params, parse.
        let head = match value.find(';') {
            Some(idx) => &value[..idx],
            None => value,
        };
        let secs: u32 = head
            .trim()
            .parse()
            .map_err(|_| SipError::Parse(format!("Invalid Min-SE value '{}'", head.trim())))?;
        Ok(MinSe(secs))
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for MinSe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for `RSeq` header (RFC 3262 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RSeq(pub u32);

impl RSeq {
    /// Parse an `RSeq` header value.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let n: u32 = value
            .trim()
            .parse()
            .map_err(|_| SipError::Parse(format!("Invalid RSeq value '{}'", value.trim())))?;
        Ok(RSeq(n))
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for RSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for `RAck` header (RFC 3262 §7.2).
///
/// Format: `RAck: <rseq> <cseq> <method>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAck {
    /// The `RSeq` value from the provisional being acknowledged.
    pub rseq: u32,
    /// The CSeq number of the request that prompted the provisional.
    pub cseq: u32,
    /// The method of the request that prompted the provisional.
    pub method: Method,
}

impl RAck {
    /// Parse an `RAck` header value (`<rseq> <cseq> <method>`).
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(SipError::Parse(format!(
                "RAck must be '<rseq> <cseq> <method>', got '{}'",
                value
            )));
        }
        let rseq: u32 = parts[0]
            .parse()
            .map_err(|_| SipError::Parse(format!("Invalid RAck rseq '{}'", parts[0])))?;
        let cseq: u32 = parts[1]
            .parse()
            .map_err(|_| SipError::Parse(format!("Invalid RAck cseq '{}'", parts[1])))?;
        let method = parse_method(parts[2])?;
        Ok(RAck { rseq, cseq, method })
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        format!("{} {} {}", self.rseq, self.cseq, self.method)
    }
}

impl fmt::Display for RAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Parse a method token (case-insensitive) into the local `Method` enum.
fn parse_method(value: &str) -> Result<Method, SipError> {
    match value.to_ascii_uppercase().as_str() {
        "INVITE" => Ok(Method::Invite),
        "ACK" => Ok(Method::Ack),
        "BYE" => Ok(Method::Bye),
        "CANCEL" => Ok(Method::Cancel),
        "REGISTER" => Ok(Method::Register),
        "OPTIONS" => Ok(Method::Options),
        "PRACK" => Ok(Method::Prack),
        "SUBSCRIBE" => Ok(Method::Subscribe),
        "NOTIFY" => Ok(Method::Notify),
        "PUBLISH" => Ok(Method::Publish),
        "INFO" => Ok(Method::Info),
        "REFER" => Ok(Method::Refer),
        "MESSAGE" => Ok(Method::Message),
        "UPDATE" => Ok(Method::Update),
        other => Err(SipError::Parse(format!("Unknown SIP method '{}'", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Via tests
    #[test]
    fn test_via_parse() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776").unwrap();
        assert_eq!(via.protocol, "UDP");
        assert_eq!(via.host, "192.168.1.1");
        assert_eq!(via.port, 5060);
        assert_eq!(via.branch, "z9hG4bK776");
        assert!(via.received.is_none());
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_with_received() {
        let via = Via::parse(
            "SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bK123;received=10.0.0.1;rport=12345",
        )
        .unwrap();
        assert_eq!(via.protocol, "TCP");
        assert_eq!(via.host, "proxy.example.com");
        assert_eq!(via.received, Some("10.0.0.1".to_string()));
        assert_eq!(via.rport, Some(12345));
    }

    #[test]
    fn test_via_parse_ipv6_with_port() {
        let via = Via::parse("SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK123").unwrap();
        assert_eq!(via.host, "[2001:db8::1]");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_ipv6_no_port() {
        let via = Via::parse("SIP/2.0/TCP [::1];branch=z9hG4bK456").unwrap();
        assert_eq!(via.host, "[::1]");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_ipv6_non_standard_port() {
        let via =
            Via::parse("SIP/2.0/TLS [fe80::1%25eth0]:5061;branch=z9hG4bK789").unwrap();
        assert_eq!(via.host, "[fe80::1%25eth0]");
        assert_eq!(via.port, 5061);
    }

    #[test]
    fn test_via_parse_ipv6_full_address() {
        let via = Via::parse(
            "SIP/2.0/UDP [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4060;branch=z9hG4bKfull",
        )
        .unwrap();
        assert_eq!(via.host, "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]");
        assert_eq!(via.port, 4060);
    }

    #[test]
    fn test_via_ipv6_round_trip() {
        // Parse → serialize → parse must be stable.
        let input = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKrt";
        let via = Via::parse(input).unwrap();
        let serialized = via.to_header_value();
        assert_eq!(serialized, input);
        let via2 = Via::parse(&serialized).unwrap();
        assert_eq!(via2.host, "[2001:db8::1]");
        assert_eq!(via2.port, 5060);
    }

    #[test]
    fn test_via_ipv6_loopback_round_trip() {
        let input = "SIP/2.0/TCP [::1]:5060;branch=z9hG4bKlo";
        let via = Via::parse(input).unwrap();
        assert_eq!(via.to_header_value(), input);
    }

    #[test]
    fn test_via_parse_ipv6_unterminated_bracket() {
        let result = Via::parse("SIP/2.0/UDP [2001:db8::1:5060;branch=z9hG4bK1");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_rport_without_value() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776;rport").unwrap();
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_tls() {
        let via = Via::parse("SIP/2.0/TLS secure.example.com:5061;branch=z9hG4bKsecure").unwrap();
        assert_eq!(via.protocol, "TLS");
        assert_eq!(via.host, "secure.example.com");
        assert_eq!(via.port, 5061);
    }

    #[test]
    fn test_via_parse_default_port() {
        let via = Via::parse("SIP/2.0/UDP proxy.example.com;branch=z9hG4bKabc").unwrap();
        assert_eq!(via.host, "proxy.example.com");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_missing_protocol() {
        let result = Via::parse("SIP/2.0/ 192.168.1.1:5060;branch=z9hG4bK123");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_non_numeric_port() {
        let via = Via::parse("SIP/2.0/UDP proxy.example.com:abc;branch=z9hG4bK123").unwrap();
        assert_eq!(via.host, "proxy.example.com:abc");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_rport_no_value() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776;rport").unwrap();
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_unknown_param_without_value() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776;foo").unwrap();
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_invalid_format() {
        let result = Via::parse("InvalidVia");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_no_branch() {
        let result = Via::parse("SIP/2.0/UDP 192.168.1.1:5060");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_whitespace() {
        let via = Via::parse("  SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123  ").unwrap();
        assert_eq!(via.protocol, "UDP");
        assert_eq!(via.branch, "z9hG4bK123");
    }

    #[test]
    fn test_via_to_string() {
        let via = Via {
            protocol: "UDP".to_string(),
            host: "192.168.1.1".to_string(),
            port: 5060,
            branch: "z9hG4bK776".to_string(),
            received: Some("10.0.0.1".to_string()),
            rport: Some(12345),
        };

        let s = via.to_string();
        assert!(s.contains("SIP/2.0/UDP"));
        assert!(s.contains("192.168.1.1:5060"));
        assert!(s.contains("branch=z9hG4bK776"));
        assert!(s.contains("received=10.0.0.1"));
        assert!(s.contains("rport=12345"));
    }

    #[test]
    fn test_via_to_header_value_no_optional() {
        let via = Via {
            protocol: "TCP".to_string(),
            host: "example.com".to_string(),
            port: 5060,
            branch: "z9hG4bK999".to_string(),
            received: None,
            rport: None,
        };

        let s = via.to_header_value();
        assert_eq!(s, "SIP/2.0/TCP example.com:5060;branch=z9hG4bK999");
    }

    #[test]
    fn test_via_clone() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123").unwrap();
        let cloned = via.clone();
        assert_eq!(via, cloned);
    }

    #[test]
    fn test_via_debug() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123").unwrap();
        let debug = format!("{:?}", via);
        assert!(debug.contains("Via"));
    }

    // Contact tests
    #[test]
    fn test_contact_parse() {
        let contact = Contact::parse("<sip:alice@192.168.1.1:5060>").unwrap();
        assert_eq!(contact.uri.to_string(), "sip:alice@192.168.1.1:5060");
        assert!(contact.display_name.is_none());
    }

    #[test]
    fn test_contact_parse_with_display_name() {
        let contact = Contact::parse("\"Alice\" <sip:alice@example.com>;expires=3600").unwrap();
        assert_eq!(contact.display_name, Some("Alice".to_string()));
        assert_eq!(contact.expires, Some(3600));
    }

    #[test]
    fn test_contact_parse_missing_end_quote() {
        let result = Contact::parse("\"Alice <sip:alice@example.com>");
        assert!(result.is_err());
    }

    #[test]
    fn test_contact_parse_with_q_value() {
        let contact = Contact::parse("<sip:alice@example.com>;q=0.5").unwrap();
        assert_eq!(contact.q, Some(0.5));
    }

    #[test]
    fn test_contact_parse_with_all_params() {
        let contact = Contact::parse("\"Bob\" <sip:bob@example.com>;expires=7200;q=0.8").unwrap();
        assert_eq!(contact.display_name, Some("Bob".to_string()));
        assert_eq!(contact.expires, Some(7200));
        assert_eq!(contact.q, Some(0.8));
    }

    #[test]
    fn test_contact_parse_display_name_no_quotes() {
        let contact = Contact::parse("Alice <sip:alice@example.com>").unwrap();
        assert_eq!(contact.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn test_contact_parse_no_angle_brackets() {
        let contact = Contact::parse("sip:alice@example.com").unwrap();
        assert!(contact.display_name.is_none());
        assert!(contact.uri.to_string().contains("alice"));
    }

    #[test]
    fn test_contact_parse_no_angle_brackets_with_params() {
        let contact = Contact::parse("sip:alice@example.com;expires=1800").unwrap();
        assert_eq!(contact.expires, Some(1800));
    }

    #[test]
    fn test_contact_parse_missing_closing_bracket() {
        let result = Contact::parse("<sip:alice@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_contact_to_header_value() {
        let contact = Contact {
            uri: SipUri::parse("sip:alice@example.com").unwrap(),
            display_name: Some("Alice".to_string()),
            expires: Some(3600),
            q: Some(0.7),
        };

        let s = contact.to_header_value();
        assert!(s.contains("\"Alice\""));
        assert!(s.contains("<sip:alice@example.com>"));
        assert!(s.contains("expires=3600"));
        assert!(s.contains("q=0.7"));
    }

    #[test]
    fn test_contact_to_header_value_no_optional() {
        let contact = Contact {
            uri: SipUri::parse("sip:bob@example.com").unwrap(),
            display_name: None,
            expires: None,
            q: None,
        };

        let s = contact.to_header_value();
        assert_eq!(s, "<sip:bob@example.com>");
    }

    #[test]
    fn test_contact_display() {
        let contact = Contact::parse("<sip:alice@example.com>").unwrap();
        let s = contact.to_string();
        assert!(s.contains("sip:alice@example.com"));
    }

    #[test]
    fn test_contact_clone() {
        let contact = Contact::parse("<sip:alice@example.com>").unwrap();
        let cloned = contact.clone();
        assert_eq!(contact, cloned);
    }

    // RecordRoute tests
    #[test]
    fn test_record_route_parse() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        assert!(rr.lr);
        assert!(rr.uri.to_string().contains("proxy.example.com"));
    }

    #[test]
    fn test_record_route_parse_no_lr() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>").unwrap();
        assert!(!rr.lr);
    }

    #[test]
    fn test_record_route_parse_with_port() {
        let rr = RecordRoute::parse("<sip:proxy.example.com:5060>;lr").unwrap();
        assert!(rr.lr);
    }

    #[test]
    fn test_record_route_parse_missing_brackets() {
        let result = RecordRoute::parse("sip:proxy.example.com;lr");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_route_parse_missing_closing() {
        let result = RecordRoute::parse("<sip:proxy.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_route_parse_invalid_uri() {
        let result = RecordRoute::parse("<sip:proxy@[::1>");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_route_parse_all() {
        let values = vec![
            "<sip:p1.example.com>;lr, <sip:p2.example.com>;lr".to_string(),
            "<sip:p3.example.com>".to_string(),
        ];
        let routes = RecordRoute::parse_all(&values);
        assert_eq!(routes.len(), 3);
    }

    #[test]
    fn test_record_route_parse_all_ignores_invalid() {
        let values = vec!["<sip:proxy.example.com>;lr, invalid".to_string()];
        let routes = RecordRoute::parse_all(&values);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn test_record_route_parse_all_empty() {
        let values: Vec<String> = vec![];
        let routes = RecordRoute::parse_all(&values);
        assert!(routes.is_empty());
    }

    #[test]
    fn test_record_route_to_header_value() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = rr.to_header_value();
        assert!(s.contains("<sip:proxy.example.com>"));
        assert!(s.contains("lr"));
    }

    #[test]
    fn test_record_route_to_header_value_no_lr() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>").unwrap();
        let s = rr.to_header_value();
        assert!(!s.contains("lr"));
    }

    #[test]
    fn test_record_route_display() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = rr.to_string();
        assert!(s.contains("proxy.example.com"));
    }

    #[test]
    fn test_record_route_clone() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        let cloned = rr.clone();
        assert_eq!(rr, cloned);
    }

    // Route tests
    #[test]
    fn test_route_parse() {
        let route = Route::parse("<sip:proxy.example.com:5060>;lr").unwrap();
        assert!(route.lr);
    }

    #[test]
    fn test_route_parse_no_lr() {
        let route = Route::parse("<sip:proxy.example.com>").unwrap();
        assert!(!route.lr);
    }

    #[test]
    fn test_route_parse_missing_brackets() {
        let result = Route::parse("sip:proxy.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_parse_missing_closing() {
        let result = Route::parse("<sip:proxy.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_parse_invalid_uri() {
        let result = Route::parse("<sip:proxy@[::1>");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_parse_all() {
        let values = vec!["<sip:p1.example.com>;lr, <sip:p2.example.com>;lr".to_string()];
        let routes = Route::parse_all(&values);
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_route_parse_all_ignores_invalid() {
        let values = vec!["<sip:p1.example.com>;lr, invalid".to_string()];
        let routes = Route::parse_all(&values);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn test_route_parse_all_empty() {
        let values: Vec<String> = vec![];
        let routes = Route::parse_all(&values);
        assert!(routes.is_empty());
    }

    #[test]
    fn test_route_to_header_value() {
        let route = Route::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = route.to_header_value();
        assert!(s.contains("<sip:proxy.example.com>"));
        assert!(s.contains("lr"));
    }

    #[test]
    fn test_route_to_header_value_no_lr() {
        let route = Route::parse("<sip:proxy.example.com>").unwrap();
        let s = route.to_header_value();
        assert!(!s.contains("lr"));
    }

    #[test]
    fn test_route_display() {
        let route = Route::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = route.to_string();
        assert!(s.contains("proxy.example.com"));
    }

    #[test]
    fn test_route_clone() {
        let route = Route::parse("<sip:proxy.example.com>;lr").unwrap();
        let cloned = route.clone();
        assert_eq!(route, cloned);
    }

    // RouteSet tests
    #[test]
    fn test_route_set_new() {
        let route_set = RouteSet::new();
        assert!(route_set.is_empty());
        assert_eq!(route_set.len(), 0);
    }

    #[test]
    fn test_route_set_default() {
        let route_set = RouteSet::default();
        assert!(route_set.is_empty());
    }

    #[test]
    fn test_route_set_from_record_routes() {
        let rrs = vec![
            RecordRoute::parse("<sip:p1.example.com;lr>").unwrap(),
            RecordRoute::parse("<sip:p2.example.com;lr>").unwrap(),
        ];

        // UAC reverses
        let route_set = RouteSet::from_record_routes(rrs.clone(), true);
        assert_eq!(route_set.len(), 2);
        assert!(route_set.routes()[0].uri.to_string().contains("p2"));
        assert!(route_set.routes()[1].uri.to_string().contains("p1"));

        // UAS doesn't reverse
        let route_set = RouteSet::from_record_routes(rrs, false);
        assert!(route_set.routes()[0].uri.to_string().contains("p1"));
        assert!(route_set.routes()[1].uri.to_string().contains("p2"));
    }

    #[test]
    fn test_route_set_is_empty() {
        let mut route_set = RouteSet::new();
        assert!(route_set.is_empty());

        route_set.push(Route::parse("<sip:proxy.example.com>;lr").unwrap());
        assert!(!route_set.is_empty());
    }

    #[test]
    fn test_route_set_len() {
        let mut route_set = RouteSet::new();
        assert_eq!(route_set.len(), 0);

        route_set.push(Route::parse("<sip:p1.example.com>;lr").unwrap());
        assert_eq!(route_set.len(), 1);

        route_set.push(Route::parse("<sip:p2.example.com>;lr").unwrap());
        assert_eq!(route_set.len(), 2);
    }

    #[test]
    fn test_route_set_first() {
        let mut route_set = RouteSet::new();
        assert!(route_set.first().is_none());

        route_set.push(Route::parse("<sip:first.example.com>;lr").unwrap());
        route_set.push(Route::parse("<sip:second.example.com>;lr").unwrap());

        let first = route_set.first().unwrap();
        assert!(first.uri.to_string().contains("first"));
    }

    #[test]
    fn test_route_set_routes() {
        let mut route_set = RouteSet::new();
        route_set.push(Route::parse("<sip:p1.example.com>;lr").unwrap());
        route_set.push(Route::parse("<sip:p2.example.com>;lr").unwrap());

        let routes = route_set.routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_route_set_push() {
        let mut route_set = RouteSet::new();
        route_set.push(Route::parse("<sip:proxy.example.com>;lr").unwrap());
        assert_eq!(route_set.len(), 1);
    }

    #[test]
    fn test_route_set_clone() {
        let mut route_set = RouteSet::new();
        route_set.push(Route::parse("<sip:proxy.example.com>;lr").unwrap());
        let cloned = route_set.clone();
        assert_eq!(cloned.len(), 1);
    }

    #[test]
    fn test_route_set_debug() {
        let route_set = RouteSet::new();
        let debug = format!("{:?}", route_set);
        assert!(debug.contains("RouteSet"));
    }

    // Refresher tests
    #[test]
    fn test_refresher_parse_uac() {
        assert_eq!(Refresher::parse("uac").unwrap(), Refresher::Uac);
    }

    #[test]
    fn test_refresher_parse_uas() {
        assert_eq!(Refresher::parse("uas").unwrap(), Refresher::Uas);
    }

    #[test]
    fn test_refresher_parse_case_insensitive() {
        assert_eq!(Refresher::parse(" UAC ").unwrap(), Refresher::Uac);
        assert_eq!(Refresher::parse("Uas").unwrap(), Refresher::Uas);
    }

    #[test]
    fn test_refresher_parse_invalid() {
        assert!(Refresher::parse("proxy").is_err());
    }

    #[test]
    fn test_refresher_display() {
        assert_eq!(Refresher::Uac.to_string(), "uac");
        assert_eq!(Refresher::Uas.to_string(), "uas");
    }

    // Require tests
    #[test]
    fn test_require_parse_single_tag() {
        let r = Require::parse("100rel").unwrap();
        assert_eq!(r.0, vec!["100rel".to_string()]);
    }

    #[test]
    fn test_require_parse_multiple_tags() {
        let r = Require::parse("100rel, timer").unwrap();
        assert_eq!(r.0, vec!["100rel".to_string(), "timer".to_string()]);
    }

    #[test]
    fn test_require_parse_extra_whitespace() {
        let r = Require::parse("  100rel ,    timer  ").unwrap();
        assert_eq!(r.0, vec!["100rel".to_string(), "timer".to_string()]);
    }

    #[test]
    fn test_require_parse_lowercases() {
        let r = Require::parse("100REL, Timer").unwrap();
        assert_eq!(r.0, vec!["100rel".to_string(), "timer".to_string()]);
    }

    #[test]
    fn test_require_parse_empty_rejected() {
        assert!(Require::parse("").is_err());
        assert!(Require::parse(" , ").is_err());
    }

    #[test]
    fn test_require_round_trip() {
        let r = Require(vec!["100rel".to_string(), "timer".to_string()]);
        let s = r.to_string();
        assert_eq!(s, "100rel, timer");
        let parsed = Require::parse(&s).unwrap();
        assert_eq!(parsed, r);
    }

    // Supported tests
    #[test]
    fn test_supported_parse_single_tag() {
        let s = Supported::parse("timer").unwrap();
        assert_eq!(s.0, vec!["timer".to_string()]);
    }

    #[test]
    fn test_supported_parse_multiple_tags() {
        let s = Supported::parse("timer, 100rel").unwrap();
        assert_eq!(s.0, vec!["timer".to_string(), "100rel".to_string()]);
    }

    #[test]
    fn test_supported_parse_empty_rejected() {
        assert!(Supported::parse("").is_err());
    }

    #[test]
    fn test_supported_round_trip() {
        let s = Supported(vec!["timer".to_string(), "100rel".to_string()]);
        let display = s.to_string();
        assert_eq!(display, "timer, 100rel");
        let parsed = Supported::parse(&display).unwrap();
        assert_eq!(parsed, s);
    }

    // SessionExpires tests
    #[test]
    fn test_session_expires_parse_value_only() {
        let se = SessionExpires::parse("1800").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert!(se.refresher.is_none());
    }

    #[test]
    fn test_session_expires_parse_with_refresher_uac() {
        let se = SessionExpires::parse("1800;refresher=uac").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uac));
    }

    #[test]
    fn test_session_expires_parse_with_refresher_uas() {
        let se = SessionExpires::parse("90 ; refresher=uas").unwrap();
        assert_eq!(se.delta_seconds, 90);
        assert_eq!(se.refresher, Some(Refresher::Uas));
    }

    #[test]
    fn test_session_expires_parse_whitespace_around_equal() {
        // RFC 3261 ABNF EQUAL = SWS "=" SWS. Pre/post-fix had this returning
        // refresher: None, silently losing the choice.
        let se = SessionExpires::parse("1800;refresher = uac").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uac));

        // Mixed-case key should also work (token is case-insensitive).
        let se = SessionExpires::parse("1800; Refresher =uas").unwrap();
        assert_eq!(se.refresher, Some(Refresher::Uas));
    }

    #[test]
    fn test_session_expires_parse_ignores_unknown_param() {
        let se = SessionExpires::parse("1800;foo=bar;refresher=uac").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uac));
    }

    #[test]
    fn test_session_expires_parse_invalid_seconds() {
        assert!(SessionExpires::parse("abc").is_err());
        assert!(SessionExpires::parse("abc;refresher=uac").is_err());
    }

    #[test]
    fn test_session_expires_parse_invalid_refresher() {
        assert!(SessionExpires::parse("1800;refresher=proxy").is_err());
    }

    #[test]
    fn test_session_expires_round_trip_no_refresher() {
        let se = SessionExpires {
            delta_seconds: 600,
            refresher: None,
        };
        let s = se.to_string();
        assert_eq!(s, "600");
        assert_eq!(SessionExpires::parse(&s).unwrap(), se);
    }

    #[test]
    fn test_session_expires_round_trip_with_refresher() {
        let se = SessionExpires {
            delta_seconds: 1800,
            refresher: Some(Refresher::Uac),
        };
        let s = se.to_string();
        assert_eq!(s, "1800;refresher=uac");
        assert_eq!(SessionExpires::parse(&s).unwrap(), se);
    }

    // MinSe tests
    #[test]
    fn test_min_se_parse() {
        assert_eq!(MinSe::parse("90").unwrap(), MinSe(90));
        assert_eq!(MinSe::parse("  120  ").unwrap(), MinSe(120));
    }

    #[test]
    fn test_min_se_parse_with_param() {
        // RFC 4028 allows generic-param after the value; we tolerate.
        assert_eq!(MinSe::parse("90;foo=bar").unwrap(), MinSe(90));
    }

    #[test]
    fn test_min_se_parse_invalid() {
        assert!(MinSe::parse("abc").is_err());
        assert!(MinSe::parse("").is_err());
    }

    #[test]
    fn test_min_se_round_trip() {
        let m = MinSe(90);
        let s = m.to_string();
        assert_eq!(s, "90");
        assert_eq!(MinSe::parse(&s).unwrap(), m);
    }

    // RSeq tests
    #[test]
    fn test_rseq_parse() {
        assert_eq!(RSeq::parse("1").unwrap(), RSeq(1));
        assert_eq!(RSeq::parse(" 4242 ").unwrap(), RSeq(4242));
    }

    #[test]
    fn test_rseq_parse_invalid() {
        assert!(RSeq::parse("abc").is_err());
        assert!(RSeq::parse("").is_err());
        assert!(RSeq::parse("-1").is_err());
    }

    #[test]
    fn test_rseq_round_trip() {
        let r = RSeq(1);
        let s = r.to_string();
        assert_eq!(s, "1");
        assert_eq!(RSeq::parse(&s).unwrap(), r);
    }

    // RAck tests
    #[test]
    fn test_rack_parse() {
        let rack = RAck::parse("1 314159 INVITE").unwrap();
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 314159);
        assert_eq!(rack.method, Method::Invite);
    }

    #[test]
    fn test_rack_parse_method_case_insensitive() {
        let rack = RAck::parse("1 1 invite").unwrap();
        assert_eq!(rack.method, Method::Invite);
    }

    #[test]
    fn test_rack_parse_extra_whitespace() {
        let rack = RAck::parse("  1   2   UPDATE  ").unwrap();
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 2);
        assert_eq!(rack.method, Method::Update);
    }

    #[test]
    fn test_rack_parse_too_few_tokens() {
        assert!(RAck::parse("1 INVITE").is_err());
    }

    #[test]
    fn test_rack_parse_too_many_tokens() {
        assert!(RAck::parse("1 2 INVITE extra").is_err());
    }

    #[test]
    fn test_rack_parse_invalid_rseq() {
        assert!(RAck::parse("abc 1 INVITE").is_err());
    }

    #[test]
    fn test_rack_parse_invalid_cseq() {
        assert!(RAck::parse("1 abc INVITE").is_err());
    }

    #[test]
    fn test_rack_parse_unknown_method() {
        assert!(RAck::parse("1 1 BOGUS").is_err());
    }

    #[test]
    fn test_rack_round_trip() {
        let rack = RAck {
            rseq: 1,
            cseq: 314159,
            method: Method::Invite,
        };
        let s = rack.to_string();
        assert_eq!(s, "1 314159 INVITE");
        assert_eq!(RAck::parse(&s).unwrap(), rack);
    }
}

//! INVITE dialog state machine.
//!
//! Handles the lifecycle of an INVITE-initiated dialog, including:
//! - Dialog establishment via INVITE/2xx/ACK
//! - In-dialog requests (re-INVITE, BYE, etc.)
//! - Dialog termination

use crate::dialog::state::{DialogId, DialogInfo, DialogState};
use crate::sip::{Method, SipRequest, SipResponse};

/// Role in the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// User Agent Client - initiated the dialog.
    Uac,
    /// User Agent Server - received the initial INVITE.
    Uas,
}

/// Output action from the dialog.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a request to the network.
    SendRequest(SipRequest),
    /// Send a response to the network.
    SendResponse(SipResponse),
    /// Emit an event to the user.
    Event(Event),
}

/// Event emitted to the user.
#[derive(Debug, Clone)]
pub enum Event {
    /// Dialog established (2xx received/sent).
    Established,
    /// Provisional response received/sent.
    Provisional(SipResponse),
    /// Re-INVITE received.
    ReInvite(SipRequest),
    /// BYE received.
    ByeReceived(SipRequest),
    /// Dialog terminated.
    Terminated(TerminationReason),
    /// Session progress (183 with SDP).
    SessionProgress(SipResponse),
}

/// Reason for dialog termination.
#[derive(Debug, Clone)]
pub enum TerminationReason {
    /// Normal BYE.
    ByeSent,
    /// Remote BYE.
    ByeReceived,
    /// INVITE rejected.
    Rejected(u16),
    /// INVITE cancelled.
    Cancelled,
    /// Error.
    Error(String),
}

/// INVITE dialog (Sans-IO).
#[derive(Debug)]
pub struct InviteDialog {
    /// Dialog info.
    info: DialogInfo,
    /// Our role.
    role: Role,
    /// Original INVITE request (for reference).
    invite: SipRequest,
    /// Pending actions.
    actions: Vec<Action>,
    /// Whether ACK has been sent/received.
    ack_sent: bool,
}

impl InviteDialog {
    /// Create a new UAC dialog from an outgoing INVITE.
    ///
    /// The dialog is not yet established - call `handle_response` with responses.
    pub fn new_uac(invite: SipRequest) -> Self {
        // Create a placeholder dialog info - will be filled in when response arrives
        let local_contact = invite
            .contact_uri()
            .map(|u| u.to_string())
            .unwrap_or_default();
        let info = DialogInfo {
            id: DialogId::new("", "", ""),
            state: DialogState::Early,
            local_seq: invite.cseq().unwrap_or(1),
            remote_seq: None,
            local_uri: invite
                .from_uri()
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_default(),
            remote_uri: invite
                .to_uri()
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_default(),
            remote_target: String::new(),
            local_contact,
            route_set: Default::default(),
            secure: false,
        };

        Self {
            info,
            role: Role::Uac,
            invite,
            actions: Vec::new(),
            ack_sent: false,
        }
    }

    /// Create a new UAS dialog from an incoming INVITE.
    ///
    /// Call `send_response` to send responses.
    pub fn new_uas(invite: SipRequest, local_tag: &str, local_contact: &str) -> Option<Self> {
        let info =
            DialogInfo::from_invite_uas(&invite, local_tag, local_contact, DialogState::Early)?;

        Some(Self {
            info,
            role: Role::Uas,
            invite,
            actions: Vec::new(),
            ack_sent: false,
        })
    }

    /// Reconstruct an `InviteDialog` from already-known `DialogInfo` and a
    /// role.
    ///
    /// Used by the session layer to thread Phase 4 in-dialog requests
    /// (PRACK, UPDATE, refresh re-INVITE, expiry BYE) through the same
    /// builders the dialog layer uses, so route_set and remote_target
    /// flow into Route headers and request URIs per RFC 3261 §12.2.1.1.
    ///
    /// The original INVITE is not preserved — `handle_response` is not
    /// useful on a transient instance constructed this way. Only the
    /// build_* / send_bye paths are intended for this constructor.
    pub fn from_dialog_info(info: DialogInfo, role: Role) -> Self {
        // Synthesize a placeholder INVITE so the field is not Optional.
        // It is not used by the build_* paths.
        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri(&info.remote_uri)
            .via("0.0.0.0", 5060, "UDP", "z9hG4bKplaceholder")
            .from(&info.local_uri, &info.id.local_tag)
            .to(&info.remote_uri)
            .call_id(&info.id.call_id)
            .cseq(info.local_seq.max(1))
            .build()
            .expect("placeholder INVITE always builds");
        Self {
            info,
            role,
            invite,
            actions: Vec::new(),
            ack_sent: false,
        }
    }

    /// Get the dialog ID.
    pub fn id(&self) -> &DialogId {
        &self.info.id
    }

    /// Get the dialog state.
    pub fn state(&self) -> DialogState {
        self.info.state
    }

    /// Get the dialog info.
    pub fn info(&self) -> &DialogInfo {
        &self.info
    }

    /// Get our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Check if dialog is terminated.
    pub fn is_terminated(&self) -> bool {
        self.info.state == DialogState::Terminated
    }

    /// Handle a response (UAC only).
    pub fn handle_response(&mut self, response: SipResponse) {
        if self.role != Role::Uac {
            return;
        }

        let code = response.status_code();

        match self.info.state {
            DialogState::Early => {
                if (100..200).contains(&code) {
                    // Provisional response
                    if code != 100 {
                        // Create early dialog if we have a To tag
                        if let Some(new_info) = DialogInfo::from_invite_response_uac(
                            &self.invite,
                            &response,
                            DialogState::Early,
                        ) {
                            self.info = new_info;
                        }

                        if code == 183 {
                            // Session progress - may have SDP for early media
                            self.actions
                                .push(Action::Event(Event::SessionProgress(response.clone())));
                        }
                        self.actions
                            .push(Action::Event(Event::Provisional(response)));
                    }
                } else if (200..300).contains(&code) {
                    // Success - dialog established
                    if let Some(new_info) = DialogInfo::from_invite_response_uac(
                        &self.invite,
                        &response,
                        DialogState::Confirmed,
                    ) {
                        self.info = new_info;
                    } else {
                        self.info.state = DialogState::Confirmed;
                    }
                    self.actions.push(Action::Event(Event::Established));
                    // UAC must send ACK - but that's handled at transaction/session level
                } else if code >= 300 {
                    // Failure - dialog terminates
                    self.info.state = DialogState::Terminated;
                    self.actions.push(Action::Event(Event::Terminated(
                        TerminationReason::Rejected(code),
                    )));
                }
            }
            DialogState::Confirmed => {
                // Responses to in-dialog requests (re-INVITE, etc.)
                // Handle at higher level
            }
            _ => {}
        }
    }

    /// Handle an incoming request (both UAC and UAS).
    pub fn handle_request(&mut self, request: SipRequest) {
        // Verify the request is for this dialog
        let cseq = match request.cseq() {
            Ok(seq) => seq,
            Err(_) => return,
        };

        match request.method() {
            Method::Bye => {
                self.info.state = DialogState::Terminated;
                self.actions
                    .push(Action::Event(Event::ByeReceived(request.clone())));
                self.actions.push(Action::Event(Event::Terminated(
                    TerminationReason::ByeReceived,
                )));
            }
            Method::Invite
                if self.info.state == DialogState::Confirmed
                    && self.info.update_remote_seq(cseq) =>
            {
                // Re-INVITE
                self.actions.push(Action::Event(Event::ReInvite(request)));
                // else: reject with 500 (CSeq out of order) — handled at the
                // wildcard arm below by doing nothing.
            }
            Method::Ack if self.role == Role::Uas && self.info.state == DialogState::Confirmed => {
                // ACK for 2xx (UAS side)
                self.ack_sent = true;
            }
            Method::Cancel if self.info.state == DialogState::Early && self.role == Role::Uas => {
                // CANCEL only applies to early dialogs
                self.info.state = DialogState::Terminated;
                self.actions.push(Action::Event(Event::Terminated(
                    TerminationReason::Cancelled,
                )));
            }
            _ => {
                // Other in-dialog requests (INFO, UPDATE, etc.)
                // Handle at higher level
            }
        }
    }

    /// Send a response (UAS only).
    pub fn send_response(&mut self, response: SipResponse) {
        if self.role != Role::Uas {
            return;
        }

        let code = response.status_code();

        if (200..300).contains(&code) && self.info.state == DialogState::Early {
            // Dialog confirmed
            self.info.state = DialogState::Confirmed;
            self.actions.push(Action::SendResponse(response));
            self.actions.push(Action::Event(Event::Established));
        } else if code >= 300 && self.info.state == DialogState::Early {
            // Dialog rejected
            self.info.state = DialogState::Terminated;
            self.actions.push(Action::SendResponse(response));
            self.actions.push(Action::Event(Event::Terminated(
                TerminationReason::Rejected(code),
            )));
        } else {
            self.actions.push(Action::SendResponse(response));
        }
    }

    /// Send a BYE to terminate the dialog.
    pub fn send_bye(&mut self) -> Option<SipRequest> {
        if self.info.state != DialogState::Confirmed {
            return None;
        }

        self.info.state = DialogState::Terminating;

        // Build BYE request
        let cseq = self.info.next_local_seq();
        let bye = self.build_in_dialog_request(Method::Bye, cseq)?;

        self.actions.push(Action::SendRequest(bye.clone()));
        Some(bye)
    }

    /// Build a PRACK request for an inbound reliable provisional response
    /// (RFC 3262 §7.2).
    ///
    /// PRACK is a new transaction inside the dialog and gets the next CSeq
    /// value, *not* the original INVITE's CSeq. The INVITE's CSeq travels in
    /// the `RAck` header alongside the response's `RSeq`.
    ///
    /// # Panics (debug builds)
    ///
    /// `to.rseq()` must be `Some` — the caller is expected to have already
    /// determined that the response carries a reliable provisional. In
    /// release builds an absent RSeq falls back to 0 to avoid a hard failure.
    pub fn build_prack(&mut self, to: &SipResponse) -> SipRequest {
        let rseq = to
            .rseq()
            .map(|r| r.0)
            .or_else(|| {
                debug_assert!(
                    false,
                    "build_prack called with response lacking RSeq header — caller bug"
                );
                None
            })
            .unwrap_or(0);
        let cseq_orig = to.cseq().unwrap_or(0);
        let cseq_method = to
            .cseq_method()
            .expect("build_prack: 1xx response must carry a parseable CSeq method (validated by transaction layer)");

        let cseq = self.info.next_local_seq();
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());
        let request_uri = self.info.remote_target.clone();
        let routes = self.info.route_set.routes();

        let mut builder = SipRequest::builder()
            .method(Method::Prack)
            .uri(&request_uri)
            .via("0.0.0.0", 5060, "UDP", &branch)
            .from(&self.info.local_uri, &self.info.id.local_tag)
            .to(&self.info.remote_uri)
            .to_tag(&self.info.id.remote_tag)
            .call_id(&self.info.id.call_id)
            .cseq(cseq)
            .max_forwards(70)
            .rack(rseq, cseq_orig, cseq_method)
            .route(routes);

        // RFC 3261 §12.2.1.1: in-dialog requests SHOULD carry Contact.
        if !self.info.local_contact.is_empty() {
            builder = builder.contact(&self.info.local_contact);
        }

        builder
            .build()
            .expect("build_prack: dialog state already validated by caller")
    }

    /// Build an in-dialog UPDATE request (RFC 3311).
    ///
    /// UPDATE is used here for session-timer refresh (RFC 4028); the body is
    /// always empty. When `session_expires` is `Some`, the request advertises
    /// us as the refresher (`refresher=uac`) and adds `Supported: timer`.
    ///
    /// CSeq is incremented as for any in-dialog UAC request. Route headers
    /// from the dialog's route set are emitted per RFC 3261 §12.2.1.1
    /// (loose-route case only; see `build_in_dialog_request`).
    pub fn build_update(&mut self, session_expires: Option<u32>) -> SipRequest {
        let cseq = self.info.next_local_seq();
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());
        let request_uri = self.info.remote_target.clone();
        let routes = self.info.route_set.routes();

        let mut builder = SipRequest::builder()
            .method(Method::Update)
            .uri(&request_uri)
            .via("0.0.0.0", 5060, "UDP", &branch)
            .from(&self.info.local_uri, &self.info.id.local_tag)
            .to(&self.info.remote_uri)
            .to_tag(&self.info.id.remote_tag)
            .call_id(&self.info.id.call_id)
            .cseq(cseq)
            .max_forwards(70)
            .allow(&[
                Method::Invite,
                Method::Ack,
                Method::Bye,
                Method::Cancel,
                Method::Options,
                Method::Prack,
                Method::Update,
            ])
            .route(routes);

        // RFC 3261 §12.2.1.1: in-dialog requests SHOULD carry Contact.
        if !self.info.local_contact.is_empty() {
            builder = builder.contact(&self.info.local_contact);
        }

        if let Some(secs) = session_expires {
            builder = builder
                .session_expires(secs, Some(crate::sip::headers::Refresher::Uac))
                .supported(&["timer"]);
        }

        builder
            .build()
            .expect("build_update: dialog state already validated by caller")
    }

    /// Build an in-dialog re-INVITE (RFC 3261 §14). Used for call hold/resume
    /// where the SDP direction changes (e.g. `a=sendonly` for hold,
    /// `a=sendrecv` for resume).
    ///
    /// CSeq is incremented normally. The SDP body is attached as
    /// `application/sdp`. The caller is responsible for creating the
    /// [`InviteClientTransaction`] and driving it to completion.
    ///
    /// Returns `None` if the dialog is not in `Confirmed` state.
    pub fn build_reinvite(&mut self, sdp_body: &str) -> Option<SipRequest> {
        if self.info.state != DialogState::Confirmed {
            return None;
        }
        let cseq = self.info.next_local_seq();
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());
        let request_uri = self.info.remote_target.clone();
        let routes = self.info.route_set.routes();

        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri(&request_uri)
            .via("0.0.0.0", 5060, "UDP", &branch)
            .from(&self.info.local_uri, &self.info.id.local_tag)
            .to(&self.info.remote_uri)
            .to_tag(&self.info.id.remote_tag)
            .call_id(&self.info.id.call_id)
            .cseq(cseq)
            .max_forwards(70)
            .route(routes)
            .body(sdp_body.as_bytes().to_vec(), "application/sdp");

        if !self.info.local_contact.is_empty() {
            builder = builder.contact(&self.info.local_contact);
        }

        builder.build().ok()
    }

    /// Build a 200 OK response to an inbound in-dialog UPDATE
    /// (RFC 3311 / RFC 4028).
    ///
    /// Echoes the request's `Session-Expires` (with refresher unchanged) when
    /// present, and always advertises our `Allow` set so the peer's future
    /// refreshes can prefer UPDATE over re-INVITE. No body. No state mutation
    /// — deadline updates are handled by the call layer (Phase 4).
    pub fn handle_update(&self, req: &SipRequest) -> SipResponse {
        let mut builder = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .allow(&[
                Method::Invite,
                Method::Ack,
                Method::Bye,
                Method::Cancel,
                Method::Options,
                Method::Prack,
                Method::Update,
            ]);

        // RFC 3261 §12.2.1.1: in-dialog responses also carry Contact so
        // the peer's subsequent in-dialog requests can be addressed
        // directly to us when no Record-Route is present.
        if !self.info.local_contact.is_empty() {
            builder = builder.contact(&self.info.local_contact);
        }

        if let Some(se) = req.session_expires() {
            builder = builder.session_expires(se.delta_seconds, se.refresher);
        }

        builder
            .build()
            .expect("handle_update: response builder should not fail for a copied request")
    }

    /// Build an in-dialog request (RFC 3261 §12.2.1.1).
    ///
    /// Loose-route case (modern carriers, `;lr` always present): the request
    /// URI is the dialog's remote target and the route set is emitted as
    /// `Route` headers in order. Strict routing is not implemented: if a
    /// peer ever advertises a route set without `;lr` we silently emit a
    /// loose-route-shaped request anyway, which violates RFC 3261
    /// §12.2.1.1 against a strict-route peer. The proxy's response is
    /// the only failure signal — there is no local detection or test
    /// for this. Nobody ships strict routing today, so this is
    /// acceptable; revisit if a strict-route peer appears.
    fn build_in_dialog_request(&self, method: Method, cseq: u32) -> Option<SipRequest> {
        self.build_in_dialog_request_with(method, cseq, &[])
    }

    /// Build an in-dialog request with extra headers appended verbatim.
    ///
    /// The extra headers are emitted via `SipRequestBuilder::header(name,
    /// value)` so callers can add things like `Reason:` for an
    /// expiry-driven BYE without bloating the dialog API surface.
    fn build_in_dialog_request_with(
        &self,
        method: Method,
        cseq: u32,
        extra_headers: &[(&str, &str)],
    ) -> Option<SipRequest> {
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());

        // Loose-route: request URI stays as remote target; routes go into
        // Route headers. Empty route set → no Route headers, URI is target.
        let request_uri = self.info.remote_target.clone();
        let routes = self.info.route_set.routes();

        // Build request - swap From/To based on role
        let (from_uri, from_tag, to_uri, to_tag) = match self.role {
            Role::Uac => (
                &self.info.local_uri,
                &self.info.id.local_tag,
                &self.info.remote_uri,
                &self.info.id.remote_tag,
            ),
            Role::Uas => (
                &self.info.local_uri,
                &self.info.id.local_tag,
                &self.info.remote_uri,
                &self.info.id.remote_tag,
            ),
        };

        let mut builder = SipRequest::builder()
            .method(method)
            .uri(&request_uri)
            .via("0.0.0.0", 5060, "UDP", &branch) // Will be filled in by transport
            .from(from_uri, from_tag)
            .to(to_uri)
            .to_tag(to_tag)
            .call_id(&self.info.id.call_id)
            .cseq(cseq)
            .max_forwards(70)
            .route(routes);

        // RFC 3261 §12.2.1.1: in-dialog requests SHOULD carry Contact.
        if !self.info.local_contact.is_empty() {
            builder = builder.contact(&self.info.local_contact);
        }

        for (name, value) in extra_headers {
            builder = builder.header(name, value);
        }

        builder.build().ok()
    }

    /// Build a BYE that carries an extra `Reason:` header (RFC 3326).
    ///
    /// Used by the session-timer expiry path to distinguish a
    /// session-timer-driven BYE from a normal hangup
    /// (`Reason: SIP;cause=200;text="Session timer expired"`).
    /// Returns `None` if the dialog is not in `Confirmed` state.
    pub fn build_bye_with_reason(&mut self, reason: &str) -> Option<SipRequest> {
        if self.info.state != DialogState::Confirmed {
            return None;
        }
        // Compute the would-be next CSeq without committing the bump yet.
        // If the build fails we leave `local_seq` and `state` untouched so
        // we don't leak a wasted CSeq or strand the dialog in `Terminating`.
        let cseq = self.info.local_seq.saturating_add(1);
        let bye = self.build_in_dialog_request_with(Method::Bye, cseq, &[("Reason", reason)])?;
        // Commit on success.
        self.info.local_seq = cseq;
        self.info.state = DialogState::Terminating;
        self.actions.push(Action::SendRequest(bye.clone()));
        Some(bye)
    }

    /// Drain pending actions.
    pub fn poll_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// Mark ACK as sent (UAC side).
    pub fn ack_sent(&mut self) {
        self.ack_sent = true;
    }

    /// Check if ACK has been sent/received.
    pub fn is_ack_complete(&self) -> bool {
        self.ack_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::SipMessage;

    fn parse_request(raw: &str) -> SipRequest {
        let msg = SipMessage::parse(raw.as_bytes()).unwrap();
        msg.as_request().unwrap().clone()
    }

    fn is_rejected_termination(action: &Action) -> bool {
        matches!(
            action,
            Action::Event(Event::Terminated(TerminationReason::Rejected(_)))
        )
    }

    fn create_invite() -> SipRequest {
        SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap()
    }

    fn create_response(request: &SipRequest, code: u16) -> SipResponse {
        SipResponse::builder()
            .status(code, "Test")
            .from_request(request)
            .to_tag("totag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap()
    }

    #[test]
    fn test_uac_dialog_creation() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uac(invite);

        assert_eq!(dialog.role(), Role::Uac);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uac_dialog_established_on_200() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Established))));
    }

    #[test]
    fn test_uac_dialog_rejected() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 486);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_uas_dialog_creation() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uas(invite, "mytag", "sip:me@192.168.1.2:5060").unwrap();

        assert_eq!(dialog.role(), Role::Uas);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uas_dialog_creation_invalid_invite() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let dialog = InviteDialog::new_uas(invite, "mytag", "sip:me@192.168.1.2:5060");
        assert!(dialog.is_none());
    }

    #[test]
    fn test_uas_dialog_established_on_200() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("mytag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_bye_terminates_dialog() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let bye = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKbye")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(bye);
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_uac_dialog_provisional_180() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 180);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uac_dialog_provisional_missing_to_tag() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&invite)
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        assert!(dialog.info().id.remote_tag.is_empty());
    }

    #[test]
    fn test_uac_dialog_session_progress_183() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 183);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::SessionProgress(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_uac_dialog_response_below_100() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 99);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_uac_dialog_ignores_100() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 100);
        dialog.handle_response(response);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_uac_dialog_200_missing_contact() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("totag")
            .build()
            .unwrap();

        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
        assert!(dialog.info().remote_target.is_empty());
    }

    #[test]
    fn test_uas_dialog_handle_response_noop() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_reinvite_ignored_on_stale_cseq() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();
        dialog.info.remote_seq = Some(2);

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_reinvite_triggers_event() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);
        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::ReInvite(_)))));
    }

    #[test]
    fn test_reinvite_ignored_before_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_ack_ignored_for_uac() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(!dialog.ack_sent);
    }

    #[test]
    fn test_ack_ignored_before_confirmed_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(!dialog.ack_sent);
    }

    #[test]
    fn test_cancel_ignored_for_uac() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_cancel_ignored_after_confirmed_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();
        assert_eq!(dialog.state(), DialogState::Confirmed);

        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_ack_sets_ack_sent_for_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(dialog.ack_sent);
    }

    #[test]
    fn test_cancel_terminates_early_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Event(Event::Terminated(TerminationReason::Cancelled))
        )));
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_send_response_rejects_uas_dialog() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 486);
        dialog.send_response(response);

        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| {
            matches!(
                a,
                Action::Event(Event::Terminated(TerminationReason::Rejected(486)))
            )
        }));
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_send_response_provisional_keeps_state() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 180);
        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_send_response_after_confirmed_does_not_reset_state() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let response = create_response(&invite, 200);
        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_send_response_failure_after_confirmed_keeps_state() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let response = create_response(&invite, 486);
        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::SendResponse(_))));
        assert!(!actions.iter().any(is_rejected_termination));
    }

    #[test]
    fn test_send_bye_requires_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite);

        let bye = dialog.send_bye();
        assert!(bye.is_none());
    }

    #[test]
    fn test_send_bye_with_route_set() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        dialog.info.route_set = crate::dialog::state::RouteSet::from_record_route_values(
            &[
                "<sip:proxy1.example.com;lr>".to_string(),
                "<sip:proxy2.example.com;lr>".to_string(),
            ],
            false,
        );

        let bye = dialog.send_bye().expect("BYE must build");
        assert_eq!(dialog.state(), DialogState::Terminating);

        // Round-trip through the wire so we read back exactly what we'll
        // emit — guards against the route headers being dropped at
        // serialization time.
        let bytes = bye.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let routes = parsed_req.route_headers();
        assert_eq!(
            routes.len(),
            2,
            "BYE must carry both Route headers from the dialog's route set"
        );
        assert!(
            routes[0].contains("proxy1"),
            "first Route header should be proxy1, got {:?}",
            routes
        );
        assert!(
            routes[1].contains("proxy2"),
            "second Route header should be proxy2, got {:?}",
            routes
        );
    }

    // Additional tests for better coverage

    #[test]
    fn test_role_debug() {
        assert!(format!("{:?}", Role::Uac).contains("Uac"));
        assert!(format!("{:?}", Role::Uas).contains("Uas"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_role_clone() {
        let role = Role::Uac;
        let cloned = role.clone();
        assert_eq!(role, cloned);
    }

    #[test]
    fn test_role_copy() {
        let role = Role::Uas;
        let copied: Role = role;
        assert_eq!(role, copied);
    }

    #[test]
    fn test_role_eq() {
        assert_eq!(Role::Uac, Role::Uac);
        assert_ne!(Role::Uac, Role::Uas);
    }

    #[test]
    fn test_action_debug() {
        let action = Action::Event(Event::Established);
        let debug = format!("{:?}", action);
        assert!(debug.contains("Event"));
    }

    #[test]
    fn test_action_clone() {
        let action = Action::Event(Event::Established);
        let cloned = action.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Established"));
    }

    #[test]
    fn test_event_debug() {
        let event = Event::Established;
        assert!(format!("{:?}", event).contains("Established"));

        let event = Event::Terminated(TerminationReason::ByeSent);
        assert!(format!("{:?}", event).contains("Terminated"));
    }

    #[test]
    fn test_event_clone() {
        let event = Event::Established;
        let cloned = event.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Established"));
    }

    #[test]
    fn test_termination_reason_debug() {
        assert!(format!("{:?}", TerminationReason::ByeSent).contains("ByeSent"));
        assert!(format!("{:?}", TerminationReason::ByeReceived).contains("ByeReceived"));
        assert!(format!("{:?}", TerminationReason::Rejected(486)).contains("486"));
        assert!(format!("{:?}", TerminationReason::Cancelled).contains("Cancelled"));
        assert!(format!("{:?}", TerminationReason::Error("test".into())).contains("Error"));
    }

    #[test]
    fn test_termination_reason_clone() {
        let reason = TerminationReason::Rejected(404);
        let cloned = reason.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Rejected"));
    }

    #[test]
    fn test_invite_dialog_debug() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uac(invite);
        let debug = format!("{:?}", dialog);
        assert!(debug.contains("InviteDialog"));
    }

    #[test]
    fn test_uac_100_trying_no_early_dialog() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // 100 Trying should not create early dialog
        let response = create_response(&invite, 100);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        // No provisional event for 100 Trying
        assert!(actions.is_empty());
    }

    #[test]
    fn test_uac_180_ringing_creates_early_dialog() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 180);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_uac_183_session_progress() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 183);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::SessionProgress(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_handle_response_uas_ignored() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        // UAS should ignore handle_response
        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_response_confirmed_state() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response.clone());
        dialog.poll_actions();

        // Response in confirmed state (e.g., re-INVITE response)
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_handle_request_reinvite() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        // Re-INVITE
        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::ReInvite(_)))));
    }

    #[test]
    fn test_handle_request_ack_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        // First send 200
        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("mytag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();
        dialog.send_response(response);
        dialog.poll_actions();

        // ACK received
        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(dialog.is_ack_complete());
    }

    #[test]
    fn test_handle_request_cancel() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        // CANCEL in early state
        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Terminated);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Event(Event::Terminated(TerminationReason::Cancelled))
        )));
    }

    #[test]
    fn test_handle_request_invalid_cseq_ignored() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let raw = String::from_utf8(invite.to_bytes().to_vec()).unwrap();
        let raw = raw.replace("CSeq: 1 INVITE", "CSeq: abc INVITE");
        assert!(raw.contains("CSeq: abc INVITE"));
        let parsed = SipMessage::parse(raw.as_bytes()).unwrap();
        let request = parsed.as_request().unwrap().clone();

        dialog.handle_request(request);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_handle_response_other_state_noop() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        dialog.info.state = DialogState::Terminated;
        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Terminated);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_handle_request_other_method() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // Establish dialog
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        // INFO request (other method)
        let info = SipRequest::builder()
            .method(Method::Info)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKinfo")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(info);

        // No state change, no events
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_send_response_uac_ignored() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // UAC should ignore send_response
        let response = create_response(&invite, 200);
        dialog.send_response(response);

        let actions = dialog.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_send_response_provisional() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&invite)
            .to_tag("mytag")
            .build()
            .unwrap();

        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::SendResponse(_))));
    }

    #[test]
    fn test_send_response_failure() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = SipResponse::builder()
            .status(486, "Busy Here")
            .from_request(&invite)
            .to_tag("mytag")
            .build()
            .unwrap();

        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Terminated);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(is_rejected_termination));
    }

    #[test]
    fn test_send_bye_not_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite);

        // Can't send BYE when not confirmed
        let bye = dialog.send_bye();
        assert!(bye.is_none());
    }

    #[test]
    fn test_send_bye_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let bye = dialog.send_bye();
        assert!(bye.is_some());
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    #[test]
    fn test_send_bye_confirmed_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let bye = dialog.send_bye();
        assert!(bye.is_some());
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    #[test]
    fn test_send_bye_build_failure_returns_none() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite);
        dialog.info.state = DialogState::Confirmed;
        dialog.info.remote_target = "sip:alice@[::1".to_string();

        let bye = dialog.send_bye();
        assert!(bye.is_none());
    }

    #[test]
    fn test_ack_sent() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        assert!(!dialog.is_ack_complete());
        dialog.ack_sent();
        assert!(dialog.is_ack_complete());
    }

    #[test]
    fn test_is_terminated() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        assert!(!dialog.is_terminated());

        let response = create_response(&invite, 486);
        dialog.handle_response(response);

        assert!(dialog.is_terminated());
    }

    #[test]
    fn test_accessors() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uac(invite);

        let _id = dialog.id();
        let _info = dialog.info();
        let _role = dialog.role();
        let _state = dialog.state();
    }

    #[test]
    fn test_poll_actions_clears() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(!actions.is_empty());

        // Second poll should be empty
        let actions2 = dialog.poll_actions();
        assert!(actions2.is_empty());
    }

    #[test]
    fn test_cancel_uac_ignored() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // CANCEL should be ignored for UAC role
        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uac_multiple_3xx_codes() {
        for code in [300, 301, 302, 400, 401, 404, 486, 500, 503, 600] {
            let invite = create_invite();
            let mut dialog = InviteDialog::new_uac(invite.clone());

            let response = create_response(&invite, code);
            dialog.handle_response(response);

            assert_eq!(dialog.state(), DialogState::Terminated);
        }
    }

    #[test]
    fn test_uac_multiple_2xx_codes() {
        for code in [200, 202] {
            let invite = create_invite();
            let mut dialog = InviteDialog::new_uac(invite.clone());

            let response = create_response(&invite, code);
            dialog.handle_response(response);

            assert_eq!(dialog.state(), DialogState::Confirmed);
        }
    }

    // ----- Phase 3: PRACK / UPDATE / handle_update --------------------------

    /// Build a confirmed UAC dialog ready for in-dialog requests.
    fn confirmed_uac_dialog() -> InviteDialog {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();
        dialog
    }

    /// Build a 180 Ringing response carrying RSeq + a fresh CSeq value the
    /// caller can pin.
    fn provisional_with_rseq(invite: &SipRequest, code: u16, rseq: u32) -> SipResponse {
        SipResponse::builder()
            .status(code, "Ringing")
            .from_request(invite)
            .to_tag("totag")
            .contact("sip:bob@192.168.1.2:5060")
            .rseq(rseq)
            .build()
            .unwrap()
    }

    #[test]
    fn test_build_prack_carries_rack() {
        // INVITE has CSeq 5 / Method INVITE, response carries RSeq 1.
        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(5)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = provisional_with_rseq(&invite, 180, 1);
        dialog.handle_response(response.clone());
        dialog.poll_actions();

        let prack = dialog.build_prack(&response);

        // Round-trip through the wire to make sure RAck survives serialization.
        let bytes = prack.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let rack = parsed_req.rack().expect("PRACK must carry RAck");
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 5);
        assert_eq!(rack.method, Method::Invite);
    }

    #[test]
    fn test_build_prack_uses_dialog_routing() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = provisional_with_rseq(&invite, 180, 1);
        dialog.handle_response(response.clone());
        dialog.poll_actions();
        let invite_cseq = dialog.info.local_seq;

        let prack = dialog.build_prack(&response);

        assert_eq!(prack.method(), Method::Prack);
        // Dialog routing fields.
        assert_eq!(prack.call_id().unwrap(), "test@example.com");
        assert_eq!(prack.from_tag().unwrap(), "fromtag");
        assert_eq!(prack.to_tag(), Some("totag".to_string()));

        // PRACK gets its OWN CSeq, *not* the INVITE's. The dialog's local_seq
        // started at the INVITE's value and must have advanced.
        let cseq = prack.cseq().unwrap();
        assert_eq!(cseq, invite_cseq + 1);
        assert_eq!(prack.cseq_method().unwrap(), Method::Prack);

        // Fresh branch — must differ from the INVITE's branch.
        let branch = prack.via_branch().unwrap();
        assert!(branch.starts_with("z9hG4bK"));
        assert_ne!(branch, "z9hG4bKtest");
    }

    #[test]
    #[should_panic(expected = "build_prack")]
    fn test_build_prack_debug_asserts_on_no_rseq() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());
        // Response with NO RSeq header.
        let response = create_response(&invite, 180);
        dialog.handle_response(response.clone());
        dialog.poll_actions();

        // Should debug_assert! and panic in test builds.
        let _ = dialog.build_prack(&response);
    }

    #[test]
    fn test_build_update_session_expires_some() {
        let mut dialog = confirmed_uac_dialog();
        let update = dialog.build_update(Some(1800));

        // Round-trip via the wire so we read back exactly what we'll emit.
        let bytes = update.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        assert_eq!(parsed_req.method(), Method::Update);

        let se = parsed_req
            .session_expires()
            .expect("Session-Expires must be present when secs is Some");
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(
            se.refresher,
            Some(crate::sip::headers::Refresher::Uac),
            "refresher should be UAC when we are sending UPDATE"
        );

        let supported = parsed_req
            .supported()
            .expect("Supported: timer must be present");
        assert!(
            supported.0.iter().any(|t| t == "timer"),
            "Supported must include the 'timer' option-tag, got {:?}",
            supported.0
        );
    }

    #[test]
    fn test_build_update_session_expires_none() {
        let mut dialog = confirmed_uac_dialog();
        let update = dialog.build_update(None);

        let bytes = update.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        assert_eq!(parsed_req.method(), Method::Update);
        assert!(
            parsed_req.session_expires().is_none(),
            "no Session-Expires when caller passes None"
        );
        let has_timer_supported = parsed_req
            .supported()
            .map(|s| s.0.iter().any(|t| t == "timer"))
            .unwrap_or(false);
        assert!(
            !has_timer_supported,
            "no 'Supported: timer' when session_expires is None"
        );
    }

    #[test]
    fn test_build_update_increments_cseq() {
        let mut dialog = confirmed_uac_dialog();
        let update1 = dialog.build_update(Some(1800));
        let update2 = dialog.build_update(Some(1800));

        let cseq1 = update1.cseq().unwrap();
        let cseq2 = update2.cseq().unwrap();
        assert_eq!(
            cseq2,
            cseq1 + 1,
            "consecutive UPDATEs must use consecutive CSeq values"
        );
        assert_eq!(update1.cseq_method().unwrap(), Method::Update);
        assert_eq!(update2.cseq_method().unwrap(), Method::Update);
    }

    /// Build an inbound UPDATE request carrying optional Session-Expires.
    fn inbound_update(
        session_expires: Option<(u32, crate::sip::headers::Refresher)>,
    ) -> SipRequest {
        let mut builder = SipRequest::builder()
            .method(Method::Update)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKupd")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(42);
        if let Some((secs, refresher)) = session_expires {
            builder = builder.session_expires(secs, Some(refresher));
        }
        builder.build().unwrap()
    }

    #[test]
    fn test_handle_update_returns_200() {
        let dialog = confirmed_uac_dialog();
        let req = inbound_update(None);

        let resp = dialog.handle_update(&req);
        assert_eq!(resp.status_code(), 200);

        // Echoed dialog identifiers come from the request.
        assert_eq!(resp.call_id().unwrap(), req.call_id().unwrap());
        assert_eq!(resp.from_tag().unwrap(), req.from_tag().unwrap());
        assert_eq!(resp.to_tag(), req.to_tag());
        assert_eq!(resp.cseq().unwrap(), req.cseq().unwrap());
        assert_eq!(resp.cseq_method().unwrap(), Method::Update);
    }

    #[test]
    fn test_handle_update_echoes_session_expires() {
        let dialog = confirmed_uac_dialog();
        let req = inbound_update(Some((1800, crate::sip::headers::Refresher::Uac)));

        let resp = dialog.handle_update(&req);

        // Round-trip through the wire to confirm Session-Expires survives.
        let bytes = resp.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();

        let se = parsed_resp
            .session_expires()
            .expect("Session-Expires must be echoed when present in request");
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(crate::sip::headers::Refresher::Uac));
    }

    #[test]
    fn test_handle_update_no_session_expires_when_request_has_none() {
        let dialog = confirmed_uac_dialog();
        let req = inbound_update(None);

        let resp = dialog.handle_update(&req);
        let bytes = resp.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();

        assert!(
            parsed_resp.session_expires().is_none(),
            "no Session-Expires on response when request had none"
        );
    }

    /// Outbound UPDATE must advertise the seven Allow methods from the HLD.
    /// Round-trips through the wire so we know we read what we emit.
    #[test]
    fn test_build_update_emits_allow_header() {
        let mut dialog = confirmed_uac_dialog();
        let update = dialog.build_update(Some(1800));

        let bytes = update.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let allow = parsed_req
            .allow()
            .expect("UPDATE must advertise Allow per HLD");
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
            ],
            "Allow must list all seven methods in order"
        );
    }

    /// 200 OK on inbound UPDATE must carry the same Allow set.
    #[test]
    fn test_handle_update_emits_allow_header() {
        let dialog = confirmed_uac_dialog();
        let req = inbound_update(None);
        let resp = dialog.handle_update(&req);

        let bytes = resp.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();

        let allow = parsed_resp
            .allow()
            .expect("200 OK to UPDATE must advertise Allow");
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
            ],
        );
    }

    /// Outbound UPDATE must emit Route headers in dialog order (loose
    /// routing, RFC 3261 §12.2.1.1).
    #[test]
    fn test_build_update_emits_route_headers() {
        let mut dialog = confirmed_uac_dialog();
        dialog.info.route_set = crate::dialog::state::RouteSet::from_record_route_values(
            &[
                "<sip:proxy1.example.com;lr>".to_string(),
                "<sip:proxy2.example.com;lr>".to_string(),
            ],
            false,
        );

        let update = dialog.build_update(Some(1800));
        let bytes = update.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let routes = parsed_req.route_headers();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("proxy1"));
        assert!(routes[1].contains("proxy2"));
    }

    /// PRACK must carry Contact (RFC 3261 §12.2.1.1).
    #[test]
    fn test_build_prack_emits_contact() {
        let invite = create_invite(); // Contact: <sip:alice@192.168.1.1:5060>
        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = provisional_with_rseq(&invite, 180, 1);
        dialog.handle_response(response.clone());
        dialog.poll_actions();

        let prack = dialog.build_prack(&response);
        let bytes = prack.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();
        let contact = parsed_req
            .contact_uri()
            .expect("PRACK must carry Contact (RFC 3261 §12.2.1.1)");
        assert!(contact.to_string().contains("alice"));
    }

    /// 200 OK to inbound UPDATE must carry Contact.
    #[test]
    fn test_handle_update_emits_contact() {
        let dialog = confirmed_uac_dialog();
        let req = inbound_update(None);
        let resp = dialog.handle_update(&req);

        let bytes = resp.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();
        let contact = parsed_resp
            .contact_uri()
            .expect("200 OK to UPDATE must carry Contact");
        assert!(contact.to_string().contains("alice"));
    }

    /// `from_dialog_info` reconstructs an InviteDialog from already-known
    /// dialog state without the original INVITE — used by the session
    /// layer to thread Phase 4 in-dialog requests through Phase 3
    /// builders.
    #[test]
    fn test_from_dialog_info_builds_routed_update() {
        use crate::dialog::state::{DialogId, DialogInfo, DialogState, RouteSet};
        let info = DialogInfo {
            id: DialogId::new("call-x", "ftag", "ttag"),
            state: DialogState::Confirmed,
            local_seq: 5,
            remote_seq: None,
            local_uri: "sip:alice@example.com".into(),
            remote_uri: "sip:bob@example.com".into(),
            remote_target: "sip:bob@10.0.0.2:5060".into(),
            local_contact: "sip:alice@10.0.0.1:5060".into(),
            route_set: RouteSet::from_record_route_values(
                &[
                    "<sip:proxy1.example.com;lr>".to_string(),
                    "<sip:proxy2.example.com;lr>".to_string(),
                ],
                false,
            ),
            secure: false,
        };
        let mut dialog = InviteDialog::from_dialog_info(info, Role::Uac);

        let update = dialog.build_update(Some(1800));
        let bytes = update.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        // Routes from the route set.
        let routes = parsed_req.route_headers();
        assert_eq!(
            routes.len(),
            2,
            "UPDATE must carry Route headers from the dialog"
        );
        assert!(routes[0].contains("proxy1"));

        // Contact from local_contact.
        let contact = parsed_req.contact_uri().expect("UPDATE must carry Contact");
        assert!(contact.to_string().contains("10.0.0.1"));

        // Request URI is the remote target.
        assert!(parsed_req.uri().to_string().contains("10.0.0.2"));

        // CSeq advanced past local_seq.
        assert_eq!(parsed_req.cseq().unwrap(), 6);
    }

    /// `build_bye_with_reason` carries Route, Contact, and the Reason
    /// header. Used by the manager's session-timer expiry path.
    #[test]
    fn test_build_bye_with_reason() {
        use crate::dialog::state::{DialogId, DialogInfo, DialogState, RouteSet};
        let info = DialogInfo {
            id: DialogId::new("call-x", "ftag", "ttag"),
            state: DialogState::Confirmed,
            local_seq: 5,
            remote_seq: None,
            local_uri: "sip:alice@example.com".into(),
            remote_uri: "sip:bob@example.com".into(),
            remote_target: "sip:bob@10.0.0.2:5060".into(),
            local_contact: "sip:alice@10.0.0.1:5060".into(),
            route_set: RouteSet::from_record_route_values(
                &["<sip:proxy.example.com;lr>".to_string()],
                false,
            ),
            secure: false,
        };
        let mut dialog = InviteDialog::from_dialog_info(info, Role::Uac);

        let bye = dialog
            .build_bye_with_reason(r#"SIP;cause=200;text="Session timer expired""#)
            .expect("BYE built");
        let bytes = bye.to_bytes();
        let raw = String::from_utf8(bytes.to_vec()).expect("utf8");

        // Reason header survives.
        assert!(
            raw.contains(r#"Reason: SIP;cause=200;text="Session timer expired""#),
            "BYE must carry the Reason header verbatim, got:\n{}",
            raw
        );

        // Route + Contact survive.
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();
        assert_eq!(parsed_req.route_headers().len(), 1);
        assert!(parsed_req.contact_uri().is_some());
        assert_eq!(parsed_req.method(), Method::Bye);
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    /// `build_bye_with_reason` rejects when the dialog isn't Confirmed.
    #[test]
    fn test_build_bye_with_reason_requires_confirmed() {
        use crate::dialog::state::{DialogId, DialogInfo, DialogState, RouteSet};
        let info = DialogInfo {
            id: DialogId::new("call-x", "ftag", "ttag"),
            state: DialogState::Early,
            local_seq: 1,
            remote_seq: None,
            local_uri: "sip:alice@example.com".into(),
            remote_uri: "sip:bob@example.com".into(),
            remote_target: "sip:bob@10.0.0.2:5060".into(),
            local_contact: "sip:alice@10.0.0.1:5060".into(),
            route_set: RouteSet::default(),
            secure: false,
        };
        let mut dialog = InviteDialog::from_dialog_info(info, Role::Uac);
        // `from_dialog_info` always sets Confirmed — overwrite to Early
        // for this negative case.
        dialog.info.state = DialogState::Early;
        assert!(dialog.build_bye_with_reason("test").is_none());
    }

    /// PRACK must also carry Route headers from the dialog's route set.
    #[test]
    fn test_build_prack_emits_route_headers() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = provisional_with_rseq(&invite, 180, 1);
        dialog.handle_response(response.clone());
        dialog.poll_actions();
        dialog.info.route_set = crate::dialog::state::RouteSet::from_record_route_values(
            &[
                "<sip:proxy1.example.com;lr>".to_string(),
                "<sip:proxy2.example.com;lr>".to_string(),
            ],
            false,
        );

        let prack = dialog.build_prack(&response);
        let bytes = prack.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let routes = parsed_req.route_headers();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("proxy1"));
        assert!(routes[1].contains("proxy2"));
    }
}

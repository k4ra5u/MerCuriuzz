use std::borrow::Cow;
use std::collections::HashSet;

use crate::inputstruct::h3_input::{QpackFieldRep, QpackHeaderBlock};
use h3i::actions::h3::StreamEventType;
use h3i::client::connection_summary::ConnectionCloseDetails;
use h3i::frame::{EnrichedHeaders, H3iFrame};
use libafl::inputs::UsesInput;
use libafl::observers::{DifferentialObserver, Observer, ObserversTuple};
use libafl::{executors::ExitKind, state::UsesState};
use libafl_bolts::tuples::{Handle, Handled, MatchNameRef};
use libafl_bolts::{Error, Named};
use quiche::h3::frame::Frame as QFrame;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum H3TerminalKind {
    None,
    Finished,
    Reset,
    ConnectionClose,
}

impl Default for H3TerminalKind {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3RequestSemantic {
    pub stream_id: u64,
    pub saw_headers: bool,
    pub headers_count: u32,
    pub status_code: Option<u16>,
    pub invalid_status: bool,
    pub saw_data: bool,
    pub data_frame_count: u32,
    pub body_len: u64,
    pub saw_reset: bool,
    pub saw_finished: bool,
    pub saw_trailers: bool,
    pub first_headers_batch: Option<u32>,
    pub first_data_batch: Option<u32>,
    pub first_terminal_batch: Option<u32>,
    pub terminal_kind: H3TerminalKind,
}

impl H3RequestSemantic {
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            saw_headers: false,
            headers_count: 0,
            status_code: None,
            invalid_status: false,
            saw_data: false,
            data_frame_count: 0,
            body_len: 0,
            saw_reset: false,
            saw_finished: false,
            saw_trailers: false,
            first_headers_batch: None,
            first_data_batch: None,
            first_terminal_batch: None,
            terminal_kind: H3TerminalKind::None,
        }
    }

    pub fn has_any_observable_response(&self) -> bool {
        self.saw_headers || self.saw_data || self.saw_reset || self.saw_finished
    }

    pub fn mark_connection_close(&mut self, batch_index: u32) {
        if self.terminal_kind == H3TerminalKind::None {
            self.terminal_kind = H3TerminalKind::ConnectionClose;
            self.first_terminal_batch.get_or_insert(batch_index);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct H3CloseSemantic {
    pub peer_close: bool,
    pub local_close: bool,
    pub timed_out: bool,
    pub peer_is_app: Option<bool>,
    pub peer_error_code: Option<u64>,
    pub peer_reason: Option<String>,
    pub local_is_app: Option<bool>,
    pub local_error_code: Option<u64>,
    pub local_reason: Option<String>,
    pub first_close_batch: Option<u32>,
}

impl H3CloseSemantic {
    pub fn has_any_close(&self) -> bool {
        self.peer_close || self.local_close
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3QpackRequestProgress {
    pub stream_id: u64,
    pub requires_dynamic_state: bool,
    pub required_insert_count: u64,
    pub base: u64,
    pub first_visible_response_batch: Option<u32>,
    pub first_terminal_batch: Option<u32>,
    pub stalled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct H3RunSemanticSummary {
    pub requests: Vec<H3RequestSemantic>,
    pub close: H3CloseSemantic,
    pub qpack_requests: Vec<H3QpackRequestProgress>,
    pub total_h3_frames: usize,
    pub total_batches: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H3SemanticObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub summary: H3RunSemanticSummary,
}

impl H3SemanticObserver {
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            summary: H3RunSemanticSummary::default(),
        }
    }

    pub fn set_summary(&mut self, summary: H3RunSemanticSummary) {
        self.summary = summary;
    }

    pub fn summary(&self) -> &H3RunSemanticSummary {
        &self.summary
    }
}

impl<S> Observer<S> for H3SemanticObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote {
            self.summary = H3RunSemanticSummary::default();
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for H3SemanticObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialH3SemanticObserver {
    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<H3SemanticObserver>,
    second_ob_ref: Handle<H3SemanticObserver>,
    first_observer: H3SemanticObserver,
    second_observer: H3SemanticObserver,
    name: Cow<'static, str>,
}

impl DifferentialH3SemanticObserver {
    pub fn new(first: &mut H3SemanticObserver, second: &mut H3SemanticObserver) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            second_ob_ref: second.handle(),
            first_observer: H3SemanticObserver::new("fake"),
            second_observer: H3SemanticObserver::new("fake"),
        }
    }

    pub fn first_summary(&self) -> &H3RunSemanticSummary {
        &self.first_observer.summary
    }

    pub fn second_summary(&self) -> &H3RunSemanticSummary {
        &self.second_observer.summary
    }
}

impl Named for DifferentialH3SemanticObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialH3SemanticObserver where S: UsesInput {}

impl<OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for DifferentialH3SemanticObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.first_observer = H3SemanticObserver::new("fake");
        self.second_observer = H3SemanticObserver::new("fake");
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        Ok(())
    }

    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        let first_observer = observers.get(&self.first_ob_ref).unwrap();
        self.first_observer = first_observer.clone();
        Ok(())
    }

    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        let second_observer = observers.get(&self.second_ob_ref).unwrap();
        self.second_observer = second_observer.clone();
        Ok(())
    }
}

pub fn requires_dynamic_state(block: &QpackHeaderBlock) -> bool {
    block.required_insert_count > 0
        || block.fields.iter().any(|field| {
            matches!(
                field,
                QpackFieldRep::Indexed {
                    is_static: false,
                    ..
                }
                    | QpackFieldRep::IndexedPostBase { .. }
                    | QpackFieldRep::LiteralWithNameRef {
                        is_static: false,
                        ..
                    }
                    | QpackFieldRep::LiteralWithPostBaseNameRef { .. }
            )
        })
}

pub fn apply_headers_to_request(
    request: &mut H3RequestSemantic,
    headers: &EnrichedHeaders,
    batch_index: u32,
) {
    request.saw_headers = true;
    request.headers_count += 1;
    request.saw_trailers = request.headers_count > 1;
    request.first_headers_batch.get_or_insert(batch_index);

    if let Some(status) = headers.status_code() {
        match std::str::from_utf8(status)
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
        {
            Some(code) => {
                if request.status_code.is_none() {
                    request.status_code = Some(code);
                }
            }
            None => request.invalid_status = true,
        }
    }
}

pub fn apply_frame_to_request(
    request: &mut H3RequestSemantic,
    frame: &H3iFrame,
    batch_index: u32,
) {
    match frame {
        H3iFrame::Headers(headers) => apply_headers_to_request(request, headers, batch_index),
        H3iFrame::QuicheH3(QFrame::Data { payload }) => {
            request.saw_data = true;
            request.data_frame_count += 1;
            request.body_len += payload.len() as u64;
            request.first_data_batch.get_or_insert(batch_index);
        }
        H3iFrame::ResetStream(_) => {
            request.saw_reset = true;
            request.terminal_kind = H3TerminalKind::Reset;
            request.first_terminal_batch.get_or_insert(batch_index);
        }
        _ => {}
    }
}

pub fn apply_stream_event_to_request(
    request: &mut H3RequestSemantic,
    event_type: StreamEventType,
    batch_index: u32,
    reset_streams: &HashSet<u64>,
) {
    match event_type {
        StreamEventType::Headers => {
            request.first_headers_batch.get_or_insert(batch_index);
        }
        StreamEventType::Data => {
            request.first_data_batch.get_or_insert(batch_index);
        }
        StreamEventType::Finished => {
            if !reset_streams.contains(&request.stream_id) && !request.saw_reset {
                request.saw_finished = true;
                if request.terminal_kind == H3TerminalKind::None {
                    request.terminal_kind = H3TerminalKind::Finished;
                }
            }
            request.first_terminal_batch.get_or_insert(batch_index);
        }
    }
}

pub fn update_close_semantic(
    close: &mut H3CloseSemantic,
    details: &ConnectionCloseDetails,
    batch_index: u32,
) {
    if let Some(peer_error) = details.peer_error() {
        close.peer_close = true;
        close.peer_is_app = Some(peer_error.is_app);
        close.peer_error_code = Some(peer_error.error_code);
        close.peer_reason = Some(String::from_utf8_lossy(&peer_error.reason).into_owned());
        close.first_close_batch.get_or_insert(batch_index);
    }

    if let Some(local_error) = details.local_error() {
        close.local_close = true;
        close.local_is_app = Some(local_error.is_app);
        close.local_error_code = Some(local_error.error_code);
        close.local_reason = Some(String::from_utf8_lossy(&local_error.reason).into_owned());
        close.first_close_batch.get_or_insert(batch_index);
    }

    if details.timed_out {
        close.timed_out = true;
        close.first_close_batch.get_or_insert(batch_index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::Header;

    #[test]
    fn h3_requires_dynamic_state_variants() {
        let mut block = QpackHeaderBlock::default();
        assert!(!requires_dynamic_state(&block));

        block.required_insert_count = 1;
        assert!(requires_dynamic_state(&block));

        block.required_insert_count = 0;
        block.fields = vec![QpackFieldRep::Indexed {
            is_static: false,
            index: 1,
        }];
        assert!(requires_dynamic_state(&block));

        block.fields = vec![QpackFieldRep::IndexedPostBase { index: 1 }];
        assert!(requires_dynamic_state(&block));

        block.fields = vec![QpackFieldRep::LiteralWithNameRef {
            is_static: false,
            name_index: 1,
            value: b"x".to_vec(),
        }];
        assert!(requires_dynamic_state(&block));

        block.fields = vec![QpackFieldRep::LiteralWithPostBaseNameRef {
            index: 1,
            value: b"x".to_vec(),
        }];
        assert!(requires_dynamic_state(&block));

        block.fields = vec![QpackFieldRep::Indexed {
            is_static: true,
            index: 1,
        }];
        assert!(!requires_dynamic_state(&block));
    }

    #[test]
    fn h3_request_semantic_headers_and_data() {
        let mut request = H3RequestSemantic::new(0);
        let headers = EnrichedHeaders::from(vec![Header::new(b":status", b"200")]);
        apply_frame_to_request(&mut request, &H3iFrame::Headers(headers), 1);
        apply_frame_to_request(
            &mut request,
            &H3iFrame::QuicheH3(QFrame::Data {
                payload: b"hello".to_vec(),
            }),
            2,
        );

        assert!(request.saw_headers);
        assert_eq!(request.status_code, Some(200));
        assert!(request.saw_data);
        assert_eq!(request.body_len, 5);
        assert_eq!(request.first_headers_batch, Some(1));
        assert_eq!(request.first_data_batch, Some(2));
    }

    #[test]
    fn h3_request_semantic_trailers_and_invalid_status() {
        let mut request = H3RequestSemantic::new(0);
        let first = EnrichedHeaders::from(vec![Header::new(b":status", b"bad")]);
        let trailers = EnrichedHeaders::from(vec![Header::new(b"x-test", b"1")]);

        apply_frame_to_request(&mut request, &H3iFrame::Headers(first), 1);
        apply_frame_to_request(&mut request, &H3iFrame::Headers(trailers), 2);

        assert!(request.invalid_status);
        assert_eq!(request.headers_count, 2);
        assert!(request.saw_trailers);
    }

    #[test]
    fn h3_request_semantic_reset_and_finished() {
        let mut request = H3RequestSemantic::new(0);
        apply_frame_to_request(
            &mut request,
            &H3iFrame::ResetStream(h3i::frame::ResetStream {
                stream_id: 0,
                error_code: 256,
            }),
            3,
        );
        let mut reset_streams = HashSet::new();
        reset_streams.insert(0);
        apply_stream_event_to_request(
            &mut request,
            StreamEventType::Finished,
            3,
            &reset_streams,
        );

        assert!(request.saw_reset);
        assert!(!request.saw_finished);
        assert_eq!(request.terminal_kind, H3TerminalKind::Reset);
        assert_eq!(request.first_terminal_batch, Some(3));
    }
}

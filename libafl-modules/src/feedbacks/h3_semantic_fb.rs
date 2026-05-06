use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};

use crate::observers::*;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::observers::ObserversTuple;
use libafl::state::State;
use libafl::{
    executors::ExitKind, feedbacks::Feedback, inputs::UsesInput, observers::Observer,
    state::UsesState,
};
use libafl_bolts::tuples::{Handle, Handled, MatchNameRef};
use libafl_bolts::{Error, Named};
use log::warn;
use serde::{Deserialize, Serialize};

fn batch_diff_at_least(left: Option<u32>, right: Option<u32>, threshold: u32) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.abs_diff(right) >= threshold,
        _ => false,
    }
}

fn request_map(summary: &H3RunSemanticSummary) -> HashMap<u64, H3RequestSemantic> {
    summary
        .requests
        .iter()
        .cloned()
        .map(|request| (request.stream_id, request))
        .collect()
}

fn qpack_map(summary: &H3RunSemanticSummary) -> HashMap<u64, H3QpackRequestProgress> {
    summary
        .qpack_requests
        .iter()
        .cloned()
        .map(|request| (request.stream_id, request))
        .collect()
}

fn terminal_kind_for_stream(summary: &H3RunSemanticSummary, stream_id: u64) -> H3TerminalKind {
    summary
        .requests
        .iter()
        .find(|request| request.stream_id == stream_id)
        .map(|request| request.terminal_kind.clone())
        .unwrap_or(H3TerminalKind::None)
}

fn find_response_mismatch(
    first: &H3RunSemanticSummary,
    second: &H3RunSemanticSummary,
) -> Option<String> {
    let first_map = request_map(first);
    let second_map = request_map(second);
    let stream_ids = first_map
        .keys()
        .chain(second_map.keys())
        .copied()
        .collect::<BTreeSet<_>>();

    for stream_id in stream_ids {
        let first_req = first_map
            .get(&stream_id)
            .cloned()
            .unwrap_or_else(|| H3RequestSemantic::new(stream_id));
        let second_req = second_map
            .get(&stream_id)
            .cloned()
            .unwrap_or_else(|| H3RequestSemantic::new(stream_id));

        if !first_req.has_any_observable_response()
            && !second_req.has_any_observable_response()
            && first_req.terminal_kind == H3TerminalKind::None
            && second_req.terminal_kind == H3TerminalKind::None
        {
            continue;
        }

        if first_req.saw_headers != second_req.saw_headers {
            return Some(format!("stream:{stream_id}:headers_presence"));
        }

        if first_req.status_code != second_req.status_code
            || first_req.invalid_status
            || second_req.invalid_status
        {
            return Some(format!(
                "stream:{stream_id}:status:{:?}:{:?}:{}:{}",
                first_req.status_code,
                second_req.status_code,
                first_req.invalid_status,
                second_req.invalid_status
            ));
        }

        if first_req.saw_data != second_req.saw_data {
            return Some(format!("stream:{stream_id}:data_presence"));
        }

        if first_req.body_len != second_req.body_len {
            return Some(format!(
                "stream:{stream_id}:body_len:{}:{}",
                first_req.body_len, second_req.body_len
            ));
        }

        if first_req.saw_reset != second_req.saw_reset {
            return Some(format!("stream:{stream_id}:reset_presence"));
        }

        if first_req.saw_finished != second_req.saw_finished {
            return Some(format!("stream:{stream_id}:finished_presence"));
        }

        if first_req.terminal_kind != second_req.terminal_kind {
            return Some(format!(
                "stream:{stream_id}:terminal:{:?}:{:?}",
                first_req.terminal_kind, second_req.terminal_kind
            ));
        }

        if batch_diff_at_least(
            first_req.first_headers_batch,
            second_req.first_headers_batch,
            3,
        ) {
            return Some(format!(
                "stream:{stream_id}:first_headers_batch:{:?}:{:?}",
                first_req.first_headers_batch, second_req.first_headers_batch
            ));
        }

        if batch_diff_at_least(
            first_req.first_terminal_batch,
            second_req.first_terminal_batch,
            3,
        ) {
            return Some(format!(
                "stream:{stream_id}:first_terminal_batch:{:?}:{:?}",
                first_req.first_terminal_batch, second_req.first_terminal_batch
            ));
        }
    }

    None
}

fn non_empty_reason(reason: &Option<String>) -> Option<&str> {
    reason.as_deref().filter(|value| !value.is_empty())
}

fn find_close_mismatch(first: &H3CloseSemantic, second: &H3CloseSemantic) -> Option<String> {
    if first.has_any_close() != second.has_any_close() {
        return Some(format!(
            "close_presence:{}:{}",
            first.has_any_close(),
            second.has_any_close()
        ));
    }

    if first.peer_close != second.peer_close {
        return Some(format!("peer_close:{}:{}", first.peer_close, second.peer_close));
    }

    if first.local_close != second.local_close {
        return Some(format!(
            "local_close:{}:{}",
            first.local_close, second.local_close
        ));
    }

    if first.timed_out != second.timed_out {
        return Some(format!("timed_out:{}:{}", first.timed_out, second.timed_out));
    }

    if first.peer_close && second.peer_close {
        if first.peer_is_app != second.peer_is_app {
            return Some(format!(
                "peer_is_app:{:?}:{:?}",
                first.peer_is_app, second.peer_is_app
            ));
        }

        if first.peer_error_code != second.peer_error_code {
            return Some(format!(
                "peer_error_code:{:?}:{:?}",
                first.peer_error_code, second.peer_error_code
            ));
        }

        if let (Some(first_reason), Some(second_reason)) = (
            non_empty_reason(&first.peer_reason),
            non_empty_reason(&second.peer_reason),
        ) {
            if first_reason != second_reason {
                return Some(format!("peer_reason:{first_reason}:{second_reason}"));
            }
        }
    }

    if first.local_close && second.local_close {
        if first.local_is_app != second.local_is_app {
            return Some(format!(
                "local_is_app:{:?}:{:?}",
                first.local_is_app, second.local_is_app
            ));
        }

        if first.local_error_code != second.local_error_code {
            return Some(format!(
                "local_error_code:{:?}:{:?}",
                first.local_error_code, second.local_error_code
            ));
        }

        if let (Some(first_reason), Some(second_reason)) = (
            non_empty_reason(&first.local_reason),
            non_empty_reason(&second.local_reason),
        ) {
            if first_reason != second_reason {
                return Some(format!("local_reason:{first_reason}:{second_reason}"));
            }
        }
    }

    if batch_diff_at_least(first.first_close_batch, second.first_close_batch, 3) {
        return Some(format!(
            "first_close_batch:{:?}:{:?}",
            first.first_close_batch, second.first_close_batch
        ));
    }

    None
}

fn qpack_terminal_mismatch(first: &H3TerminalKind, second: &H3TerminalKind) -> bool {
    matches!(first, H3TerminalKind::Reset | H3TerminalKind::ConnectionClose)
        && matches!(second, H3TerminalKind::Finished | H3TerminalKind::None)
        || matches!(second, H3TerminalKind::Reset | H3TerminalKind::ConnectionClose)
            && matches!(first, H3TerminalKind::Finished | H3TerminalKind::None)
}

fn find_qpack_mismatch(
    first: &H3RunSemanticSummary,
    second: &H3RunSemanticSummary,
) -> Option<String> {
    let first_map = qpack_map(first);
    let second_map = qpack_map(second);
    let stream_ids = first_map
        .keys()
        .chain(second_map.keys())
        .copied()
        .collect::<BTreeSet<_>>();

    for stream_id in stream_ids {
        let Some(first_qpack) = first_map.get(&stream_id) else {
            return Some(format!("stream:{stream_id}:missing_first_qpack"));
        };
        let Some(second_qpack) = second_map.get(&stream_id) else {
            return Some(format!("stream:{stream_id}:missing_second_qpack"));
        };

        if first_qpack.first_visible_response_batch.is_some()
            != second_qpack.first_visible_response_batch.is_some()
        {
            return Some(format!(
                "stream:{stream_id}:visible_response:{:?}:{:?}",
                first_qpack.first_visible_response_batch, second_qpack.first_visible_response_batch
            ));
        }

        let first_terminal = terminal_kind_for_stream(first, stream_id);
        let second_terminal = terminal_kind_for_stream(second, stream_id);
        if qpack_terminal_mismatch(&first_terminal, &second_terminal) {
            return Some(format!(
                "stream:{stream_id}:terminal:{:?}:{:?}",
                first_terminal, second_terminal
            ));
        }

        if batch_diff_at_least(
            first_qpack.first_visible_response_batch,
            second_qpack.first_visible_response_batch,
            3,
        ) {
            return Some(format!(
                "stream:{stream_id}:visible_batch:{:?}:{:?}",
                first_qpack.first_visible_response_batch,
                second_qpack.first_visible_response_batch
            ));
        }

        if first_qpack.stalled != second_qpack.stalled {
            return Some(format!(
                "stream:{stream_id}:stalled:{}:{}",
                first_qpack.stalled, second_qpack.stalled
            ));
        }
    }

    None
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct H3ResponseSemanticDedup {
    key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct H3CloseSemanticDedup {
    key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct H3QpackProgressDedup {
    key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct H3ResponseSemanticFeedback {
    diff_h3_semantic_ob_handle: Handle<DifferentialH3SemanticObserver>,
    history_object: Vec<H3ResponseSemanticDedup>,
}

impl H3ResponseSemanticFeedback {
    #[must_use]
    pub fn new(diff_h3_semantic_ob: &DifferentialH3SemanticObserver) -> Self {
        Self {
            diff_h3_semantic_ob_handle: diff_h3_semantic_ob.handle(),
            history_object: Vec::new(),
        }
    }
}

impl Named for H3ResponseSemanticFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ResponseSemanticFeedback");
        &NAME
    }
}

impl<S> Feedback<S> for H3ResponseSemanticFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let diff_h3_semantic_ob = observers.get(&self.diff_h3_semantic_ob_handle).unwrap();
        if let Some(key) = find_response_mismatch(
            diff_h3_semantic_ob.first_summary(),
            diff_h3_semantic_ob.second_summary(),
        ) {
            if self.history_object.iter().any(|history| history.key == key) {
                return Ok(false);
            }

            warn!("h3 response semantic mismatch: {}", key);
            self.history_object.push(H3ResponseSemanticDedup { key });
            return Ok(true);
        }

        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct H3CloseSemanticFeedback {
    diff_h3_semantic_ob_handle: Handle<DifferentialH3SemanticObserver>,
    history_object: Vec<H3CloseSemanticDedup>,
}

impl H3CloseSemanticFeedback {
    #[must_use]
    pub fn new(diff_h3_semantic_ob: &DifferentialH3SemanticObserver) -> Self {
        Self {
            diff_h3_semantic_ob_handle: diff_h3_semantic_ob.handle(),
            history_object: Vec::new(),
        }
    }
}

impl Named for H3CloseSemanticFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3CloseSemanticFeedback");
        &NAME
    }
}

impl<S> Feedback<S> for H3CloseSemanticFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let diff_h3_semantic_ob = observers.get(&self.diff_h3_semantic_ob_handle).unwrap();
        if let Some(key) = find_close_mismatch(
            &diff_h3_semantic_ob.first_summary().close,
            &diff_h3_semantic_ob.second_summary().close,
        ) {
            if self.history_object.iter().any(|history| history.key == key) {
                return Ok(false);
            }

            warn!("h3 close semantic mismatch: {}", key);
            self.history_object.push(H3CloseSemanticDedup { key });
            return Ok(true);
        }

        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct H3QpackProgressFeedback {
    diff_h3_semantic_ob_handle: Handle<DifferentialH3SemanticObserver>,
    history_object: Vec<H3QpackProgressDedup>,
}

impl H3QpackProgressFeedback {
    #[must_use]
    pub fn new(diff_h3_semantic_ob: &DifferentialH3SemanticObserver) -> Self {
        Self {
            diff_h3_semantic_ob_handle: diff_h3_semantic_ob.handle(),
            history_object: Vec::new(),
        }
    }
}

impl Named for H3QpackProgressFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackProgressFeedback");
        &NAME
    }
}

impl<S> Feedback<S> for H3QpackProgressFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let diff_h3_semantic_ob = observers.get(&self.diff_h3_semantic_ob_handle).unwrap();
        if let Some(key) = find_qpack_mismatch(
            diff_h3_semantic_ob.first_summary(),
            diff_h3_semantic_ob.second_summary(),
        ) {
            if self.history_object.iter().any(|history| history.key == key) {
                return Ok(false);
            }

            warn!("h3 qpack progress mismatch: {}", key);
            self.history_object.push(H3QpackProgressDedup { key });
            return Ok(true);
        }

        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(stream_id: u64) -> H3RequestSemantic {
        H3RequestSemantic::new(stream_id)
    }

    fn summary_with_request(request: H3RequestSemantic) -> H3RunSemanticSummary {
        H3RunSemanticSummary {
            requests: vec![request],
            ..Default::default()
        }
    }

    #[test]
    fn h3_response_mismatch_status_code() {
        let mut first = request(0);
        first.saw_headers = true;
        first.status_code = Some(200);

        let mut second = request(0);
        second.saw_headers = true;
        second.status_code = Some(500);

        assert!(find_response_mismatch(
            &summary_with_request(first),
            &summary_with_request(second)
        )
        .is_some());
    }

    #[test]
    fn h3_response_mismatch_body_len() {
        let mut first = request(0);
        first.saw_data = true;
        first.body_len = 10;

        let mut second = request(0);
        second.saw_data = true;
        second.body_len = 20;

        assert!(find_response_mismatch(
            &summary_with_request(first),
            &summary_with_request(second)
        )
        .is_some());
    }

    #[test]
    fn h3_response_mismatch_reset_vs_finished() {
        let mut first = request(0);
        first.saw_reset = true;
        first.terminal_kind = H3TerminalKind::Reset;

        let mut second = request(0);
        second.saw_finished = true;
        second.terminal_kind = H3TerminalKind::Finished;

        assert!(find_response_mismatch(
            &summary_with_request(first),
            &summary_with_request(second)
        )
        .is_some());
    }

    #[test]
    fn h3_close_mismatch_peer_application_vs_transport() {
        let first = H3CloseSemantic {
            peer_close: true,
            peer_is_app: Some(true),
            peer_error_code: Some(1),
            ..Default::default()
        };
        let second = H3CloseSemantic {
            peer_close: true,
            peer_is_app: Some(false),
            peer_error_code: Some(1),
            ..Default::default()
        };

        assert!(find_close_mismatch(&first, &second).is_some());
    }

    #[test]
    fn h3_close_mismatch_timeout() {
        let first = H3CloseSemantic {
            timed_out: true,
            ..Default::default()
        };
        let second = H3CloseSemantic::default();

        assert!(find_close_mismatch(&first, &second).is_some());
    }

    #[test]
    fn h3_qpack_mismatch_response_presence() {
        let first = H3RunSemanticSummary {
            qpack_requests: vec![H3QpackRequestProgress {
                stream_id: 0,
                requires_dynamic_state: true,
                required_insert_count: 1,
                base: 0,
                first_visible_response_batch: Some(1),
                first_terminal_batch: None,
                stalled: false,
            }],
            ..Default::default()
        };
        let second = H3RunSemanticSummary {
            qpack_requests: vec![H3QpackRequestProgress {
                stream_id: 0,
                requires_dynamic_state: true,
                required_insert_count: 1,
                base: 0,
                first_visible_response_batch: None,
                first_terminal_batch: None,
                stalled: false,
            }],
            ..Default::default()
        };

        assert!(find_qpack_mismatch(&first, &second).is_some());
    }

    #[test]
    fn h3_qpack_mismatch_response_batch_skew() {
        let first = H3RunSemanticSummary {
            qpack_requests: vec![H3QpackRequestProgress {
                stream_id: 0,
                requires_dynamic_state: true,
                required_insert_count: 1,
                base: 0,
                first_visible_response_batch: Some(1),
                first_terminal_batch: None,
                stalled: false,
            }],
            ..Default::default()
        };
        let second = H3RunSemanticSummary {
            qpack_requests: vec![H3QpackRequestProgress {
                stream_id: 0,
                requires_dynamic_state: true,
                required_insert_count: 1,
                base: 0,
                first_visible_response_batch: Some(4),
                first_terminal_batch: None,
                stalled: false,
            }],
            ..Default::default()
        };

        assert!(find_qpack_mismatch(&first, &second).is_some());
    }
}

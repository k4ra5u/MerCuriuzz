use std::borrow::Cow;

use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::inputs::HasMutatorBytes;
use libafl::observers::ObserversTuple;
use libafl::state::State;
use libafl::HasMetadata;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::Handle;
use libafl_bolts::tuples::Handled;
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::{Error, Named,tuples::MatchName};
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState, feedbacks::Feedback};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::observers::*;

/// Nop feedback that annotates execution time in the new testcase, if any
/// for this Feedback, the testcase is never interesting (use with an OR).
/// It decides, if the given [`RecvPktNumObserver`] value of a run is interesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecvPktNumFeedback {
    observer_handle: Handle<RecvPktNumObserver>,
}

impl<S> Feedback<S> for RecvPktNumFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = _observers.get(&self.observer_handle).unwrap();
        let recv_pkts = observer.get_recv_pkts();
        let send_pkts = observer.get_send_pkts();
        if recv_pkts > 0 && (recv_pkts as f64) / (send_pkts as f64) > 0.9 {
            info!("RecvPktNum Interesting testcase");
            return Ok(true);
        }

        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        let observer = observers.get(&self.observer_handle).unwrap();
        let recv_pkts = observer.get_recv_pkts();
        let send_pkts = observer.get_send_pkts();
        if recv_pkts > 0 && send_pkts > 0 && recv_pkts / send_pkts > 1 {
            info!("Appending RecvPktNum Interesting testcase");
            // TODO: 根据产生回复的帧判断是否是有用的测试用例，以及如何对测试用例进行剪枝
        }
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Named for RecvPktNumFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl RecvPktNumFeedback {
    /// Creates a new [`RecvPktNumFeedback`], deciding if the given [`RecvPktNumObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &RecvPktNumObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
        }
    }
}


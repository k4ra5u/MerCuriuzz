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
/// It decides, if the given [`CPUUsageObserver`] value of a run is interesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CPUUsageFeedback {
    observer_handle: Handle<CPUUsageObserver>,
}

impl<S> Feedback<S> for CPUUsageFeedback
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
        let final_cpu_usage = observer.final_cpu_usage;
        let avg_cpu = observer.final_based_cpu_usage;
        warn!("CPUUsageFeedback: avg_cpu: {:.2}%", avg_cpu);
        if (final_cpu_usage > observer.based_cpu_usage +30.0) || (avg_cpu > observer.based_cpu_usage + 30.0) {
            info!("CPUUsageFeedback: Interesting testcase");
            return Ok(true);
        }

        Ok(false)
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

impl Named for CPUUsageFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl CPUUsageFeedback {
    /// Creates a new [`CPUUsageFeedback`], deciding if the given [`CPUUsageObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &CPUUsageObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
        }
    }
}


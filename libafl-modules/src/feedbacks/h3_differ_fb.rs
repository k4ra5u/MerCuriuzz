use core::error;
use std::borrow::Cow;
use std::io::Write;
use std::mem;
use std::process::Command;

use crate::inputstruct::*;
use crate::observers::*;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::inputs::HasMutatorBytes;
use libafl::observers::ObserversTuple;
use libafl::state::State;
use libafl::HasMetadata;
use libafl::{
    executors::ExitKind, feedbacks::Feedback, inputs::UsesInput, observers::Observer,
    state::UsesState,
};
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::Handle;
use libafl_bolts::tuples::Handled;
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::{tuples::MatchName, Error, Named};
use log::error;
use log::info;
use log::warn;
use quiche::{frame, packet, Connection, ConnectionId, Header};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Deduplication {
    pub cc_time_state: CCTimesObserverState,
    // pub ack_state: ACKObserverState,
    pub match_nums: usize,
}

impl Deduplication {
    /// Creates a new [`Deduplication`] with the given name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cc_time_state: CCTimesObserverState::OK,
            // ack_state: ACKObserverState::OK,
            match_nums: 0,
        }
    }
}
impl PartialEq for Deduplication {
    fn eq(&self, other: &Self) -> bool {
        self.cc_time_state == other.cc_time_state
        // self.ack_state == other.ack_state
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct H3DifferFeedback {
    diff_cc_ob_handle: Handle<DifferentialCCTimesObserver>,
    // diff_ack_ob_handle: Handle<DifferentialACKRangeObserver>,
    history_object: Vec<Deduplication>,
}

impl<S> Feedback<S> for H3DifferFeedback
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
        let diff_cc_ob = _observers.get(&self.diff_cc_ob_handle).unwrap();
        // let diff_ack_ob = _observers.get(&self.diff_ack_ob_handle).unwrap();

        let mut interesting_flag = false;
        let diff_cc_ob_judge_type = diff_cc_ob.judge_type();
        if *diff_cc_ob_judge_type != CCTimesObserverState::OK
            && *diff_cc_ob_judge_type != CCTimesObserverState::MistypeCCReason
            && *diff_cc_ob_judge_type != CCTimesObserverState::MistypePkn
        {
            warn!("vul of CC testcase: {:?}", diff_cc_ob_judge_type);
            interesting_flag = true;
        }
        // if *diff_ack_ob.judge_type() != ACKObserverState::OK {
        //     warn!("vul of ACK Range testcase: {:?}",diff_ack_ob.judge_type());
        //     interesting_flag = true;
        // }
        if interesting_flag {
            let mut new_deduplication = Deduplication::new();
            new_deduplication.match_nums = 1;
            new_deduplication.cc_time_state = diff_cc_ob.judge_type().clone();
            // new_deduplication.ack_state = diff_ack_ob.judge_type().clone();
            for old_object in self.history_object.iter_mut() {
                if old_object == &new_deduplication {
                    if old_object.match_nums > 0 {
                        warn!("Deduplication testcase");
                        return Ok(false);
                    } else {
                        old_object.match_nums += 1;
                        error!("Deduplicate but interesting testcase");
                        return Ok(true);
                    }
                }
            }
            self.history_object.push(new_deduplication);
            error!("Interesting testcase");

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

impl Named for H3DifferFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3DifferFeedback");
        &NAME
        // self.observer_handle.name()
    }
}

impl H3DifferFeedback {
    /// Creates a new [`H3DifferFeedback`]
    #[must_use]
    pub fn new(diff_cc_ob: &DifferentialCCTimesObserver) -> Self {
        Self {
            diff_cc_ob_handle: diff_cc_ob.handle(),
            // diff_ack_ob_handle: diff_ack_ob.handle(),
            history_object: Vec::new(),
        }
    }
}

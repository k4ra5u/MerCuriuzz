use std::borrow::Cow;
use std::io::Write;
use std::sync::{Arc, Mutex};

use std::process::Command;

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
use crate::observers::PcapRecord;
use ctrlc;

/// Nop feedback that annotates execution time in the new testcase, if any
/// for this Feedback, the testcase is never interesting (use with an OR).
/// It decides, if the given [`MiscObserver`] value of a run is interesting.


#[derive(Serialize, Deserialize, Debug)]
pub struct MiscFeedback {
    observer_handle: Handle<MiscObserver>,
    srand_seed:u32,
}

impl<S> Feedback<S> for MiscFeedback
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
        self.srand_seed = observer.srand_seed;
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
        // let _ = Command::new("sudo")
        // .arg("rm")
        // .arg("-f")
        // .arg(&self.pcap_path)
        // .output() // 捕获 `touch` 的输出
        // .expect("Failed to create empty pcap file");

        // info!("delete pcap file: {:?}",&self.pcap_path);
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Named for MiscFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl MiscFeedback {
    /// Creates a new [`MiscFeedback`], deciding if the given [`MiscObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &MiscObserver) -> Self  {
        let instance = Self {
            observer_handle: observer.handle(),
            srand_seed: 0,
        };
        instance
    }

}


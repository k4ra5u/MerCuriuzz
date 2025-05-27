use std::borrow::Cow;

use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::{Handle, Handled};
use libafl_bolts::{Error, Named,tuples::MatchName,tuples::MatchNameRef};
use log::info;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use libafl::{
    observers::{DifferentialObserver, Observer, ObserversTuple},
};
use crate::inputstruct::*;

use super::HasRecordRemote;

#[derive(Debug, Serialize,Clone, Deserialize,PartialEq)]
pub enum CCTimesObserverState {
    OK,
    FirstCC,
    SecondCC,
    MistypeErrorCode,
    MistypeCCReason,
}


#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct CCTimesObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub pkn: u64,
    pub error_code: u64,
    pub frame_type: u64,
    pub reason: String,

}

impl CCTimesObserver {
    /// Creates a new [`CPUUsageObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            pkn: 0,
            error_code: 0,
            frame_type : 0,
            reason: String::new(),
        }
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote(){
            self.pkn = 0;
            self.error_code = 0;
            self.frame_type = 0;
            self.reason = String::new();
        }

        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // info!("post_exec of CCTimesObserver: {:?}", self);
        Ok(())
    }

}

impl<S> Observer<S> for CCTimesObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote(){
            self.pkn = 0;
            self.error_code = 0;
            self.frame_type = 0;
            self.reason = String::new();
        }

        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // info!("post_exec of CCTimesObserver: {:?}", self);
        Ok(())
    }
}

impl Named for CCTimesObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialCCTimesObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<CCTimesObserver>,
    first_observer: CCTimesObserver,
    second_observer: CCTimesObserver,
    second_ob_ref: Handle<CCTimesObserver>,
    name: Cow<'static, str>,
    judge_type: CCTimesObserverState,
}

impl DifferentialCCTimesObserver {
    /// Create a new `DifferentialCCTimesObserver`.
    pub fn new (
        first: &mut CCTimesObserver,
        second: &mut CCTimesObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            first_observer: CCTimesObserver::new("fake"),
            second_observer: CCTimesObserver::new("fake"),
            second_ob_ref: second.handle(),
            judge_type: CCTimesObserverState::OK,
        }
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn second_name(&self) -> &str {
        &self.second_name
    }

    pub fn judge_type(&self) -> &CCTimesObserverState {
        &self.judge_type
    }
    pub fn perform_judge (&mut self) {
        if self.first_observer.pkn ==0 && self.second_observer.pkn == 0 {
            self.judge_type = CCTimesObserverState::OK;
        } else if self.first_observer.pkn == 0 && self.second_observer.pkn != 0 {
            self.judge_type = CCTimesObserverState::SecondCC;
        } else if self.first_observer.pkn != 0 && self.second_observer.pkn == 0 {
            self.judge_type = CCTimesObserverState::FirstCC;
        } else if self.first_observer.pkn != 0 && self.second_observer.pkn != 0 {
            if self.first_observer.error_code != self.second_observer.error_code {
                self.judge_type = CCTimesObserverState::MistypeErrorCode;
            } else if self.first_observer.reason.len() !=0 && self.second_observer.reason.len() != 0 {
                if self.first_observer.reason == self.second_observer.reason {
                    self.judge_type = CCTimesObserverState::OK;
                } else {
                    self.judge_type = CCTimesObserverState::MistypeCCReason;
                }
            } else {
                self.judge_type = CCTimesObserverState::OK;
            } 
        }
        info!("FirCCOb:{:?}", self.first_observer);
        info!("SecCCOb:{:?}", self.second_observer);
        self.first_observer = CCTimesObserver::new("fake");
        self.second_observer = CCTimesObserver::new("fake");
    }
}

impl Named for DifferentialCCTimesObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialCCTimesObserver where S: UsesInput {}

impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialCCTimesObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = CCTimesObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = CCTimesObserverState::OK;
        Ok(())
    }
    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        let first_observer = observers.get(&self.first_ob_ref).unwrap();
        self.first_observer = first_observer.clone();
        if self.second_observer.name() != "fake" {
            self.perform_judge();
        }
        Ok(())
    }
    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        let second_observer = observers.get(&self.second_ob_ref).unwrap();
        self.second_observer = second_observer.clone();
        if self.first_observer.name() != "fake" {
            self.perform_judge();
        }
        Ok(())
    }
}
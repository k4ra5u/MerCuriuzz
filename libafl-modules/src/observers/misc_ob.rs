use std::borrow::Cow;
use std::time::Duration;
use std::net::ToSocketAddrs;

use std::io::prelude::*;

use std::rc::Rc;

use std::cell::RefCell;


use libafl::inputs::HasMutatorBytes;
use libafl::prelude::{DifferentialObserver, ObserversTuple};
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::Handle;
use libafl_bolts::{Error, Named,tuples::MatchName, rands::Rand,};
use log::{debug, error, info};
use ring::rand::*;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState,state::HasRand};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::misc::*;
use std::thread::sleep;
use libafl_bolts::tuples::Handled;
use libafl_bolts::tuples::MatchNameRef;

use super::HasRecordRemote;

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct MiscObserver {
    pub name: Cow<'static, str>,
    pub record_remote: bool,
    pub srand_seed: u32,
}

impl MiscObserver {
    /// Creates a new [`MiscObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            srand_seed: 0,
        }
    }

    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.srand_seed = 0;
        }
        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // info!("post_exec of MiscObserver: {:?}", self);
        Ok(())
    }
}

impl<S> Observer<S> for MiscObserver
where
    S: UsesInput + HasRand,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.srand_seed = 0;
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // info!("post_exec of MiscObserver: {:?}", self);
        Ok(())
    }
}

impl Named for MiscObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}


#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialMiscObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<MiscObserver>,
    first_observer: MiscObserver,
    second_observer: MiscObserver,
    second_ob_ref: Handle<MiscObserver>,
    name: Cow<'static, str>,
    pub srand_seed: u32,
}

impl DifferentialMiscObserver {
    /// Create a new `DifferentialMiscObserver`.
    pub fn new (
        first: &mut MiscObserver,
        second: &mut MiscObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            first_observer: MiscObserver::new("fake"),
            second_observer: MiscObserver::new("fake"),
            second_ob_ref: second.handle(),
            srand_seed: 0,

        }
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn second_name(&self) -> &str {
        &self.second_name
    }

    pub fn perform_judge (&mut self) {
        self.srand_seed = self.first_observer.srand_seed;
        info!("Fir:{:?}", self.first_observer);
        info!("Sec:{:?}", self.second_observer);
        self.first_observer = MiscObserver::new("fake");
        self.second_observer = MiscObserver::new("fake");

    }
}

impl Named for DifferentialMiscObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialMiscObserver where S: UsesInput {}

impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialMiscObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
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
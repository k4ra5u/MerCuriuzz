use std::borrow::Cow;
use std::time::Duration;
use std::net::ToSocketAddrs;

use std::io::prelude::*;

use std::rc::Rc;

use std::cell::RefCell;


use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::{Error, Named,tuples::MatchName, rands::Rand,};
use log::{debug, error, info};
use rand::Rng;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState,state::HasRand};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::misc::*;
use std::thread::sleep;

use super::HasRecordRemote;

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct UCBObserver {
    pub name: Cow<'static, str>,
    pub record_remote: bool,
    pub reward: f64,
}

impl UCBObserver {
    /// Creates a new [`CPUUsageObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            reward: 0.0,
        }
    }
    pub fn get_reward(&self) -> f64 {
        self.reward
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.reward = 0.0;
        }
        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            debug!("post_exec of UCBObserver: {:?}", self);
            let mut rng = rand::thread_rng();
            let rand_0: u64 = rng.gen_range(0..10000);
            let rand_0_1 = rand_0 as f64 / 10000.0;
            self.reward = rand_0_1;
        }

        Ok(())
    }
}

impl<S> Observer<S> for UCBObserver
where
    S: UsesInput + HasRand,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.reward = 0.0;
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            debug!("post_exec of UCBObserver: {:?}", self);
            let rand_0 = _state.rand_mut().below(10000);
            let rand_0_1 = rand_0 as f64 / 10000.0;
            self.reward = rand_0_1;
        }

        Ok(())
    }
}

impl Named for UCBObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

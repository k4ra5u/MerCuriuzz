use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::borrow::Cow;
use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::inputstruct::*;
use chrono::{DateTime, FixedOffset, TimeDelta, TimeZone, Utc};
use libafl::inputs::HasMutatorBytes;
use libafl::observers::{DifferentialObserver, Observer, ObserversTuple};
use libafl::{executors::ExitKind, inputs::UsesInput, state::UsesState};
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::{Handle, Handled};
use libafl_bolts::{tuples::MatchName, tuples::MatchNameRef, Error, Named};
use log::info;
use quiche::{frame, packet, Connection, ConnectionId, Header};
use serde::{Deserialize, Serialize};

const QUIC_SIZE: usize = 0x100000; //128MB
const OB_RESPONSE_SIZE: usize = 0x100000; //16MB
const MAP_SIZE: usize = 1048260;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShmemIOObserver {
    pub name: Cow<'static, str>,
    pub shmem_io_ptr: OwnedMutPtr<u8>,
}

impl ShmemIOObserver {
    pub fn new<S>(name: S, raw_shmem: *mut u8) -> ShmemIOObserver
    where
        S: Into<String>,
    {
        ShmemIOObserver {
            name: Cow::from(name.into()),
            shmem_io_ptr: OwnedMutPtr::Ptr(raw_shmem),
        }
    }

    pub fn io_shmem_ref(&self) -> &u8 {
        unsafe { &*(self.shmem_io_ptr.as_ref()) }
        // unsafe { &(self.quic_response_ptr.as_ref() as *const u8)  }
    }

    pub fn io_shmem_mut(&mut self) -> &mut u8 {
        unsafe { &mut *(self.shmem_io_ptr.as_mut() as *mut u8) }
    }
    pub fn clear(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.io_shmem_mut(), 0, QUIC_SIZE);
        }
    }
    pub fn write_bytes(&mut self, data: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.io_shmem_mut() as *mut u8).add(1),
                data.len(),
            );
        }
        *self.io_shmem_mut() = 1 as u8;
    }
}

impl<S> Observer<S> for ShmemIOObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.io_shmem_mut();
        Ok(())
    }
}

impl Named for ShmemIOObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

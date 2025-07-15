use std::borrow::Cow;
use std::cmp::max;
use std::fs::File;
use std::io::{self, BufRead};
use std::iter::FusedIterator;
use std::path::{absolute, Path};
use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::{Handle, Handled};
use libafl_bolts::{Error, Named,tuples::MatchName,tuples::MatchNameRef};
use log::{info, warn};
use num_traits::abs;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use libafl::{
    observers::{DifferentialObserver, Observer, ObserversTuple},
};
use crate::inputstruct::*;

use super::HasRecordRemote;

#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub enum MemObserverState {
    OK,
    FirMemLeak,
    SecMemLeak,
    BothMemLeak,
}


#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct MemObserver {
    pub name: Cow<'static, str>,
    pub record_remote: bool,
    pub pid: u32,
    pub initial_mem: i64,
    pub before_mem: i64,
    pub after_mem: i64,
    pub allowed_mem: i64,
}

impl MemObserver {
    /// Creates a new [`MemObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            pid: 0,
            initial_mem: 0,
            before_mem: 0,
            after_mem: 0,
            allowed_mem: 0,
        }
    }
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn set_init_mem(&mut self, initial_mem: i64) {
        self.initial_mem = initial_mem;
    }
    pub fn set_before_mem(&mut self, before_mem: i64) {
        self.before_mem = before_mem;
    }
    pub fn set_after_mem(&mut self, after_mem: i64) {
        self.after_mem = after_mem;
    }
    pub fn parse_rw_memory_range(&self,line: &str) -> Option<(i64, i64)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
    
        let range = parts[0];
        let permissions = parts[1];
    
        if !permissions.contains('w') {
            return None;
        }
    
        let range_parts: Vec<&str> = range.split('-').collect();
        if range_parts.len() != 2 {
            return None;
        }
    
        let start = i64::from_str_radix(range_parts[0], 16).ok()?;
        let end = i64::from_str_radix(range_parts[1], 16).ok()?;
    
        Some((start, end))
    }
    
    pub fn judge_proc_exist(&self) -> bool {
        let pid = self.pid;
        let ps_pid = format!("/proc/{}", pid);
        let path = absolute(&ps_pid).unwrap();
        path.exists()
    }

    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.before_mem = 0;
            // self.pid = 0;
            if self.pid != 0 {
                let map_file = format!("/proc/{}/maps", self.pid);
                let file = match File::open(map_file){
                    Ok(file) => file,
                    Err(err) => {
                        warn!("Failed to open memory map file: {}", err);
                        self.before_mem = 0;
                        self.initial_mem = 0;
                        self.allowed_mem = 0;
                        self.after_mem = 0;
                        self.pid = 0;

                        return Ok(());
                    }
                };
                let reader = io::BufReader::new(file);
                for cur_line in reader.lines() {
                    let line = cur_line?;
                    if let Some((start, end)) = self.parse_rw_memory_range(&line) {
                        self.before_mem += end - start;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            if !self.judge_proc_exist() {
                self.after_mem = self.before_mem;
                return Ok(());
            }
            self.after_mem = 0;
            let map_file = format!("/proc/{}/maps", self.pid);
            let file = match File::open(map_file){
                    Ok(file) => file,
                    Err(err) => {
                        warn!("Failed to open memory map file: {}", err);
                        self.before_mem = 0;
                        self.initial_mem = 0;
                        self.allowed_mem = 0;
                        self.after_mem = 0;
                        self.pid = 0;
                        
                        return Ok(());
                    }
                };
            let reader = io::BufReader::new(file);
            for cur_line in reader.lines() {
                let line = cur_line?;
                if let Some((start, end)) = self.parse_rw_memory_range(&line) {
                    self.after_mem += end - start;
                }
            }
            if self.allowed_mem == 0 {
                self.allowed_mem = max(self.after_mem - self.initial_mem, 50000);
            }
            // info!("post_exec of MemObserver: {:?}", self);
        }

        Ok(())
    }
}

impl<S> Observer<S> for MemObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.before_mem = 0;
            // self.pid = 0;
            if self.pid != 0 {
                let map_file = format!("/proc/{}/maps", self.pid);
                let file = match File::open(map_file){
                    Ok(file) => file,
                    Err(err) => {
                        warn!("Failed to open memory map file: {}", err);
                        self.before_mem = 0;
                        self.initial_mem = 0;
                        self.allowed_mem = 0;
                        self.after_mem = 0;
                        self.pid = 0;
                        
                        return Ok(());
                    }
                };
                let reader = io::BufReader::new(file);
                for cur_line in reader.lines() {
                    let line = cur_line?;
                    if let Some((start, end)) = self.parse_rw_memory_range(&line) {
                        self.before_mem += end - start;
                    }
                }
            }
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
            if !self.judge_proc_exist() {
                self.after_mem = 0;
                self.pid = 0;
                self.initial_mem = 0;
                self.allowed_mem = 0;
                self.before_mem = 0;
                return Ok(());
            }
            self.after_mem = 0;
            let map_file = format!("/proc/{}/maps", self.pid);
            let file = match File::open(map_file){
                Ok(file) => file,
                Err(err) => {
                    warn!("Failed to open memory map file: {}", err);
                    self.before_mem = 0;
                    self.initial_mem = 0;
                    self.allowed_mem = 0;
                    self.after_mem = 0;
                    self.pid = 0;
                    
                    return Ok(());
                }
            };
            let reader = io::BufReader::new(file);
            for cur_line in reader.lines() {
                let line = cur_line?;
                if let Some((start, end)) = self.parse_rw_memory_range(&line) {
                    self.after_mem += end - start;
                }
            }
            if self.allowed_mem == 0 {
                self.allowed_mem = max(self.after_mem - self.initial_mem, 50000);
            }
            // info!("post_exec of MemObserver: {:?}", self);
        }

        Ok(())
    }
}

impl Named for MemObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialMemObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<MemObserver>,
    first_observer: MemObserver,
    second_observer: MemObserver,
    second_ob_ref: Handle<MemObserver>,
    name: Cow<'static, str>,
    judge_type: MemObserverState,
}

impl DifferentialMemObserver {
    /// Create a new `MemObserver.
    pub fn new (
        first: &mut MemObserver,
        second: &mut MemObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            first_observer: MemObserver::new("fake"),
            second_observer: MemObserver::new("fake"),
            second_ob_ref: second.handle(),
            judge_type: MemObserverState::OK,
        }
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn second_name(&self) -> &str {
        &self.second_name
    }

    pub fn judge_type(&self) -> &MemObserverState {
        &self.judge_type
    }
    pub fn perform_judge (&mut self) {
        let mut first_mem_rev = false;
        let mut second_mem_rev = false;
        if self.first_observer.after_mem > self.first_observer.before_mem {
            let first_mem_diff = self.first_observer.after_mem - self.first_observer.before_mem;
            // let first_running_diff = self.first_observer.before_mem - self.first_observer.initial_mem;
            // if first_mem_diff as f64 / first_running_diff as f64 > 1.0 {
            if first_mem_diff > self.first_observer.allowed_mem*3 {
                self.judge_type = MemObserverState::FirMemLeak;
            }
            // }
        } else {
            first_mem_rev = true;
        }
        if self.second_observer.after_mem > self.second_observer.before_mem {
            let second_mem_diff = self.second_observer.after_mem - self.second_observer.before_mem;
            // let second_running_diff = self.second_observer.before_mem - self.second_observer.initial_mem;
            // if second_mem_diff as f64 / second_running_diff as f64 > 1.0 {
            if second_mem_diff > self.second_observer.allowed_mem*3 {
                self.judge_type = MemObserverState::SecMemLeak;
            }
            // }
        } else {
            second_mem_rev = true;
        }   
        if !first_mem_rev && !second_mem_rev {
            let first_mem_diff = self.first_observer.after_mem - self.first_observer.before_mem;
            let second_mem_diff = self.second_observer.after_mem - self.second_observer.before_mem;
            let mem_abs = abs(first_mem_diff - second_mem_diff);
            let allow_mem_diff_abs = abs(self.first_observer.allowed_mem - self.second_observer.allowed_mem);
            if first_mem_diff > second_mem_diff {
                if mem_abs > 500000 || (mem_abs > 3*allow_mem_diff_abs) {
                    if self.judge_type == MemObserverState::SecMemLeak {
                        self.judge_type = MemObserverState::BothMemLeak;
                    }
                    else {
                        self.judge_type = MemObserverState::FirMemLeak;
                    }
                }
            }
            if second_mem_diff > first_mem_diff {
                if mem_abs > 500000 || (mem_abs > 3*allow_mem_diff_abs) {
                    if self.judge_type == MemObserverState::FirMemLeak {
                        self.judge_type = MemObserverState::BothMemLeak;
                    }
                    else {
                        self.judge_type = MemObserverState::SecMemLeak;
                    }
                }
            }
        }
        info!("FirMemOb:{:?}", self.first_observer);
        info!("SecMemOb:{:?}", self.second_observer);
        self.first_observer = MemObserver::new("fake");
        self.second_observer = MemObserver::new("fake");
    }
}

impl Named for DifferentialMemObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialMemObserver where S: UsesInput {}

impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialMemObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = MemObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = MemObserverState::OK;
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
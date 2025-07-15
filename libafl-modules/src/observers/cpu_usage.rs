use std::borrow::Cow;
use std::path::absolute;
use std::time::Duration;

use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::{Handle, Handled};
use libafl_bolts::{Error, Named,tuples::MatchName,tuples::MatchNameRef};
use libc::abs;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput, state::UsesState};
use libafl::{
    observers::{DifferentialObserver, Observer, ObserversTuple},
};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::misc::*;
use std::thread::sleep;

use super::HasRecordRemote;

#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub enum CPUUsageObserverState {
    OK,
    FirstCPU,
    SecondCPU,
    BothCPU,
}

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct CPUUsageObserver {
    pub name: Cow<'static, str>,
    pub record_remote: bool,
    pub pid: u32,
    pub cpu_ids: Vec<u32>,
    pub based_cpu_usage: f64,
    pub final_based_cpu_usage: f64,
    pub final_cpu_usage: f64,
    pub prev_process_time: (u64,u64),
    pub prev_cpu_times: Vec<(u64,u64)>,
    pub record_times: u64,
    pub record_cpu_usages: Vec<f64>,


}

impl CPUUsageObserver {
    /// Creates a new [`CPUUsageObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            record_remote: false,
            pid: 0,
            name: Cow::from(name),
            cpu_ids: Vec::new(),
            based_cpu_usage: 0.0,
            final_based_cpu_usage: 0.0,
            final_cpu_usage: 0.0,
            prev_process_time: (0,0),
            prev_cpu_times: Vec::new(),
            record_times: 0,
            record_cpu_usages: Vec::new(),

        }
    }

    pub fn get_cur_cpu_usage(&mut self) -> f64 {
        // 获取初始的进程和指定CPU核心的时间
        let pid = self.pid;
        let cpu_ids = self.cpu_ids.clone();

        // 获取当前的进程和指定CPU核心的时间
        let curr_process_time = get_process_cpu_time(pid).expect(&format!("Failed to get process CPU time:{}", pid));
        let curr_cpu_times = get_cpu_time(&cpu_ids).expect("Failed to get CPU core times");

        // 克隆 curr_cpu_times 以避免移动
        let curr_cpu_times_clone = curr_cpu_times.clone();

        // 计算 CPU 占用率
        let cpu_usage = calculate_cpu_usage(
            self.prev_process_time,
            curr_process_time,
            self.prev_cpu_times.clone(),
            curr_cpu_times_clone,
        );

        // 更新 prev_process_time 和 prev_cpu_times
        self.prev_process_time = curr_process_time;
        self.prev_cpu_times = curr_cpu_times;

        debug!(
            "Process {} CPU Usage on cores {:?}: {:.2}%",
            pid, cpu_ids, cpu_usage
        );

        cpu_usage
    }

    pub fn get_cur_cpu_usage_imut(&self) -> f64 {
        // 获取初始的进程和指定CPU核心的时间
        let pid = self.pid;
        let cpu_ids = self.cpu_ids.clone();

        // 获取当前的进程和指定CPU核心的时间
        // let curr_process_time = get_process_cpu_time(pid).expect( &format!("Failed to get process CPU time:{}", pid));
        let curr_process_time = match get_process_cpu_time(pid) {
            Some(time) => time,
            None => {
                debug!("Failed to get process CPU time: {}", pid);
                return 0.0;
            }
        };
        // let curr_cpu_times = get_cpu_time(&cpu_ids).expect("Failed to get CPU core times");
        let curr_cpu_times = match get_cpu_time(&cpu_ids) {
            Some(times) => times,
            None => {
                debug!("Failed to get CPU core times");
                return 0.0;
            }
        };

        // 克隆 curr_cpu_times 以避免移动
        let curr_cpu_times_clone = curr_cpu_times.clone();

        // 计算 CPU 占用率
        let cpu_usage = calculate_cpu_usage(
            self.prev_process_time,
            curr_process_time,
            self.prev_cpu_times.clone(),
            curr_cpu_times_clone,
        );

        // 更新 prev_process_time 和 prev_cpu_times
        // self.prev_process_time = curr_process_time;
        // self.prev_cpu_times = curr_cpu_times;

        debug!(
            "Process {} CPU Usage on cores {:?}: {:.2}%",
            pid, cpu_ids, cpu_usage
        );

        cpu_usage
    }
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn add_cpu_id(&mut self, cpu_id: u32) {
        self.cpu_ids.push(cpu_id);
    }
    pub fn set_based_cpu_usage(&mut self, based_cpu_usage: f64) {
        self.based_cpu_usage = based_cpu_usage;
    }
    pub fn set_final_based_cpu_usage(&mut self, final_based_cpu_usage: f64) {
        self.final_based_cpu_usage = final_based_cpu_usage;
    }
    pub fn set_final_cpu_usage(&mut self, final_cpu_usage: f64) {
        self.final_cpu_usage = final_cpu_usage;
    }
    pub fn add_frame_record_times(&mut self) {
        self.record_times += 1;
    }
    pub fn add_record_cpu_usage(&mut self, record_cpu_usage: f64) {
        self.record_cpu_usages.push(record_cpu_usage);
    }
    pub fn record_cur_cpu_usage(&mut self) {
        let cur_cpu_usage = self.get_cur_cpu_usage();
        self.add_record_cpu_usage(cur_cpu_usage);
        self.add_frame_record_times();
    }
    pub fn judge_proc_exist(&self) -> bool {
        let pid = self.pid;
        let ps_pid = format!("/proc/{}", pid);
        let path = absolute(&ps_pid).unwrap();
        path.exists()
    }

    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            // self.cpu_ids = Vec::new();
            self.based_cpu_usage = 0.0;
            self.final_based_cpu_usage = 0.0;
            self.record_times = 0;
            self.record_cpu_usages.clear();
        }
        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            if !self.judge_proc_exist() {
                self.set_final_based_cpu_usage(0.0);
                self.set_final_cpu_usage(0.0);
                // info!("post_exec of CPUUsageObserver: {:?},{:?}", self.name,self.final_based_cpu_usage);
                return Ok(());
            }
            let final_cpu_usage = self.get_cur_cpu_usage_imut();
            if(final_cpu_usage == 0.0){
                self.set_final_based_cpu_usage(0.0);
                self.set_final_cpu_usage(0.0);
                return Ok(());
            }
            let mut total_cpu = 0.0;
            for record_cpu in self.record_cpu_usages.iter() {
                total_cpu += record_cpu;
            }
            let avg_cpu = total_cpu / self.record_times as f64;
            self.set_final_based_cpu_usage(avg_cpu);
            self.set_final_cpu_usage(final_cpu_usage);
            // info!("post_exec of CPUUsageObserver: {:?},{:?}", self.name,self.final_based_cpu_usage);
        }
        Ok(())
    }




}

impl<S> Observer<S> for CPUUsageObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            // self.cpu_ids = Vec::new();
            // self.based_cpu_usage = 0.0;
            self.final_based_cpu_usage = 0.0;
            self.record_times = 0;
            self.record_cpu_usages.clear();
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
                self.set_final_based_cpu_usage(0.0);
                self.set_final_cpu_usage(0.0);
                // info!("post_exec of CPUUsageObserver: {:?},{:?}", self.name,self.final_based_cpu_usage);
                return Ok(());
            }
            let final_cpu_usage = self.get_cur_cpu_usage_imut();
            let mut total_cpu = 0.0;
            for record_cpu in self.record_cpu_usages.iter() {
                total_cpu += record_cpu;
            }
            let avg_cpu = total_cpu / self.record_times as f64;
            self.set_final_based_cpu_usage(avg_cpu);
            self.set_final_cpu_usage(final_cpu_usage);
            if self.based_cpu_usage == 0.0 {
                self.based_cpu_usage = avg_cpu;
            }
            // info!("post_exec of CPUUsageObserver: {:?},{:?}", self.name,self.final_based_cpu_usage);
        }
        Ok(())
    }
}

impl Named for CPUUsageObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialCPUUsageObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<CPUUsageObserver>,
    second_ob_ref: Handle<CPUUsageObserver>,
    first_observer: CPUUsageObserver,
    second_observer: CPUUsageObserver,
    name: Cow<'static, str>,
    judge_type: CPUUsageObserverState,
}

impl DifferentialCPUUsageObserver {
    /// Create a new `DifferentialCPUUsageObserver`.
    pub fn new (
        first: &mut CPUUsageObserver,
        second: &mut CPUUsageObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            second_ob_ref: second.handle(),
            first_observer: CPUUsageObserver::new("fake"),
            second_observer: CPUUsageObserver::new("fake"),
            judge_type: CPUUsageObserverState::OK,
        }
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn second_name(&self) -> &str {
        &self.second_name
    }
    pub fn judge_type(&self) -> &CPUUsageObserverState {
        &self.judge_type
    }
    pub fn perform_judge(&mut self) {
        let first_cpu_usage = self.first_observer.final_based_cpu_usage;
        let second_cpu_usage = self.second_observer.final_based_cpu_usage;
        if first_cpu_usage - self.first_observer.based_cpu_usage > 80.0 || first_cpu_usage > 95.0 {
            self.judge_type = CPUUsageObserverState::FirstCPU;
        }
        if second_cpu_usage - self.second_observer.based_cpu_usage > 80.0 || second_cpu_usage > 95.0  {
            if self.judge_type == CPUUsageObserverState::FirstCPU {
                self.judge_type = CPUUsageObserverState::BothCPU;
            }
            else {
                self.judge_type = CPUUsageObserverState::SecondCPU;
            }
        }
        if first_cpu_usage > second_cpu_usage && first_cpu_usage - second_cpu_usage > 70.0 {
            if self.judge_type == CPUUsageObserverState::SecondCPU {
                self.judge_type = CPUUsageObserverState::BothCPU;
            }
            else if self.judge_type == CPUUsageObserverState::OK {
                self.judge_type = CPUUsageObserverState::FirstCPU;
            }
        } else if second_cpu_usage > first_cpu_usage && second_cpu_usage - first_cpu_usage > 70.0 {
            if self.judge_type == CPUUsageObserverState::FirstCPU {
                self.judge_type = CPUUsageObserverState::BothCPU;
            }
            else if self.judge_type == CPUUsageObserverState::OK {
                self.judge_type = CPUUsageObserverState::SecondCPU;
            }
        } 

        info!("{:?},{:?}", self.first_observer.name,self.first_observer.final_based_cpu_usage);
        info!("{:?},{:?}", self.second_observer.name,self.second_observer.final_based_cpu_usage);
        self.first_observer = CPUUsageObserver::new("fake");
        self.second_observer = CPUUsageObserver::new("fake");

    }
}

impl Named for DifferentialCPUUsageObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialCPUUsageObserver where S: UsesInput {}

impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialCPUUsageObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = CPUUsageObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = CPUUsageObserverState::OK;
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
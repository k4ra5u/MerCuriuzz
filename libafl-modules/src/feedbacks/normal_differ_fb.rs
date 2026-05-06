use core::error;
use std::borrow::Cow;
use std::io::Write;
use std::mem;
use std::process::Command;

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
    pub cpu_usage_state: CPUUsageObserverState,
    pub mem_state: MemObserverState,
    pub exit_kind: ExitKind,
    pub match_nums: usize,
}

impl Deduplication {
    /// Creates a new [`Deduplication`] with the given name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cpu_usage_state: CPUUsageObserverState::OK,
            mem_state: MemObserverState::OK,
            exit_kind: ExitKind::Ok,
            match_nums: 0,
        }
    }
}
impl PartialEq for Deduplication {
    fn eq(&self, other: &Self) -> bool {
        self.cpu_usage_state == other.cpu_usage_state
            && self.exit_kind == other.exit_kind
            && self.mem_state == other.mem_state
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NormalDifferFeedback {
    diff_cpu_ob_handle: Handle<DifferentialCPUUsageObserver>,
    diff_mem_ob_handle: Handle<DifferentialMemObserver>,
    diff_pcap_ob_handle: Handle<DifferentialPcapObserver>,
    diff_misc_ob_handle: Handle<DifferentialMiscObserver>,
    history_object: Vec<Deduplication>,
    pub srand_seed: u32,
    pub first_pcap: PcapRecord,
    pub second_pcap: PcapRecord,
}

impl<S> Feedback<S> for NormalDifferFeedback
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
        let diff_misc_ob = _observers.get(&self.diff_misc_ob_handle).unwrap();
        self.srand_seed = diff_misc_ob.srand_seed;

        // let observer = _observers.get(&self.observer_handle).unwrap();
        let diff_cpu_ob = _observers.get(&self.diff_cpu_ob_handle).unwrap();
        let diff_mem_ob = _observers.get(&self.diff_mem_ob_handle).unwrap();
        let diff_pcap_ob = _observers.get(&self.diff_pcap_ob_handle).unwrap();
        self.first_pcap = diff_pcap_ob.first_pcap_record.clone();
        self.second_pcap = diff_pcap_ob.second_pcap_record.clone();

        let mut interesting_flag = false;
        if *diff_cpu_ob.judge_type() != CPUUsageObserverState::OK {
            warn!("vul of CPU testcase: {:?}", diff_cpu_ob.judge_type());
            interesting_flag = true;
        }
        if *diff_mem_ob.judge_type() != MemObserverState::OK {
            warn!("vul of Mem testcase: {:?}", diff_mem_ob.judge_type());
            interesting_flag = true;
        }
        let mut crash_flag = false;
        if _exit_kind != &ExitKind::Ok {
            error!("vul of ExitKind testcase: {:?}", _exit_kind);
            crash_flag = true;
            interesting_flag = true;
        }
        if interesting_flag {
            let mut new_deduplication = Deduplication::new();
            new_deduplication.match_nums = 1;
            new_deduplication.cpu_usage_state = diff_cpu_ob.judge_type().clone();
            new_deduplication.mem_state = diff_mem_ob.judge_type().clone();
            new_deduplication.exit_kind = _exit_kind.clone();
            for old_object in self.history_object.iter_mut() {
                if old_object == &new_deduplication {
                    if old_object.match_nums > 0 {
                        warn!("Deduplication testcase");
                        if crash_flag == true {
                            warn!("Crash testcase");
                            return Ok(true);
                        }
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
        let new_Path = format!("./crashes/seed_{:?}", self.srand_seed);
        *testcase.file_path_mut() = Some(std::path::PathBuf::from(new_Path.clone()));
        info!("Stored input to disk:: {:?}", new_Path);
        // ./path/to/crashes/0fac37e6127023ae -> ./path/to/crashes/
        let first_commend = format!(
            "editcap -A {} -B {} record.pcap {}\n",
            self.first_pcap.start_time, self.first_pcap.end_time, self.first_pcap.name
        );
        let second_commend = format!(
            "editcap -A {} -B {} record.pcap {}\n",
            self.second_pcap.start_time, self.second_pcap.end_time, self.second_pcap.name
        );

        // write into dump_records.sh
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open("dump_records.sh")
            .unwrap();
        file.write_all(first_commend.as_bytes()).unwrap();
        file.write_all(second_commend.as_bytes()).unwrap();
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

impl Named for NormalDifferFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("NormalDifferFeedback");
        &NAME
        // self.observer_handle.name()
    }
}

impl NormalDifferFeedback {
    /// Creates a new [`NormalDifferFeedback`]
    #[must_use]
    pub fn new(
        diff_cpu_ob: &DifferentialCPUUsageObserver,
        diff_mem_ob: &DifferentialMemObserver,
        diff_pcap_ob: &DifferentialPcapObserver,
        diff_misc_ob: &DifferentialMiscObserver,
    ) -> Self {
        Self {
            diff_cpu_ob_handle: diff_cpu_ob.handle(),
            diff_mem_ob_handle: diff_mem_ob.handle(),
            diff_pcap_ob_handle: diff_pcap_ob.handle(),
            diff_misc_ob_handle: diff_misc_ob.handle(),
            srand_seed: 0,
            history_object: Vec::new(),
            first_pcap: PcapRecord::new(),
            second_pcap: PcapRecord::new(),
        }
    }
}

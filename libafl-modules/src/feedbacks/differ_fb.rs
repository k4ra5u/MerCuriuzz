use core::error;
use std::borrow::Cow;
use std::io::Write;
use std::mem;
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
use log::error;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState, feedbacks::Feedback};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::observers::*;

pub fn cmp_ctrl_frames(a:Vec<Frame_info>,b:Vec<Frame_info>) -> bool {
    for new_frame in b.iter() {
        let mut new_flag = false;
        for old_frame in a.iter() {
            if mem::discriminant(&new_frame.frame) == mem::discriminant(&old_frame.frame) && new_frame.frame_num >10 && old_frame.frame_num > 10 {
                new_flag = true;
                break;
            }
        }
        if !new_flag {
            return false;
        }
    }
    for old_frame in a.iter() {
        let mut old_flag = false;
        for new_frame in b.iter() {
            if mem::discriminant(&new_frame.frame) == mem::discriminant(&old_frame.frame) && new_frame.frame_num >10 && old_frame.frame_num > 10 {
                old_flag = true;
                break;
            }
        }
        if !old_flag {
            return false;
        }
    }

    return true;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Deduplication {
    pub cc_time_state: CCTimesObserverState,
    pub cpu_usage_state: CPUUsageObserverState,
    pub mem_state: MemObserverState,
    pub ctrl_state: CtrlObserverState,
    pub data_state: DataObserverState,
    pub ack_state: ACKObserverState,
    pub exit_kind: ExitKind,
    pub ctrl_seq: Vec<Frame_info>,
    pub match_nums:usize

}

impl Deduplication {
    /// Creates a new [`Deduplication`] with the given name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cc_time_state: CCTimesObserverState::OK,
            cpu_usage_state: CPUUsageObserverState::OK,
            mem_state: MemObserverState::OK,
            ctrl_state: CtrlObserverState::OK,
            data_state: DataObserverState::OK,
            ack_state: ACKObserverState::OK,
            exit_kind: ExitKind::Ok,
            ctrl_seq: Vec::new(),
            match_nums: 0,
        }
    }
}
impl PartialEq for Deduplication {
    fn eq(&self, other: &Self) -> bool {
        self.cc_time_state == other.cc_time_state &&
        self.cpu_usage_state == other.cpu_usage_state &&
        self.mem_state == other.mem_state &&
        self.ctrl_state == other.ctrl_state &&
        self.data_state == other.data_state &&
        self.ack_state == other.ack_state &&
        self.exit_kind == other.exit_kind &&
        cmp_ctrl_frames(self.ctrl_seq.clone(),other.ctrl_seq.clone())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DifferFeedback {
    diff_cc_ob_handle: Handle<DifferentialCCTimesObserver>,
    diff_cpu_ob_handle: Handle<DifferentialCPUUsageObserver>,
    diff_mem_ob_handle: Handle<DifferentialMemObserver>,
    diff_ctrl_ob_handle: Handle<DifferentialRecvControlFrameObserver>,
    diff_data_ob_handle: Handle<DifferentialRecvDataFrameObserver>,
    diff_ack_ob_handle: Handle<DifferentialACKRangeObserver>,
    diff_pcap_ob_handle: Handle<DifferentialPcapObserver>,
    diff_misc_ob_handle: Handle<DifferentialMiscObserver>,
    history_object:Vec<Deduplication>,
    pub srand_seed: u32,
    pub first_pcap: PcapRecord,
    pub second_pcap: PcapRecord,

}

impl<S> Feedback<S> for DifferFeedback
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
        let diff_cc_ob = _observers.get(&self.diff_cc_ob_handle).unwrap();
        let diff_cpu_ob = _observers.get(&self.diff_cpu_ob_handle).unwrap();
        let diff_mem_ob = _observers.get(&self.diff_mem_ob_handle).unwrap();
        let diff_ctrl_ob = _observers.get(&self.diff_ctrl_ob_handle).unwrap();
        let diff_data_ob = _observers.get(&self.diff_data_ob_handle).unwrap();
        let diff_ack_ob = _observers.get(&self.diff_ack_ob_handle).unwrap();
        let diff_pcap_ob = _observers.get(&self.diff_pcap_ob_handle).unwrap();
        self.first_pcap = diff_pcap_ob.first_pcap_record.clone();
        self.second_pcap = diff_pcap_ob.second_pcap_record.clone();

        let mut interesting_flag = false;
        let diff_cc_ob_judge_type = diff_cc_ob.judge_type();
        if *diff_cc_ob_judge_type != CCTimesObserverState::OK && *diff_cc_ob_judge_type != CCTimesObserverState::MistypeCCReason {
            warn!("vul of CC testcase: {:?}",diff_cc_ob_judge_type);
            interesting_flag = true;
        }
        if *diff_cpu_ob.judge_type() != CPUUsageObserverState::OK {
            warn!("vul of CPU testcase: {:?}",diff_cpu_ob.judge_type());
            interesting_flag = true;
        }
        if *diff_mem_ob.judge_type() != MemObserverState::OK && *diff_mem_ob.judge_type() != MemObserverState::BothMemLeak {
            warn!("vul of Mem testcase: {:?}",diff_mem_ob.judge_type());
            interesting_flag = true;
        }
        if *diff_ctrl_ob.judge_type() != CtrlObserverState::OK {
            warn!("vul of Control Frame testcase: {:?}",diff_ctrl_ob.judge_type());
            interesting_flag = true;
        }
        if *diff_data_ob.judge_type() != DataObserverState::OK {
            warn!("vul of Data Frame testcase: {:?}",diff_data_ob.judge_type());
            interesting_flag = true;
        }
        if *diff_ack_ob.judge_type() != ACKObserverState::OK {
            warn!("vul of ACK Range testcase: {:?}",diff_ack_ob.judge_type());
            interesting_flag = true;
        }
        let mut crash_flag = false;
        if _exit_kind != &ExitKind::Ok {
            error!("vul of ExitKind testcase: {:?}",_exit_kind);
            crash_flag = true;
            interesting_flag = true;
        }
        if interesting_flag {
            let mut new_deduplication = Deduplication::new();
            new_deduplication.match_nums = 1;
            new_deduplication.cc_time_state = diff_cc_ob.judge_type().clone();
            new_deduplication.cpu_usage_state = diff_cpu_ob.judge_type().clone();
            new_deduplication.mem_state = diff_mem_ob.judge_type().clone();
            new_deduplication.ctrl_state = diff_ctrl_ob.judge_type().clone();
            new_deduplication.data_state = diff_data_ob.judge_type().clone();
            new_deduplication.ack_state = diff_ack_ob.judge_type().clone();
            new_deduplication.exit_kind = _exit_kind.clone();
            new_deduplication.ctrl_seq = diff_ctrl_ob.get_ctrl_frames();
            for old_object in self.history_object.iter_mut() {
                if old_object == &new_deduplication {
                    if old_object.match_nums > 0 {
                        warn!("Deduplication testcase");
                        if crash_flag == true {
                            warn!("Crash testcase");
                            return Ok(true);
                        }
                        return Ok(false);
                    }
                    else {
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
        let new_Path = format!("./crashes/seed_{:?}",self.srand_seed);
        *testcase.file_path_mut()  = Some(std::path::PathBuf::from(new_Path.clone()));
        info!("Stored input to disk:: {:?}",new_Path);
        // ./path/to/crashes/0fac37e6127023ae -> ./path/to/crashes/
        let first_commend = format!("editcap -A {} -B {} record.pcap {}\n",self.first_pcap.start_time,self.first_pcap.end_time,self.first_pcap.name);
        let second_commend = format!("editcap -A {} -B {} record.pcap {}\n",self.second_pcap.start_time,self.second_pcap.end_time,self.second_pcap.name);

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
        
        // let _ = Command::new("sudo")
        // .arg("rm")
        // .arg("-f")
        // .arg(&self.first_pcap_path)
        // .output() // 捕获 `touch` 的输出
        // .expect("Failed to create empty pcap file");
        // let _ = Command::new("sudo")
        // .arg("rm")
        // .arg("-f")
        // .arg(&self.second_pcap_path)
        // .output() // 捕获 `touch` 的输出
        // .expect("Failed to create empty pcap file");

        // info!("delete pcap file: {:?}",&self.first_pcap_path);
        // info!("delete pcap file: {:?}",&self.second_pcap_path);
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Named for DifferFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("DifferFeedback");
        &NAME
        // self.observer_handle.name()
    }
}

impl DifferFeedback {
    /// Creates a new [`DifferFeedback`]
    #[must_use]
    pub fn new(diff_cc_ob: &DifferentialCCTimesObserver,
                diff_cpu_ob: &DifferentialCPUUsageObserver,
                diff_mem_ob: &DifferentialMemObserver,
                diff_ctrl_ob: &DifferentialRecvControlFrameObserver,
                diff_data_ob: &DifferentialRecvDataFrameObserver,
                diff_ack_ob: &DifferentialACKRangeObserver,
                diff_pcap_ob: &DifferentialPcapObserver,
                diff_misc_ob: &DifferentialMiscObserver,
    ) -> Self {
        Self {
            diff_cc_ob_handle: diff_cc_ob.handle(),
            diff_cpu_ob_handle: diff_cpu_ob.handle(),
            diff_mem_ob_handle: diff_mem_ob.handle(),
            diff_ctrl_ob_handle: diff_ctrl_ob.handle(),
            diff_data_ob_handle: diff_data_ob.handle(),
            diff_ack_ob_handle: diff_ack_ob.handle(),
            diff_pcap_ob_handle: diff_pcap_ob.handle(),
            diff_misc_ob_handle: diff_misc_ob.handle(),
            srand_seed: 0,
            history_object: Vec::new(),
            first_pcap: PcapRecord::new(),
            second_pcap: PcapRecord::new(),
        }
    }
}


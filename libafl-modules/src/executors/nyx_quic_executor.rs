// use std::{io::Write, process::exit};

use libafl::{
    corpus::Corpus, executors::{Executor, ExitKind, HasObservers}, inputs::{BytesInput, HasTargetBytes, UsesInput}, observers::{ObserversTuple, UsesObservers}, state::{HasCorpus, HasExecutions, HasRandSeed, HasSolutions, State, UsesState}
};
use libafl_bolts::{prelude::OwnedMutPtr, tuples::RefIndexable};
use libafl_nyx::executor::NyxExecutor;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, time::Duration, vec
};
use std::num::ParseIntError;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use libc::{rand, srand, ETH_DATA_LEN};
use libc::{CODA_SUPER_MAGIC, ERA};
use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::TimeSpec,
        wait::waitpid,
    },
    unistd::Pid,
};
use libafl_bolts::{
    rands, shmem::{ShMem, ShMemId, ShMemProvider, UnixShMemProvider}, tuples::{Handle, Handled,MatchName ,MatchNameRef, Prepend}, AsSlice, AsSliceMut, Truncate
};
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug,warn};

use quiche::{frame::{self, EcnCounts, Frame, MAX_STREAM_SIZE}, packet, ranges::{self, RangeSet}, stream, Connection, ConnectionId, Error, FrameWithPkn, Header};

use crate::inputstruct::{pkt_resort_type, quic_input::InputStruct_deserialize, FramesCycleStruct, InputStruct, QuicStruct};
use crate::observers::*;
use crate::misc::*;

pub fn start_harness_with_envs(command: &str, envs: Vec<(OsString, OsString)>) -> Result<Output, std::io::Error> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output()
}

/*
    pub exit_kind: ExitKind,
    pub normal_conn_ob: NormalConnObserver,
    pub cc_time_ob: CCTimesObserver,
    pub misc_ob: MiscObserver,
    pub recv_pkt_num_ob: RecvPktNumObserver,
    pub ack_range_ob: ACKRangeObserver,
    pub control_frame_ob: RecvControlFrameObserver,
    pub data_frame_ob: RecvDataFrameObserver,
    pub cpu_usage_ob: CPUUsageObserver,
    pub mem_usage_ob: MemObserver,
    pub pcap_record_ob: PcapObserver,
    pub ucb_ob: UCBObserver, */
pub struct NyxQuicExecutor<OT, S>
{
    pub frame_rand_seed: u32,
    pub remote_obs_data: Option<RemoteObsData>,
    pub normal_conn_ob_ref: Handle<NormalConnObserver>,
    pub cc_time_ob_ref: Handle<CCTimesObserver>,
    pub misc_ob_ref: Handle<MiscObserver>,
    pub recv_pkt_num_ob_ref: Handle<RecvPktNumObserver>,
    pub ack_range_ob_ref: Handle<ACKRangeObserver>,
    pub control_frame_ob_ref: Handle<RecvControlFrameObserver>,
    pub data_frame_ob_ref: Handle<RecvDataFrameObserver>,
    pub cpu_usage_ob_ref: Handle<CPUUsageObserver>,
    pub mem_usage_ob_ref: Handle<MemObserver>,
    pub pcap_record_ob_ref: Handle<PcapObserver>,
    pub ucb_ob_ref: Handle<UCBObserver>,
    pub parent: NyxExecutor<S, OT>,
    pub quic_response: OwnedMutPtr<u8>,
    pub is_first:bool,
}

impl<OT, S> NyxQuicExecutor<OT, S> 
where 
OT: ObserversTuple<S>,
S: State, 
{
    pub fn new(
        normal_conn_ob_ref: Handle<NormalConnObserver>,
        cc_time_ob_ref: Handle<CCTimesObserver>,
        misc_ob_ref: Handle<MiscObserver>,
        recv_pkt_num_ob_ref: Handle<RecvPktNumObserver>,
        ack_range_ob_ref: Handle<ACKRangeObserver>,
        control_frame_ob_ref: Handle<RecvControlFrameObserver>,
        data_frame_ob_ref: Handle<RecvDataFrameObserver>,
        cpu_usage_ob_ref: Handle<CPUUsageObserver>,
        mem_usage_ob_ref: Handle<MemObserver>,
        pcap_record_ob_ref: Handle<PcapObserver>,
        ucb_ob_ref: Handle<UCBObserver>,
        parent: NyxExecutor<S,OT>,
        // raw_quic_response: *mut u8,
        is_first: bool
    ) -> Self {
        let quic_response_buffer = parent.helper.quic_response_buffer;    
        Self {
            frame_rand_seed:0,
            remote_obs_data:None,
            normal_conn_ob_ref,
            cc_time_ob_ref,
            misc_ob_ref,
            recv_pkt_num_ob_ref,
            ack_range_ob_ref,
            control_frame_ob_ref,
            data_frame_ob_ref,
            cpu_usage_ob_ref,
            mem_usage_ob_ref,
            pcap_record_ob_ref,
            ucb_ob_ref,
            parent,
            quic_response:OwnedMutPtr::Ptr(quic_response_buffer),
            is_first,

        }
    }

    pub fn set_frame_seed(mut self, seed: u32) -> Self {
        self.frame_rand_seed = seed;
        self
    }

    pub fn wait_for_quic_shm_res(&mut self) {
        while true {
            let res = self.quic_response.as_mut() as *mut u8;
            if(unsafe { *res } == 1) {
                unsafe { *res = 0 };
                break;
            }
            else {
                sleep(Duration::from_millis(100));
            }
        }
    } 
    
    pub fn sync_normal_conn_ob(&mut self, normal_conn_ob: &NormalConnObserver) {
        let normal_conn_handle = self.normal_conn_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(normal_conn) = observers.get_mut(&normal_conn_handle) {
            normal_conn.pre_spend_time = normal_conn_ob.pre_spend_time;
            normal_conn.post_spend_time = normal_conn_ob.post_spend_time;
            normal_conn.unable_to_connect = normal_conn_ob.unable_to_connect;
        }
    }

    pub fn sync_cc_time_ob(&mut self, cc_time_ob: &CCTimesObserver) {
        let cc_time_handle = self.cc_time_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(cc_time) = observers.get_mut(&cc_time_handle) {
            cc_time.pkn = cc_time_ob.pkn;
            cc_time.error_code = cc_time_ob.error_code;
            cc_time.frame_type = cc_time_ob.frame_type;
            cc_time.reason = cc_time_ob.reason.clone();
        }
    }

    pub fn sync_misc_ob(&mut self, misc_ob: &MiscObserver) {
        let misc_ob_ref = self.misc_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(misc) = observers.get_mut(&misc_ob_ref) {
            misc.srand_seed = misc_ob.srand_seed;
        }
    }

    pub fn sync_recv_pkt_num_ob(&mut self, recv_pkt_num_ob: &RecvPktNumObserver) {
        let recv_pkt_num_handle = self.recv_pkt_num_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(recv_pkt_num) = observers.get_mut(&recv_pkt_num_handle) {
            recv_pkt_num.send_pkts = recv_pkt_num_ob.send_pkts;
            recv_pkt_num.recv_pkts = recv_pkt_num_ob.recv_pkts;
            recv_pkt_num.send_bytes = recv_pkt_num_ob.send_bytes;
            recv_pkt_num.recv_bytes = recv_pkt_num_ob.recv_bytes;

        }
    }

    pub fn sync_ack_range_ob(&mut self, ack_range_ob: &ACKRangeObserver) {
        let ack_range_handle = self.ack_range_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(ack_range) = observers.get_mut(&ack_range_handle) {
            ack_range.ack_ranges = ack_range_ob.ack_ranges.clone();
            ack_range.ack_ranges_nums = ack_range_ob.ack_ranges_nums;

        }
    }

    pub fn sync_control_frame_ob(&mut self, control_frame_ob: &RecvControlFrameObserver) {
        let control_frame_handle = self.control_frame_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(control_frame) = observers.get_mut(&control_frame_handle) {
            control_frame.ctrl_frames_list = control_frame_ob.ctrl_frames_list.clone();
        }
    }

    pub fn sync_data_frame_ob(&mut self, data_frame_ob: &RecvDataFrameObserver) {
        let data_frame_handle = self.data_frame_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(data_frame) = observers.get_mut(&data_frame_handle) {
            data_frame.crypto_frames_list = data_frame_ob.crypto_frames_list.clone();
            data_frame.stream_frames_list = data_frame_ob.stream_frames_list.clone();
            data_frame.pr_frames_list = data_frame_ob.pr_frames_list.clone();
            data_frame.dgram_frames_list = data_frame_ob.dgram_frames_list.clone();

        }
    }

    pub fn sync_cpu_usage_ob(&mut self, cpu_usage_ob: &CPUUsageObserver) {
        let cpu_usage_handle = self.cpu_usage_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(cpu_usage) = observers.get_mut(&cpu_usage_handle) {
            cpu_usage.based_cpu_usage = cpu_usage_ob.based_cpu_usage;
            cpu_usage.final_cpu_usage = cpu_usage_ob.final_cpu_usage;
        }
    }

    pub fn sync_mem_usage_ob(&mut self, mem_usage_ob: &MemObserver) {
        let mem_usage_handle = self.mem_usage_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(mem_usage) = observers.get_mut(&mem_usage_handle) {
            mem_usage.initial_mem = mem_usage_ob.initial_mem;
            mem_usage.allowed_mem = mem_usage_ob.allowed_mem;
            mem_usage.before_mem = mem_usage_ob.before_mem;
            mem_usage.after_mem = mem_usage_ob.after_mem;

        }
    }

    pub fn sync_pcap_record_ob(&mut self, pcap_record_ob: &PcapObserver) {
        let pcap_record_handle = self.pcap_record_ob_ref.clone();
        let mut observers = self.observers_mut();

        if let Some(pcap_record) = observers.get_mut(&pcap_record_handle) {
            pcap_record.new_record = pcap_record_ob.new_record.clone();
        }
        
    }

    pub fn sync_ucb_ob(&mut self, ucb_ob: &UCBObserver) {
        let ucb_handle = self.ucb_ob_ref.clone();
        let mut observers = self.observers_mut();
        if let Some(ucb) = observers.get_mut(&ucb_handle) {
            ucb.reward = ucb_ob.reward;
        }
    }

    pub fn update_all_obs(&mut self) -> ExitKind {
        let raw_ptr = match self.quic_response {
            libafl_bolts::prelude::OwnedMutPtr::Ptr(p) => p.wrapping_add(1),
            _ => panic!("quic_response is not a valid pointer"),
        };
        let obs_response = unsafe {
            std::slice::from_raw_parts(raw_ptr, 0x100000)
        };


        let serde_obs_buf = obs_response.as_slice();
        let obs_data = bincode::deserialize::<RemoteObsData>(&serde_obs_buf).unwrap();
        info!("recive obs_data: \n{:?}\n\n",obs_data);
        self.sync_normal_conn_ob(&obs_data.normal_conn_ob);
        self.sync_cc_time_ob(&obs_data.cc_time_ob);
        self.sync_misc_ob(&obs_data.misc_ob);
        self.sync_recv_pkt_num_ob(&obs_data.recv_pkt_num_ob);
        self.sync_ack_range_ob(&obs_data.ack_range_ob);
        self.sync_control_frame_ob(&obs_data.control_frame_ob);
        self.sync_data_frame_ob(&obs_data.data_frame_ob);
        self.sync_cpu_usage_ob(&obs_data.cpu_usage_ob);
        self.sync_mem_usage_ob(&obs_data.mem_usage_ob);
        self.sync_pcap_record_ob(&obs_data.pcap_record_ob);
        self.sync_ucb_ob(&obs_data.ucb_ob);
        obs_data.exit_kind

    }



}

impl<OT, S> UsesState for NyxQuicExecutor<OT, S>
where
    S: State, 
{
    type State = S;
}

impl<OT, S> UsesObservers for NyxQuicExecutor<OT, S>
where
    OT: ObserversTuple<S>,
    S: State,
{
    type Observers = OT;
}

impl<OT, S> HasObservers for NyxQuicExecutor<OT, S>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.parent.observers()
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.parent.observers_mut()
    }
}

impl<EM, OT, S, Z> Executor<EM, Z> for NyxQuicExecutor<OT, S>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions + HasCorpus + HasSolutions + HasRandSeed + UsesInput<Input=BytesInput>,
    S::Input: HasTargetBytes,
    OT: MatchName + ObserversTuple<S>,
    Z: UsesState<State = S> {
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<libafl::prelude::ExitKind, libafl::prelude::Error> {

        if self.is_first {
            self.frame_rand_seed = unsafe {rand().try_into().unwrap()};
            // info!("now {:?} corpus",state.corpus().count());
        }
        info!("running corpus: {:?}", state.corpus().current());

        *state.executions_mut() += 1;


        let binding: libafl_bolts::prelude::OwnedSlice<'_, u8> = input.target_bytes();
        let mut ori_input = binding.as_slice();
        // quic_shm_buf[1..9].copy_from_slice( &data.len().to_be_bytes());
        // quic_shm_buf[9..13].copy_from_slice(&seed.to_be_bytes());
        // quic_shm_buf[13..13+data.len()].copy_from_slice(data);
        // quic_shm_buf[0] = 1; 
        let input_len = ori_input.len();
        let total_size = 13 + input_len; // 根据你的需求计算总长度
        let mut new_input = vec![0; total_size]; // 初始化全 0 的向量
        new_input[0] = 1;
        new_input[1..9].copy_from_slice( &input_len.to_be_bytes());
        new_input[9..13].copy_from_slice(&self.frame_rand_seed.to_be_bytes());
        new_input[13..13+input_len].copy_from_slice(ori_input);
        let mut NewInput = BytesInput::new(new_input);
        self.parent.run_target(_fuzzer, state, _mgr, &NewInput);

        
        self.wait_for_quic_shm_res();

        /* Create pcap file if not exists */
        let pcap_recv = self.parent.helper.execution_path_buffer;
        let pcap_path_string = format!("pcaps/{}.pcap", state.rand_seed());
        let pcap_file_path = Path::new(&pcap_path_string);
        if !pcap_file_path.exists() {
            let mut file = File::create(pcap_file_path).expect("Failed to create pcap file");
            unsafe {
                file.write_all(std::slice::from_raw_parts(pcap_recv, 0x100000)).expect("Failed to write pcap data");
            }
        }


        let exit_kind = self.update_all_obs();
        Ok(exit_kind)
    }
}

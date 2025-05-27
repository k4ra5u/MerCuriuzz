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
use libafl::{
    corpus::Corpus, executors::{
        Executor, ExitKind, HasObservers
    }, inputs::HasTargetBytes, observers::{
        get_asan_runtime_flags_with_log_path, AsanBacktraceObserver, ObserversTuple, UsesObservers
    }, prelude::{multi_map, HitcountsIterableMapObserver, MapObserver, MultiMapObserver}, state::{
        HasCorpus, HasExecutions, HasRandSeed, HasSolutions, State, UsesState
    }
};
use libafl_bolts::{
    rands, shmem::{ShMem, ShMemId, ShMemProvider, UnixShMemProvider}, tuples::{Handle, Handled,MatchName ,MatchNameRef, Prepend, RefIndexable}, AsSlice, AsSliceMut, Truncate
};
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug,warn};

use quiche::{frame::{self, EcnCounts, Frame, MAX_STREAM_SIZE}, packet, ranges::{self, RangeSet}, stream, Connection, ConnectionId, Error, FrameWithPkn, Header};

use crate::inputstruct::{pkt_resort_type, quic_input::InputStruct_deserialize, FramesCycleStruct, InputStruct, QuicStruct};
use crate::observers::*;
use crate::misc::*;

//use crate::QuicStruct;
// use quic_input::{FramesCycleStruct, InputStruct, pkt_resort_type, QuicStruct};

const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP_REQ_STREAM_ID: u64 = 4;

/// For experiment only, please use `STNyxExecutor` in production.


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
pub struct QuicExecutor<OT, S, SP>
where SP: ShMemProvider,
{
    pub start_command: String,
    pub judge_command: String,
    pub envs: Vec<(OsString, OsString)>,
    pub observers: OT,
    pub phantom: std::marker::PhantomData<S>,
    pub map: Option<SP::ShMem>,
    pub map_size: Option<usize>,
    pub shmem_provider: SP,
    pub pid: i32,
    pub ob_shm_id: String,
    pub ob_shm_size: usize,
    pub quic_shm_id: String,
    pub quic_shm_size: usize,
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
}

impl<OT, S,SP> QuicExecutor<OT, S,SP> 
where 
OT: ObserversTuple<S>,
S: State, 
SP: ShMemProvider,
{
    pub fn new(observers: OT,shmem_provider:SP,
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
    ) -> Self {
        Self {
            start_command: "".to_owned(),
            judge_command: "".to_owned(),
            envs: vec![],
            observers,
            phantom: std::marker::PhantomData,
            map:None,
            map_size:None,
            shmem_provider,
            pid:0,
            quic_shm_id:String::new() ,
            quic_shm_size:0,
            ob_shm_id:String::new(),
            ob_shm_size:0,
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

        }
    }

    pub fn start_command(mut self,str:String) -> Self {
        let base_dir = env::var("START_DIR").unwrap();
        self.start_command = format!("{base_dir}/{str}.sh");
        info!("start_command: {:?}",self.start_command);
        self

    }

    pub fn judge_command(mut self,str:String) -> Self {
        let base_dir = env::var("JUDGE_DIR").unwrap();
        self.judge_command = format!("{base_dir}/{str}-judge.sh");
        info!("judge_command: {:?}",self.judge_command);
        self
    }


    pub fn coverage_map_size(mut self, size: usize) -> Self {
        self.map_size = Some(size);
        self
    }

    pub fn set_frame_seed(mut self, seed: u32) -> Self {
        self.frame_rand_seed = seed;
        self
    }

    pub fn env<K, V>(mut self, key: K, val: V) -> Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.envs
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Adds environmental vars to the harness's commandline
    pub fn envs<IT, K, V>(mut self, vars: IT) -> Self
    where
        IT: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut res = vec![];
        for (ref key, ref val) in vars {
            res.push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        }
        self.envs.append(&mut res);
        self
    }

    pub fn get_coverage_map_size(&self) -> Option<usize> {
        self.map_size
    }

    pub fn quic_shm_id(mut self, quic_shm_id: String) -> Self {
        self.quic_shm_id = quic_shm_id;
        self
    }

    pub fn quic_shm_size(mut self, quic_shm_size: usize) -> Self {
        self.quic_shm_size = quic_shm_size;
        self
    }

    pub fn ob_shm_id(mut self, ob_shm_id: String) -> Self {
        self.ob_shm_id = ob_shm_id;
        self
    }

    pub fn ob_shm_size(mut self, ob_shm_size: usize) -> Self {
        self.ob_shm_size = ob_shm_size;
        self
    }

    pub fn write_to_quic_shm_seed(&mut self, data: &[u8],seed: u32) {
        let mut quic_shm = self.shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&format!("{}",self.quic_shm_id)),self.quic_shm_size)
            .unwrap();
        let quic_shm_buf = quic_shm.as_slice_mut();

        quic_shm_buf[1..9].copy_from_slice( &data.len().to_be_bytes());
        quic_shm_buf[9..13].copy_from_slice(&seed.to_be_bytes());
        quic_shm_buf[13..13+data.len()].copy_from_slice(data);
        quic_shm_buf[0] = 1;
    } 
    pub fn wait_for_quic_shm_res(&mut self) {
        let mut quic_shm = self.shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&format!("{}",self.quic_shm_id)),self.quic_shm_size)
            .unwrap();
        let quic_shm_buf = quic_shm.as_slice();
        while true {
            if(quic_shm_buf[0] == 0) {
                break;
            }
            else {
                sleep(Duration::from_millis(100));
            }
        }
    } 
    
    pub fn sync_normal_conn_ob(&mut self, normal_conn_ob: &NormalConnObserver) {
        if let Some(normal_conn) = self.observers.get_mut(&self.normal_conn_ob_ref) {
            normal_conn.pre_spend_time = normal_conn_ob.pre_spend_time;
            normal_conn.post_spend_time = normal_conn_ob.post_spend_time;
            normal_conn.unable_to_connect = normal_conn_ob.unable_to_connect;
        }
    }
    pub fn sync_cc_time_ob(&mut self, cc_time_ob: &CCTimesObserver) {
        if let Some(cc_time) = self.observers.get_mut(&self.cc_time_ob_ref) {
            cc_time.pkn = cc_time_ob.pkn;
            cc_time.error_code = cc_time_ob.error_code;
            cc_time.frame_type = cc_time_ob.frame_type;
            cc_time.reason = cc_time_ob.reason.clone();
        }
    }
    pub fn sync_misc_ob(&mut self, misc_ob: &MiscObserver) {
        if let Some(misc) = self.observers.get_mut(&self.misc_ob_ref) {
            misc.srand_seed = misc_ob.srand_seed;
        }
    }
    pub fn sync_recv_pkt_num_ob(&mut self, recv_pkt_num_ob: &RecvPktNumObserver) {
        if let Some(recv_pkt_num) = self.observers.get_mut(&self.recv_pkt_num_ob_ref) {
            recv_pkt_num.send_pkts = recv_pkt_num_ob.send_pkts;
            recv_pkt_num.recv_pkts = recv_pkt_num_ob.recv_pkts;
            recv_pkt_num.send_bytes = recv_pkt_num_ob.send_bytes;
            recv_pkt_num.recv_bytes = recv_pkt_num_ob.recv_bytes;

        }
    }
    pub fn sync_ack_range_ob(&mut self, ack_range_ob: &ACKRangeObserver) {
        if let Some(ack_range) = self.observers.get_mut(&self.ack_range_ob_ref) {
            ack_range.ack_ranges = ack_range_ob.ack_ranges.clone();
            ack_range.ack_ranges_nums = ack_range_ob.ack_ranges_nums;

        }
    }
    pub fn sync_control_frame_ob(&mut self, control_frame_ob: &RecvControlFrameObserver) {
        if let Some(control_frame) = self.observers.get_mut(&self.control_frame_ob_ref) {
            control_frame.ctrl_frames_list = control_frame_ob.ctrl_frames_list.clone();
        }
    }
    pub fn sync_data_frame_ob(&mut self, data_frame_ob: &RecvDataFrameObserver) {
        if let Some(data_frame) = self.observers.get_mut(&self.data_frame_ob_ref) {
            data_frame.crypto_frames_list = data_frame_ob.crypto_frames_list.clone();
            data_frame.stream_frames_list = data_frame_ob.stream_frames_list.clone();
            data_frame.pr_frames_list = data_frame_ob.pr_frames_list.clone();
            data_frame.dgram_frames_list = data_frame_ob.dgram_frames_list.clone();

        }
    }
    pub fn sync_cpu_usage_ob(&mut self, cpu_usage_ob: &CPUUsageObserver) {
        if let Some(cpu_usage) = self.observers.get_mut(&self.cpu_usage_ob_ref) {
            cpu_usage.based_cpu_usage = cpu_usage_ob.based_cpu_usage;
            cpu_usage.final_cpu_usage = cpu_usage_ob.final_cpu_usage;
        }
    }
    pub fn sync_mem_usage_ob(&mut self, mem_usage_ob: &MemObserver) {
        if let Some(mem_usage) = self.observers.get_mut(&self.mem_usage_ob_ref) {
            mem_usage.initial_mem = mem_usage_ob.initial_mem;
            mem_usage.allowed_mem = mem_usage_ob.allowed_mem;
            mem_usage.before_mem = mem_usage_ob.before_mem;
            mem_usage.after_mem = mem_usage_ob.after_mem;

        }
    }
    pub fn sync_pcap_record_ob(&mut self, pcap_record_ob: &PcapObserver) {
        if let Some(pcap_record) = self.observers.get_mut(&self.pcap_record_ob_ref) {
            pcap_record.new_record = pcap_record_ob.new_record.clone();
        }
    }
    pub fn sync_ucb_ob(&mut self, ucb_ob: &UCBObserver) {
        if let Some(ucb) = self.observers.get_mut(&self.ucb_ob_ref) {
            ucb.reward = ucb_ob.reward;
        }
    }

    pub fn update_all_obs(&mut self) -> ExitKind {
        let obs_shm = self.shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&format!("{}",self.ob_shm_id)),self.ob_shm_size)
            .unwrap();

        let serde_obs_buf = obs_shm.as_slice();
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

impl<OT, S,SP> UsesState for QuicExecutor<OT, S, SP>
where
    S: State, 
    SP: ShMemProvider
{
    type State = S;
}

impl<OT, S,SP> UsesObservers for QuicExecutor<OT, S,SP>
where
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider
{
    type Observers = OT;
}

impl<OT, S,SP> HasObservers for QuicExecutor<OT, S,SP>
where
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<EM, OT, S,SP, Z> Executor<EM, Z> for QuicExecutor<OT, S,SP>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions + HasCorpus + HasSolutions +HasRandSeed,
    S::Input: HasTargetBytes,
    SP: ShMemProvider,
    OT: MatchName + ObserversTuple<S>,
    Z: UsesState<State = S> {
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<libafl::prelude::ExitKind, libafl::prelude::Error> {

        let mut is_first = false;
        if self.start_command.contains("lsquic.sh") {
            is_first = true;
        }
        if is_first {
            self.frame_rand_seed = unsafe {rand().try_into().unwrap()};
            // info!("now {:?} corpus",state.corpus().count());
        }
        info!("running corpus: {:?}", state.corpus().current());

        *state.executions_mut() += 1;



        let binding = input.target_bytes();
        let mut inputs = binding.as_slice();   
        self.write_to_quic_shm_seed(&inputs,self.frame_rand_seed);
        self.wait_for_quic_shm_res();
        if is_first {
            let multi_map_ob_handle = HitcountsIterableMapObserver::new(MultiMapObserver::new("combined-edges", Vec::<libafl_bolts::ownedref::OwnedMutSlice<u8>>::new())).handle();
            let hit_multi_map_ob = self.observers.get(&multi_map_ob_handle).unwrap();
            let multi_map_ob = &hit_multi_map_ob.base;
            let map_fir = &multi_map_ob.maps[0];
            let map_sec = &multi_map_ob.maps[1];
            let initial = multi_map_ob.initial();
            let mut first_count = 0;
            let mut sec_count = 0;
            for x in map_fir.as_slice() {
                if *x != initial {
                    first_count += 1;
                }
            }
            for x in map_sec.as_slice() {
                if *x != initial {
                    sec_count += 1;
                }
            }
            let first_total = map_fir.as_slice().len();
            let sec_total = map_sec.as_slice().len();
            warn!("cov_fir cnt/tot: {:?}/{:?}",first_count,first_total);
            warn!("cov_sec cnt/tot: {:?}/{:?}",sec_count,sec_total);
        }

        let exit_kind = self.update_all_obs();
        Ok(exit_kind)
    }
}

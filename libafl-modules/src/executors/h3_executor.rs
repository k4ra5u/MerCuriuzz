use h3i::actions::h3::{Action, StreamEventType};
use h3i::frame::H3iFrame;
use libafl::{
    corpus::Corpus,
    events::{Event, EventFirer},
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::{
        get_asan_runtime_flags_with_log_path, AsanBacktraceObserver, ObserversTuple, UsesObservers,
    },
    state::{HasCorpus, HasExecutions, HasRandSeed, HasSolutions, State, UsesState},
};
use libafl_bolts::{
    rands,
    shmem::{ShMem, ShMemId, ShMemProvider, UnixShMemProvider},
    tuples::{Handle, Handled, MatchName, MatchNameRef, Prepend, RefIndexable},
    AsSlice, AsSliceMut, Truncate,
};
use libc::{rand, srand, ETH_DATA_LEN};
use libc::{CODA_SUPER_MAGIC, ERA};
use log::{debug, error, info, warn};
use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::TimeSpec,
        wait::waitpid,
    },
    unistd::Pid,
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use ring::rand::*;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::ParseIntError;
use std::panic::{self, AssertUnwindSafe};
use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, prelude::*, BufRead, ErrorKind, Read, Write},
    marker::PhantomData,
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Output, Stdio},
    str,
    thread::sleep,
    time::{Duration, Instant},
    vec,
};

use quiche::{
    h3::frame::Frame as H3Frame,
    frame::{self, EcnCounts, Frame, MAX_STREAM_SIZE},
    packet,
    ranges::{self, RangeSet},
    stream, Connection, ConnectionId, Error, FrameWithPkn, Header,
};

use crate::inputstruct::{
    h3_input::{deserialize_h3_struct, H3QpackStep},
    pkt_resort_type, quic_input::InputStruct_deserialize, FramesCycleStruct, H3Conn, H3Struct,
    InputStruct, QuicStruct,
};
use crate::misc::*;
use crate::observers::*;

//use crate::QuicStruct;
// use quic_input::{FramesCycleStruct, InputStruct, pkt_resort_type, QuicStruct};

const MAX_DATAGRAM_SIZE: usize = 1350;
const MAP_SIZE: usize = 0x100000;
const HTTP_REQ_STREAM_ID: u64 = 4;
const DEFAULT_H3_SERVER_START_WAIT_MS: u64 = 50;
const DEFAULT_H3_PRE_CONNECT_WAIT_MS: u64 = 5;
const DEFAULT_H3_MAX_TESTCASE_BYTES: usize = 4 * 1024 * 1024;

/// For experiment only, please use `STNyxExecutor` in production.

fn start_harness_with_envs(
    command: &str,
    envs: Vec<(OsString, OsString)>,
) -> Result<Output, std::io::Error> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output()
}

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    let millis = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_ms);
    Duration::from_millis(millis)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn split_h3_action_batches(actions: Vec<Action>) -> Vec<Vec<Action>> {
    let hard_limit = env_usize("MERCURIUZZ_H3_EXECUTOR_ACTION_BATCH_SIZE", 0);
    let split_on_flush = env_bool("MERCURIUZZ_H3_EXECUTOR_BATCH_ON_FLUSH", false);
    let mut batches = Vec::new();
    let mut current = Vec::new();

    for action in actions {
        let end_batch = split_on_flush && matches!(action, Action::FlushPackets);
        current.push(action);

        if end_batch || (hard_limit > 0 && current.len() >= hard_limit) {
            batches.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        batches.push(current);
    }

    batches
}

fn h3_target_label(start_command: &str, port: u16) -> String {
    let target = Path::new(start_command)
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or(start_command);
    format!("{target}@{port}")
}

fn log_h3_replay_stats(
    target_label: &str,
    total_sent_actions: u64,
    total_recv_h3_frames: usize,
    total_sent_pkts: u64,
    total_sent_initial_pkts: u64,
    total_sent_handshake_pkts: u64,
    total_sent_0rtt_pkts: u64,
    total_sent_short_pkts: u64,
    total_sent_short_data_pkts: u64,
    total_sent_short_control_pkts: u64,
    total_sent_ack_eliciting_pkts: u64,
    total_recv_pkts: usize,
    total_sent_bytes: usize,
    total_recv_bytes: usize,
) {
    info!(
        "h3 replay stats [{}]: sent_actions={} recv_h3_frames={} sent_udp_pkts={} sent_initial_pkts={} sent_handshake_pkts={} sent_0rtt_pkts={} sent_short_pkts={} sent_short_data_pkts={} sent_short_control_pkts={} sent_ack_eliciting_pkts={} recv_udp_pkts={} sent_udp_bytes={} recv_udp_bytes={}",
        target_label,
        total_sent_actions,
        total_recv_h3_frames,
        total_sent_pkts,
        total_sent_initial_pkts,
        total_sent_handshake_pkts,
        total_sent_0rtt_pkts,
        total_sent_short_pkts,
        total_sent_short_data_pkts,
        total_sent_short_control_pkts,
        total_sent_ack_eliciting_pkts,
        total_recv_pkts,
        total_sent_bytes,
        total_recv_bytes
    );

    if total_recv_pkts > 0 && total_recv_h3_frames == 0 {
        info!(
            "h3 replay verdict [{}]: peer replied with QUIC transport packets but no H3 frames; inspect pcap/qlog for ACK/MAX_DATA/MAX_STREAM_DATA details",
            target_label
        );
    }

    if total_sent_short_data_pkts > 0 && total_recv_h3_frames == 0 {
        info!(
            "h3 replay verdict [{}]: client emitted {} app-data-carrying 1-RTT packets, but peer produced no H3 frames; inspect server logs or qlog for blocked QPACK / stream-level handling",
            target_label,
            total_sent_short_data_pkts
        );
    } else if total_sent_pkts > 0 && total_recv_h3_frames == 0 {
        info!(
            "h3 replay verdict [{}]: no app-data-carrying 1-RTT packets were emitted; sent_udp_pkts only reflects handshake or transport-control traffic",
            target_label
        );
    } else if total_sent_actions > 0 && total_sent_pkts == 0 {
        info!(
            "h3 replay verdict [{}]: actions were executed but quiche emitted no UDP packets; inspect flush cadence, congestion state, and send buffering",
            target_label
        );
    }
}

fn modeled_request_stream_ids(h3_struct: &H3Struct) -> BTreeSet<u64> {
    let mut stream_ids = BTreeSet::new();

    for (index, _) in h3_struct.data_blocks.iter().enumerate() {
        stream_ids.insert((index as u64) * 4);
    }

    for step in &h3_struct.qpack_plan.steps {
        if let H3QpackStep::RequestHeaderBlock { stream_id, .. } = step {
            stream_ids.insert(*stream_id);
        }
    }

    stream_ids
}

fn initial_request_semantics(h3_struct: &H3Struct) -> Vec<H3RequestSemantic> {
    modeled_request_stream_ids(h3_struct)
        .into_iter()
        .map(H3RequestSemantic::new)
        .collect()
}

fn initial_qpack_progress(h3_struct: &H3Struct) -> Vec<H3QpackRequestProgress> {
    let mut qpack_requests = Vec::new();
    let mut seen_streams = HashSet::new();

    for step in &h3_struct.qpack_plan.steps {
        if let H3QpackStep::RequestHeaderBlock {
            stream_id, block, ..
        } = step
        {
            if seen_streams.insert(*stream_id) {
                qpack_requests.push(H3QpackRequestProgress {
                    stream_id: *stream_id,
                    requires_dynamic_state: requires_dynamic_state(block),
                    required_insert_count: block.required_insert_count,
                    base: block.base,
                    first_visible_response_batch: None,
                    first_terminal_batch: None,
                    stalled: false,
                });
            }
        }
    }

    qpack_requests
}

pub struct H3Executor<OT, S, SP>
where
    SP: ShMemProvider,
{
    pub start_command: String,
    pub judge_command: String,
    pub is_first: bool,
    pub envs: Vec<(OsString, OsString)>,
    pub port: u16,
    pub timeout: Duration,
    pub observers: OT,
    pub phantom: std::marker::PhantomData<S>,
    pub map: Option<SP::ShMem>,
    pub map_size: Option<usize>,
    pub kill_signal: Option<Signal>,
    pub asan_obs: Option<Handle<AsanBacktraceObserver>>,
    pub crash_exitcode: Option<i8>,
    pub shmem_provider: SP,
    pub pid: u32,
    pub quic_shm_id: String,
    pub quic_shm_size: usize,
    pub h3_conn: Option<H3Conn>,
    pub recv_pkts: usize,
    pub non_res_times: usize,
    pub frame_rand_seed: u32,
    pub coverage_map1: Vec<bool>,
    pub coverage_map2: Vec<bool>,
    pub coverage_map1_shmem_id: Option<String>,
    pub coverage_map2_shmem_id: Option<String>,
}

pub struct H3ExecutorBuilder<'a, SP>
where
    SP: ShMemProvider,
{
    start_command: String,
    judge_command: String,
    envs: Vec<(OsString, OsString)>,
    port: u16,
    timeout: Duration,
    map: Option<SP::ShMem>,
    map_size: Option<usize>,
    kill_signal: Option<Signal>,
    asan_obs: Option<Handle<AsanBacktraceObserver>>,
    crash_exitcode: Option<i8>,
    shmem_provider: &'a mut SP,
    pid: u32,
    h3_conn: Option<H3Conn>,
    frame_rand_seed: u64,
}

// impl H3Executor<(), (), UnixShMemProvider> {
//     /// Builder for `H3Executor`
//     #[must_use]
//     pub fn builder() -> H3ExecutorBuilder<'static, UnixShMemProvider> {
//         H3ExecutorBuilder::new()
//     }
// }

impl<OT, S, SP> H3Executor<OT, S, SP>
where
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    pub fn new(observers: OT, shmem_provider: SP) -> Self {
        Self {
            start_command: "".to_owned(),
            judge_command: "".to_owned(),
            is_first: false,
            envs: vec![],
            port: 80,
            timeout: Duration::from_millis(100),
            observers,
            phantom: std::marker::PhantomData,
            map: None,
            map_size: None,
            kill_signal: None,
            asan_obs: None,
            crash_exitcode: None,
            shmem_provider,
            pid: 0,
            quic_shm_id: String::new(),
            quic_shm_size: 0,
            h3_conn: None,
            recv_pkts: 0,
            non_res_times: 0,
            frame_rand_seed: 0,
            coverage_map1: vec![false; MAP_SIZE],
            coverage_map2: vec![false; MAP_SIZE],
            coverage_map1_shmem_id: None,
            coverage_map2_shmem_id: None,
        }
    }

    pub fn start_command(mut self, str: String) -> Self {
        let base_dir = env::var("START_DIR").unwrap();
        self.start_command = format!("{base_dir}/{str}.sh");
        info!("start_command: {:?}", self.start_command);
        self
    }

    pub fn judge_command(mut self, str: String) -> Self {
        let base_dir = env::var("JUDGE_DIR").unwrap();
        self.judge_command = format!("{base_dir}/{str}-judge.sh");
        info!("judge_command: {:?}", self.judge_command);
        self
    }

    pub fn is_first(mut self) -> Self {
        self.is_first = true;
        self
    }
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn coverage_map_size(mut self, size: usize) -> Self {
        self.map_size = Some(size);
        self
    }

    pub fn coverage_shmem_ids(mut self, first: String, second: String) -> Self {
        self.coverage_map1_shmem_id = Some(first);
        self.coverage_map2_shmem_id = Some(second);
        self
    }

    pub fn set_frame_seed(mut self, seed: u32) -> Self {
        self.frame_rand_seed = seed;
        self
    }
    pub fn change_recv_pkts(&mut self, nums: usize) {
        self.recv_pkts = nums;
    }

    pub fn change_non_res_times(&mut self, nums: usize) {
        self.non_res_times = nums;
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

    pub fn kill_signal(mut self, kill_signal: Signal) -> Self {
        self.kill_signal = Some(kill_signal);
        self
    }

    pub fn asan_obs(mut self, asan_obs: Handle<AsanBacktraceObserver>) -> Self {
        self.asan_obs = Some(asan_obs);
        self
    }

    fn maybe_emit_historical_coverage_stats<EM>(
        &mut self,
        state: &mut S,
        mgr: &mut EM,
    ) -> Result<(), libafl::prelude::Error>
    where
        S: HasExecutions,
        EM: EventFirer<State = S>,
    {
        let Some(first_shmem_id) = self.coverage_map1_shmem_id.as_deref() else {
            return Ok(());
        };
        let Some(second_shmem_id) = self.coverage_map2_shmem_id.as_deref() else {
            return Ok(());
        };

        let completed_targets = *state.executions();
        if completed_targets == 0 || completed_targets % 2 != 0 {
            return Ok(());
        }

        let map_size = self.map_size.unwrap_or(MAP_SIZE);
        let mut shmem_provider = self.shmem_provider.clone();
        let first_shmem = shmem_provider
            .shmem_from_id_and_size(ShMemId::from_string(first_shmem_id), map_size)?;
        let second_shmem = shmem_provider
            .shmem_from_id_and_size(ShMemId::from_string(second_shmem_id), map_size)?;
        let map_fir = first_shmem.as_slice();
        let map_sec = second_shmem.as_slice();

        if self.coverage_map1.len() != map_fir.len() {
            self.coverage_map1.resize(map_fir.len(), false);
        }
        if self.coverage_map2.len() != map_sec.len() {
            self.coverage_map2.resize(map_sec.len(), false);
        }

        let mut first_count = 0usize;
        let mut sec_count = 0usize;
        let first_total = map_fir.len();
        let sec_total = map_sec.len();

        for (slot, &edge) in self.coverage_map1.iter_mut().zip(map_fir.iter()) {
            if edge != 0 {
                *slot = true;
            }
            if *slot {
                first_count += 1;
            }
        }
        for (slot, &edge) in self.coverage_map2.iter_mut().zip(map_sec.iter()) {
            if edge != 0 {
                *slot = true;
            }
            if *slot {
                sec_count += 1;
            }
        }

        let total_count = first_count + sec_count;
        let total_total = first_total + sec_total;
        let coverage_line = format!(
            "first={first_count}/{first_total} | second={sec_count}/{sec_total} | total={total_count}/{total_total}"
        );

        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("history-coverage"),
                value: UserStats::new(
                    UserStatsValue::String(Cow::Owned(coverage_line)),
                    AggregatorOps::None,
                ),
                phantom: PhantomData,
            },
        )?;

        Ok(())
    }

    pub fn update_recv_pkt_obs(&mut self, buf_obs: RecvPktNumObserver) {
        let recv_pkt_num_observer_ref = RecvPktNumObserver::new("recv_pkt_num").handle();
        if let Some(recv_pkt_num_observer) = self.observers.get_mut(&recv_pkt_num_observer_ref) {
            recv_pkt_num_observer.set_recv_bytes(buf_obs.get_recv_bytes());
            recv_pkt_num_observer.set_recv_pkts(buf_obs.get_recv_pkts());
            recv_pkt_num_observer.set_send_bytes(buf_obs.get_send_bytes());
            recv_pkt_num_observer.set_send_pkts(buf_obs.get_send_pkts());
        }
    }

    pub fn update_h3_semantic_obs(&mut self, summary: H3RunSemanticSummary) {
        let h3_semantic_observer_ref = H3SemanticObserver::new("h3_semantic").handle();
        if let Some(h3_semantic_observer) = self.observers.get_mut(&h3_semantic_observer_ref) {
            h3_semantic_observer.set_summary(summary);
        }
    }

    pub fn set_initial_mem_usage(&mut self) -> bool {
        let mem_observer_ref = MemObserver::new("mem").handle();
        if let Some(mem_observer) = self.observers.get_mut(&mem_observer_ref) {
            if self.pid != mem_observer.pid {
                mem_observer.reset_measurement();
                mem_observer.set_pid(self.pid);
            }
            if mem_observer.capture_before_snapshot() {
                if mem_observer.initial_mem == 0 {
                    warn!(
                        "initial_mem is 0, set to before_mem: {}",
                        mem_observer.before_mem
                    );
                }
                return true;
            }
            error!(
                "Failed to capture initial memory snapshot for pid {}",
                mem_observer.pid
            );
        }
        false
    }

    pub fn inital_first_cpu_usage_obs(&mut self) {
        let cpu_usage_observer = CPUUsageObserver::new("first_cpu_usage");
        let cpu_usage_observer_ref = cpu_usage_observer.handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            cpu_usage_observer.set_pid(self.pid as u32);
            // cpu_usage_observer.add_cpu_id(50);
            // cpu_usage_observer.add_cpu_id(51);
            // cpu_usage_observer.add_cpu_id(22);
            // cpu_usage_observer.add_cpu_id(23);
            let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
            cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);
        }
    }

    pub fn inital_second_cpu_usage_obs(&mut self) {
        let cpu_usage_observer = CPUUsageObserver::new("second_cpu_usage");
        let cpu_usage_observer_ref = cpu_usage_observer.handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            cpu_usage_observer.set_pid(self.pid as u32);
            // cpu_usage_observer.add_cpu_id(52);
            // cpu_usage_observer.add_cpu_id(53);
            // cpu_usage_observer.add_cpu_id(22);
            // cpu_usage_observer.add_cpu_id(23);
            let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
            cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);
        }
    }

    pub fn get_first_cpu_usage_ob_mut(&mut self) -> &mut CPUUsageObserver {
        let cpu_usage_observer_ref = CPUUsageObserver::new("first_cpu_usage").handle();
        self.observers.get_mut(&cpu_usage_observer_ref).unwrap()
    }
    pub fn get_second_cpu_usage_ob_mut(&mut self) -> &mut CPUUsageObserver {
        let cpu_usage_observer_ref = CPUUsageObserver::new("second_cpu_usage").handle();
        self.observers.get_mut(&cpu_usage_observer_ref).unwrap()
    }

    pub fn update_first_cpu_usage_obs(&mut self, cur_cpu_usages: Vec<f64>) -> bool {
        let cpu_usage_observer_ref = CPUUsageObserver::new("first_cpu_usage").handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            if !cpu_usage_observer.judge_proc_exist() {
                return false;
            }
            for cur_cpu_usage in cur_cpu_usages.iter() {
                cpu_usage_observer.add_record_cpu_usage(*cur_cpu_usage);
                cpu_usage_observer.add_frame_record_times();
                let curr_process_time = match get_process_cpu_time(cpu_usage_observer.pid) {
                    Some(time) => time,
                    None => {
                        error!("Failed to get process CPU time");
                        return false;
                    }
                };
                let curr_cpu_times = match get_cpu_time(&cpu_usage_observer.cpu_ids) {
                    Some(times) => times,
                    None => {
                        error!("Failed to get CPU core times");
                        return false;
                    }
                };
                cpu_usage_observer.prev_cpu_times = curr_cpu_times.clone();
                cpu_usage_observer.prev_process_time = curr_process_time;
            }
        }
        return true;
    }

    pub fn update_second_cpu_usage_obs(&mut self, cur_cpu_usages: Vec<f64>) -> bool {
        let cpu_usage_observer_ref = CPUUsageObserver::new("second_cpu_usage").handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            if !cpu_usage_observer.judge_proc_exist() {
                return false;
            }
            for cur_cpu_usage in cur_cpu_usages.iter() {
                cpu_usage_observer.add_record_cpu_usage(*cur_cpu_usage);
                cpu_usage_observer.add_frame_record_times();
                let curr_process_time = match get_process_cpu_time(cpu_usage_observer.pid) {
                    Some(time) => time,
                    None => {
                        error!("Failed to get process CPU time");
                        return false;
                    }
                };
                let curr_cpu_times = match get_cpu_time(&cpu_usage_observer.cpu_ids) {
                    Some(times) => times,
                    None => {
                        error!("Failed to get CPU core times");
                        return false;
                    }
                };
                cpu_usage_observer.prev_cpu_times = curr_cpu_times.clone();
                cpu_usage_observer.prev_process_time = curr_process_time;
            }
        }
        return true;
    }
    pub fn cc_observer_update(
        &mut self,
        pkn: u64,
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    ) {
        let cc_times_observer_ref = CCTimesObserver::new("cc_time").handle();
        if let Some(cc_times_observer) = self.observers.get_mut(&cc_times_observer_ref) {
            cc_times_observer.pkn = pkn;
            cc_times_observer.error_code = error_code;
            cc_times_observer.frame_type = frame_type;
            cc_times_observer.reason = match String::from_utf8(reason) {
                Ok(val) => val,
                Err(e) => {
                    error!("Failed to convert reason to UTF-8: {}", e);
                    "Invalid UTF-8".to_string()
                }
            };
        }
    }

    pub fn ack_observer_add_range(&mut self, ranges: RangeSet) {
        let ack_observer_ref = ACKRangeObserver::new("ack").handle();
        if let Some(ack_observer) = self.observers.get_mut(&ack_observer_ref) {
            ranges.iter().for_each(|range| {
                ack_observer.add_ACK_range(range.start, range.end);
            });
        }
    }

    pub fn ctrl_observer_add_frame(&mut self, frames: Vec<Frame>) {
        let ctrl_observer_ref = RecvControlFrameObserver::new("ctrl").handle();
        if let Some(ctrl_observer) = self.observers.get_mut(&ctrl_observer_ref) {
            for frame in frames.iter() {
                ctrl_observer.add_frame_list(frame.clone());
            }
        }
    }

    pub fn data_observer_add_frame(
        &mut self,
        crypto_frames: Vec<FrameWithPkn>,
        stream_frames: Vec<FrameWithPkn>,
        pr_frames: Vec<FrameWithPkn>,
        dgram_frames: Vec<FrameWithPkn>,
    ) {
        let data_observer_ref = RecvDataFrameObserver::new("data").handle();
        if let Some(data_observer) = self.observers.get_mut(&data_observer_ref) {
            for frame in crypto_frames.iter() {
                data_observer.add_crypto_frame_list(frame.clone());
            }
            for frame in stream_frames.iter() {
                data_observer.add_stream_frame_list(frame.clone());
            }
            for frame in pr_frames.iter() {
                data_observer.add_pr_frame_list(frame.clone());
            }
            for frame in dgram_frames.iter() {
                data_observer.add_dgram_frame_list(frame.clone());
            }
        }
    }

    pub fn handle_frames(&mut self, recv_frames: Vec<FrameWithPkn>) {
        let mut ctrl_frames: Vec<Frame> = Vec::new();
        let mut crypto_frames: Vec<FrameWithPkn> = Vec::new();
        let mut stream_frames: Vec<FrameWithPkn> = Vec::new();
        let mut pr_frames: Vec<FrameWithPkn> = Vec::new();
        let mut dgram_frames: Vec<FrameWithPkn> = Vec::new();
        let mut cc_times = 0;
        for recv_frame in recv_frames.iter() {
            match &recv_frame.frame {
                frame::Frame::Padding { .. } => (),
                frame::Frame::Ping { .. } => (),
                frame::Frame::ACK {
                    ranges,
                    ack_delay,
                    ecn_counts,
                } => {
                    self.ack_observer_add_range(ranges.clone());
                    ranges.iter().for_each(|range| {
                        debug!("ack range: {:?}", range);
                    });
                }
                frame::Frame::ResetStream { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::StopSending { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::Crypto { data } => {
                    crypto_frames.push(recv_frame.clone());
                }
                frame::Frame::NewToken { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::Stream { data, stream_id } => {
                    stream_frames.push(recv_frame.clone());
                }
                frame::Frame::MaxData { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::MaxStreamData { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::MaxStreamsBidi { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::DataBlocked { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::StreamDataBlocked { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::StreamsBlockedBidi { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::NewConnectionId { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::RetireConnectionId { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::PathChallenge { .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::PathResponse { data } => {
                    pr_frames.push(recv_frame.clone());
                }
                frame::Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    self.cc_observer_update(
                        recv_frame.pkn,
                        *error_code,
                        *frame_type,
                        reason.clone(),
                    );
                }
                frame::Frame::ApplicationClose { error_code, reason } => {
                    self.cc_observer_update(recv_frame.pkn, *error_code, 0, reason.clone());
                }
                frame::Frame::HandshakeDone => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::Datagram { data } => {
                    dgram_frames.push(recv_frame.clone());
                }
                frame::Frame::DatagramHeader { length } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::CryptoHeader { offset, length } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::Others { .. } => (),
                frame::Frame::StreamHeader {
                    stream_id,
                    offset,
                    length,
                    fin,
                } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::MaxStreamsUni { max } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
                frame::Frame::StreamsBlockedUni { limit } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                }
            }
        }
        self.ctrl_observer_add_frame(ctrl_frames);
        self.data_observer_add_frame(crypto_frames, stream_frames, pr_frames, dgram_frames);
    }

    pub fn pcap_observer_update_get_name(&mut self) -> String {
        let pcap_observer_ref = PcapObserver::new("pcap").handle();
        if let Some(pcap_observer) = self.observers.get_mut(&pcap_observer_ref) {
            pcap_observer.port = self.port;
            pcap_observer.new_record.port = self.port;
            pcap_observer.new_record.name.clone()
        } else {
            String::new()
        }
    }

    pub fn sync_srand_seed_path(&mut self, pcap_path: String) {
        let misc_observer_ref = MiscObserver::new("misc").handle();
        if let Some(misc_observer) = self.observers.get_mut(&misc_observer_ref) {
            misc_observer.srand_seed = self.frame_rand_seed;
        }
    }

    pub fn nor_conn_ob_connect(&mut self) {
        let conn_observer_ref = NormalConnObserver::new(
            "conn",
            "127.0.0.1".to_owned(),
            self.port,
            "myserver.xx".to_owned(),
        )
        .handle();
        if let Some(conn_observer) = self.observers.get_mut(&conn_observer_ref) {
            conn_observer.calc_pre_spend_time();
        }
    }

    pub fn build_h3_conn_struct(
        mut self,
        server_name: String,
        server_port: u16,
        server_host: String,
    ) -> Self {
        let h3_conn = H3Conn::new(server_name, server_port, server_host);
        self.h3_conn = Some(h3_conn);
        self
    }

    pub fn rebuild_h3_conn_struct(&mut self) {
        let server_name = self.h3_conn.as_ref().unwrap().server_name.clone();
        let server_port = self.h3_conn.as_ref().unwrap().server_port;
        let server_host = self.h3_conn.as_ref().unwrap().server_host.clone();
        //drop(self.h3_conn);
        self.h3_conn = Some(H3Conn::new(server_name, server_port, server_host));
    }

    pub fn build(mut self) -> Self
    where
        SP: ShMemProvider,
    {
        let mut shmem = self.shmem_provider.new_shmem(0x10000).unwrap();
        shmem.write_to_env("__AFL_SHM_FUZZ_ID");

        let size_in_bytes = (0x1000u32).to_ne_bytes();
        shmem.as_slice_mut()[..4].clone_from_slice(&size_in_bytes[..4]);
        let map = shmem;
        self.map = Some(map);
        self
    }

    pub fn get_coverage_map_size(&self) -> Option<usize> {
        self.map_size
    }

    pub fn judge_server_status(&self) -> u32 {
        // warn!("judge_server_status:{:?}",self.judge_command);
        let output = std::process::Command::new(&self.judge_command)
            .output()
            .expect("Failed to execute command");

        // 检查命令的执行状态
        if output.status.success() {
            // 处理标准输出
            let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");
            debug!("Command executed successfully:\n{}", stdout);
            // println!("Command executed successfully:\n{}", stdout);
            match stdout.trim().parse::<u32>() {
                Ok(value) => return value,
                //Err(e) => {eprintln!("Failed to parse integer: {}", e);return 0},
                Err(e) => {
                    debug!("Failed to parse integer: {}", e);
                    return 0;
                }
            }
        } else {
            // 处理标准错误输出
            let stderr = str::from_utf8(&output.stderr).expect("Invalid UTF-8 in stderr");
            // eprintln!("Command failed with error:\n{}", stderr);
            return 0;
        }
    }
}

impl<OT, S, SP> UsesState for H3Executor<OT, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    type State = S;
}

impl<OT, S, SP> UsesObservers for H3Executor<OT, S, SP>
where
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type Observers = OT;
}

impl<OT, S, SP> HasObservers for H3Executor<OT, S, SP>
where
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<EM, OT, S, SP, Z> Executor<EM, Z> for H3Executor<OT, S, SP>
where
    EM: EventFirer<State = S>,
    S: State + HasExecutions + HasCorpus + HasSolutions + HasRandSeed,
    S::Input: HasTargetBytes,
    SP: ShMemProvider,
    OT: MatchName + ObserversTuple<S>,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<libafl::prelude::ExitKind, libafl::prelude::Error> {
        //let mut observers: RefIndexable<&mut OT, OT> = self.observers_mut();
        // info!("now seed:{:?}",self.frame_rand_seed);
        let decode_start = Instant::now();
        let replay_target = h3_target_label(&self.start_command, self.port);
        let binding = input.target_bytes();
        let inputs = binding.as_slice();
        let max_testcase_bytes = env_usize(
            "MERCURIUZZ_H3_MAX_TESTCASE_BYTES",
            DEFAULT_H3_MAX_TESTCASE_BYTES,
        );
        if max_testcase_bytes > 0 && inputs.len() > max_testcase_bytes {
            warn!(
                "h3 testcase skipped [{}]: testcase_bytes={} limit={}",
                replay_target,
                inputs.len(),
                max_testcase_bytes
            );
            return Ok(ExitKind::Ok);
        }
        let mut h3_struct: H3Struct = deserialize_h3_struct(inputs).unwrap();
        info!(
            "h3 input decode: testcase_bytes={} deserialize_elapsed={:?}",
            inputs.len(),
            decode_start.elapsed()
        );
        let mut is_first = false;
        if self.is_first {
            is_first = true;
        }
        // for check_corpus to replay the srand seed
        if state.rand_seed() != 0 {
            warn!("checking corpus: seed_{:?}", state.rand_seed());
            self.frame_rand_seed = state.rand_seed();
            if !is_first {
                state.set_rand_seed(0);
            }
        }
        //TODO: del
        // let pcap_path = gen_pcap_path();
        let pcap_path = self.pcap_observer_update_get_name();
        self.sync_srand_seed_path(pcap_path.clone());

        unsafe {
            srand(self.frame_rand_seed);
        }
        self.frame_rand_seed = unsafe { rand().try_into().unwrap() };
        // info!("now {:?} corpus",state.corpus().count());
        debug!("running corpus: {:?}", state.corpus().current());

        //let mut recv_pkt_num_observer = None;
        // for observer in observers.iter() {
        //     if let Some(recv_pkt_num_observer) = observer.downcast_mut::<RecvPktNumObserver>() {}
        // }

        let mut buf_recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
        // let cc_times_observer_ref = CCTimesObserver::new("cc_times").handle();
        // let mut cc_times_observer = self.observers.get_mut(&cc_times_observer_ref).unwrap();
        // let mut buf_asan_backtrace_observer = AsanBacktraceObserver::new("asan_backtrace");

        let mut out = [0; MAX_DATAGRAM_SIZE << 10];
        let mut exit_kind = ExitKind::Ok;
        let mut total_recv_pkts = 0;
        let mut total_recv_bytes = 0;
        let mut cur_cpu_usages: Vec<f64> = Vec::new();
        let mut total_recv_frames: Vec<FrameWithPkn> = Vec::new();
        *state.executions_mut() += 1;
        for (key, value) in &self.envs {
            std::env::set_var(key, value);
        }
        // let res = self.judge_server_status();
        // // 快照功能不完善，目前每次fuzz重启服务
        // // 尝试不重启服务，只重新建立连接
        // if res !=0 {
        //     std::process::Command::new("sh").arg("-c").arg(format!("kill -9 {}",res))
        //     .stdout(Stdio::null())
        //     .stderr(Stdio::null())
        //     .status()
        //     .unwrap();
        // }
        let mut pid = self.judge_server_status();
        let startup_phase = Instant::now();
        // 如果服务未启动，则启动服务
        // warn!("non_res_times:{:?} recv_pkts:{:?}",self.non_res_times,self.recv_pkts);
        debug!("pid:{:?},recore_pid:{:?}", pid, self.pid);
        if pid != self.pid {
            debug!("pid not match");
        }
        if pid == 0 || self.pid == 0 || pid != self.pid {
            let mut start_attempts = 0usize;
            while (true) {
                start_attempts += 1;
                info!(
                    "h3 startup [{}]: launching harness attempt={} old_pid={} recorded_pid={}",
                    replay_target, start_attempts, pid, self.pid
                );
                info!("{:?}", self.envs);
                let command_start = Instant::now();
                match start_harness_with_envs(&self.start_command, self.envs.clone()) {
                    Ok(output) => {
                        let elapsed = command_start.elapsed();
                        info!(
                            "h3 startup [{}]: start command exited status={:?} elapsed={:?}",
                            replay_target,
                            output.status.code(),
                            elapsed
                        );
                        if !output.stdout.is_empty() {
                            debug!(
                                "h3 startup [{}] stdout: {}",
                                replay_target,
                                String::from_utf8_lossy(&output.stdout)
                            );
                        }
                        if !output.stderr.is_empty() {
                            debug!(
                                "h3 startup [{}] stderr: {}",
                                replay_target,
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "h3 startup [{}]: start command failed after {:?}: {:?}",
                            replay_target,
                            command_start.elapsed(),
                            e
                        );
                    }
                }
                // std::process::Command::new("sh").arg("-c").arg(&self.start_command)
                // .output()
                // .unwrap();
                let server_wait = env_duration_ms(
                    "MERCURIUZZ_H3_SERVER_START_WAIT_MS",
                    DEFAULT_H3_SERVER_START_WAIT_MS,
                );
                if !server_wait.is_zero() {
                    debug!(
                        "h3 startup [{}]: waiting {:?} before judge_server_status",
                        replay_target, server_wait
                    );
                    sleep(server_wait);
                }
                pid = self.judge_server_status();
                info!(
                    "h3 startup [{}]: judge_server_status returned pid={} after {:?}",
                    replay_target,
                    pid,
                    startup_phase.elapsed()
                );
                // info!("pid:{:?}",pid);
                if pid == 0 {
                    error!("Failed to start server");
                } else {
                    break;
                }
            }
            self.pid = pid;
            info!(
                "h3 startup [{}]: harness ready pid={} total_elapsed={:?}",
                replay_target,
                self.pid,
                startup_phase.elapsed()
            );
        } else {
            info!(
                "h3 startup [{}]: reusing existing pid={} total_elapsed={:?}",
                replay_target,
                self.pid,
                startup_phase.elapsed()
            );
        }
        debug!("pid:{:?}", self.pid);
        let set_mem = self.set_initial_mem_usage();
        if set_mem == false {
            warn!("Failed to set initial memory usage");
            return Ok(ExitKind::Crash);
        }

        if is_first {
            self.inital_first_cpu_usage_obs();
            // self.get_first_cpu_usage_ob_mut()
        } else {
            self.inital_second_cpu_usage_obs();
            // self.get_first_cpu_usage_ob_mut();
        };

        // let mut capture_process = start_capture(self.port,pcap_path.clone());
        let pre_connect_wait = env_duration_ms(
            "MERCURIUZZ_H3_PRE_CONNECT_WAIT_MS",
            DEFAULT_H3_PRE_CONNECT_WAIT_MS,
        );
        if !pre_connect_wait.is_zero() {
            debug!(
                "h3 startup [{}]: pre-connect wait {:?}",
                replay_target, pre_connect_wait
            );
            sleep(pre_connect_wait);
        }

        // self.nor_conn_ob_connect();

        let cpu_usage_observer_ref = if is_first {
            CPUUsageObserver::new("first_cpu_usage").handle()
        } else {
            CPUUsageObserver::new("second_cpu_usage").handle()
        };

        //h3_conn 必须存在，检查 h3_conn 合法性
        let mut valid_h3_conn = false;
        if valid_h3_conn == false || self.non_res_times >= 3 {
            debug!("judged connection closed");
            self.rebuild_h3_conn_struct();
        }

        let mut need_rebuild_h3_conn = false;
        {
            let mut h3_conn = self.h3_conn.as_mut().unwrap();
            match &mut h3_conn.conn {
                None => {
                    for _ in 0..2 {
                        self.rebuild_h3_conn_struct();
                        h3_conn = self.h3_conn.as_mut().unwrap();
                        let connect_start = Instant::now();
                        match h3_conn.connect() {
                            Err(e) => {
                                error!(
                                    "h3 startup [{}]: connect failed after {:?}: {:?}",
                                    replay_target,
                                    connect_start.elapsed(),
                                    e
                                );
                                exit_kind = ExitKind::Crash;
                            }
                            Ok(_) => {
                                info!(
                                    "h3 startup [{}]: connect succeeded in {:?}",
                                    replay_target,
                                    connect_start.elapsed()
                                );
                                exit_kind = ExitKind::Ok;
                                break;
                            }
                        }
                    }
                }

                Some(_) => {}
            }
            debug!(
                "Connection established, from {:?} to {:?}",
                h3_conn.local_addr.port(),
                h3_conn.peer_addr.port()
            );
        }
        if exit_kind == ExitKind::Crash {
            error!("Failed to connect, markd as crash");
            //send stop to pid
            std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("kill -9 {}", self.pid))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            self.pid = 0;
            // stop_capture(capture_process);
            self.maybe_emit_historical_coverage_stats(state, _mgr)?;
            return Ok(exit_kind);
        }
        let cpu_usage_observer = self.observers.get_mut(&cpu_usage_observer_ref).unwrap();

        let lost_time_dur = h3_struct.send_timeout;
        // let lost_time_dur = 0;
        let recv_time = h3_struct.recv_timeout;
        let mut recv_left_time = recv_time;
        let mut request_semantics = initial_request_semantics(&h3_struct);
        let request_semantic_indexes: HashMap<u64, usize> = request_semantics
            .iter()
            .enumerate()
            .map(|(index, request)| (request.stream_id, index))
            .collect();
        let mut qpack_progress = initial_qpack_progress(&h3_struct);
        let qpack_progress_indexes: HashMap<u64, usize> = qpack_progress
            .iter()
            .enumerate()
            .map(|(index, request)| (request.stream_id, index))
            .collect();
        let mut close_semantic = H3CloseSemantic::default();

        let mut total_sent_actions: u64 = 0;
        let mut total_sent_pkts: u64 = 0;
        let mut total_sent_initial_pkts: u64 = 0;
        let mut total_sent_handshake_pkts: u64 = 0;
        let mut total_sent_0rtt_pkts: u64 = 0;
        let mut total_sent_short_pkts: u64 = 0;
        let mut total_sent_short_data_pkts: u64 = 0;
        let mut total_sent_short_control_pkts: u64 = 0;
        let mut total_sent_ack_eliciting_pkts: u64 = 0;
        let mut total_sent_bytes = 0;
        let mut total_recv_h3_frames = 0;
        let gen_frames_start = Instant::now();
        let total_actions = h3_struct.gen_frames();
        let gen_frames_elapsed = gen_frames_start.elapsed();
        let total_actions_len = total_actions.len();
        let batch_split_start = Instant::now();
        let action_batches = split_h3_action_batches(total_actions);
        let batch_split_elapsed = batch_split_start.elapsed();
        let action_batches_len = action_batches.len();
        info!(
            "h3 replay plan [{}]: actions={} batches={} gen_frames_elapsed={:?} batch_split_elapsed={:?} split_on_flush={} batch_limit={}",
            replay_target,
            total_actions_len,
            action_batches_len,
            gen_frames_elapsed,
            batch_split_elapsed,
            env_bool("MERCURIUZZ_H3_EXECUTOR_BATCH_ON_FLUSH", false),
            env_usize("MERCURIUZZ_H3_EXECUTOR_ACTION_BATCH_SIZE", 0)
        );
        debug!("total action nums: {}", total_actions_len);
        debug!("total action batches: {}", action_batches_len);

        {
            let h3_conn = self.h3_conn.as_mut().unwrap();
            for (batch_index, take_list) in action_batches.into_iter().enumerate() {
                if take_list.is_empty() {
                    continue;
                }

                let batch_action_count = take_list.len() as u64;
                total_sent_actions += batch_action_count;
                debug!(
                    "h3 action batch {}/{} nums:{}",
                    batch_index + 1,
                    action_batches_len,
                    batch_action_count
                );
                debug!(
                    "h3 action batch {}/{}:{:?}",
                    batch_index + 1,
                    action_batches_len,
                    take_list
                );

                let old_hook = panic::take_hook();
                panic::set_hook(Box::new(|_| {}));
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    h3_conn.process_actions(take_list, self.timeout)
                }));
                panic::set_hook(old_hook);

                match result {
                    Ok(Ok(process_result)) => {
                        let summary = process_result.summary;
                        let observation = process_result.observation;
                        debug!("send_result: Ok({:?})", summary);
                        let batch_num = (batch_index + 1) as u32;
                        let batch_recv_h3_frames = observation
                            .per_stream_frames
                            .iter()
                            .map(|(_, frames)| frames.len())
                            .sum::<usize>();
                        total_recv_h3_frames += batch_recv_h3_frames;

                        let mut reset_streams = HashSet::new();
                        let mut batch_visible_streams = HashSet::new();
                        let mut batch_terminal_streams = HashSet::new();

                        for (stream_id, frames) in &observation.per_stream_frames {
                            let Some(request_index) = request_semantic_indexes.get(stream_id) else {
                                continue;
                            };
                            let request = &mut request_semantics[*request_index];

                            for frame in frames {
                                if matches!(frame, H3iFrame::Headers(_)) {
                                    batch_visible_streams.insert(*stream_id);
                                } else if matches!(frame, H3iFrame::QuicheH3(H3Frame::Data { .. })) {
                                    batch_visible_streams.insert(*stream_id);
                                } else if matches!(frame, H3iFrame::ResetStream(_)) {
                                    batch_terminal_streams.insert(*stream_id);
                                    reset_streams.insert(*stream_id);
                                }

                                apply_frame_to_request(request, frame, batch_num);
                            }
                        }

                        for response in &observation.responded_stream_events {
                            let Some(request_index) =
                                request_semantic_indexes.get(&response.stream_id)
                            else {
                                continue;
                            };

                            if matches!(response.event_type, StreamEventType::Finished) {
                                batch_terminal_streams.insert(response.stream_id);
                            }

                            let request = &mut request_semantics[*request_index];
                            apply_stream_event_to_request(
                                request,
                                response.event_type,
                                batch_num,
                                &reset_streams,
                            );
                        }

                        update_close_semantic(
                            &mut close_semantic,
                            &observation.conn_close_details,
                            batch_num,
                        );

                        if close_semantic.has_any_close() || close_semantic.timed_out {
                            for request in request_semantics.iter_mut() {
                                request.mark_connection_close(batch_num);
                            }
                        }

                        for (stream_id, qpack_index) in &qpack_progress_indexes {
                            if batch_visible_streams.contains(stream_id)
                                && qpack_progress[*qpack_index]
                                    .first_visible_response_batch
                                    .is_none()
                            {
                                qpack_progress[*qpack_index].first_visible_response_batch =
                                    Some(batch_num);
                            }

                            if batch_terminal_streams.contains(stream_id)
                                && qpack_progress[*qpack_index].first_terminal_batch.is_none()
                            {
                                qpack_progress[*qpack_index].first_terminal_batch =
                                    Some(batch_num);
                            }
                        }

                        if let Some(stats) = summary.stats {
                            let next_total_recv_pkts = stats.recv as u64;
                            let next_total_recv_bytes = stats.recv_bytes as usize;
                            let next_total_sent_pkts = stats.sent as u64;
                            let next_total_sent_initial_pkts = stats.sent_initial_pkts as u64;
                            let next_total_sent_handshake_pkts = stats.sent_handshake_pkts as u64;
                            let next_total_sent_0rtt_pkts = stats.sent_0rtt_pkts as u64;
                            let next_total_sent_short_pkts = stats.sent_short_pkts as u64;
                            let next_total_sent_short_data_pkts = stats.sent_short_data_pkts as u64;
                            let next_total_sent_short_control_pkts =
                                stats.sent_short_control_pkts as u64;
                            let next_total_sent_ack_eliciting_pkts =
                                stats.sent_ack_eliciting_pkts as u64;
                            let next_total_sent_bytes = stats.sent_bytes as usize;

                            debug!(
                                "h3 batch stats {}/{}: actions={} sent_udp_pkts_delta={} sent_initial_pkts_delta={} sent_handshake_pkts_delta={} sent_0rtt_pkts_delta={} sent_short_pkts_delta={} sent_short_data_pkts_delta={} sent_short_control_pkts_delta={} recv_udp_pkts_delta={} sent_udp_bytes_delta={} recv_udp_bytes_delta={} recv_h3_frames_delta={}",
                                batch_index + 1,
                                action_batches_len,
                                batch_action_count,
                                next_total_sent_pkts.saturating_sub(total_sent_pkts),
                                next_total_sent_initial_pkts
                                    .saturating_sub(total_sent_initial_pkts),
                                next_total_sent_handshake_pkts
                                    .saturating_sub(total_sent_handshake_pkts),
                                next_total_sent_0rtt_pkts
                                    .saturating_sub(total_sent_0rtt_pkts),
                                next_total_sent_short_pkts
                                    .saturating_sub(total_sent_short_pkts),
                                next_total_sent_short_data_pkts
                                    .saturating_sub(total_sent_short_data_pkts),
                                next_total_sent_short_control_pkts
                                    .saturating_sub(total_sent_short_control_pkts),
                                next_total_recv_pkts.saturating_sub(total_recv_pkts as u64),
                                next_total_sent_bytes.saturating_sub(total_sent_bytes),
                                next_total_recv_bytes.saturating_sub(total_recv_bytes),
                                batch_recv_h3_frames
                            );

                            if next_total_recv_pkts > total_recv_pkts as u64
                                && batch_recv_h3_frames == 0
                            {
                                debug!(
                                    "h3 batch {} saw transport-only replies; likely ACK/MAX_DATA/MAX_STREAM_DATA or other QUIC control frames",
                                    batch_index + 1
                                );
                            }

                            total_recv_pkts = next_total_recv_pkts as usize;
                            total_recv_bytes = next_total_recv_bytes;
                            total_sent_pkts = next_total_sent_pkts;
                            total_sent_initial_pkts = next_total_sent_initial_pkts;
                            total_sent_handshake_pkts = next_total_sent_handshake_pkts;
                            total_sent_0rtt_pkts = next_total_sent_0rtt_pkts;
                            total_sent_short_pkts = next_total_sent_short_pkts;
                            total_sent_short_data_pkts = next_total_sent_short_data_pkts;
                            total_sent_short_control_pkts = next_total_sent_short_control_pkts;
                            total_sent_ack_eliciting_pkts = next_total_sent_ack_eliciting_pkts;
                            total_sent_bytes = next_total_sent_bytes;
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("h3 action processing failed: {:?}", e);
                        need_rebuild_h3_conn = true;
                        break;
                    }
                    Err(panic_payload) => {
                        let panic_msg =
                            if let Some(msg) = panic_payload.downcast_ref::<&'static str>() {
                                (*msg).to_string()
                            } else if let Some(msg) = panic_payload.downcast_ref::<String>() {
                                msg.clone()
                            } else {
                                "non-string panic payload".to_string()
                            };
                        warn!("h3 action processing panicked: {}", panic_msg);
                        need_rebuild_h3_conn = true;
                        break;
                    }
                }

                if !cpu_usage_observer.judge_proc_exist() {
                    error!("cannot find process");
                    exit_kind = ExitKind::Crash;
                    log_h3_replay_stats(
                        &replay_target,
                        total_sent_actions,
                        total_recv_h3_frames,
                        total_sent_pkts,
                        total_sent_initial_pkts,
                        total_sent_handshake_pkts,
                        total_sent_0rtt_pkts,
                        total_sent_short_pkts,
                        total_sent_short_data_pkts,
                        total_sent_short_control_pkts,
                        total_sent_ack_eliciting_pkts,
                        total_recv_pkts,
                        total_sent_bytes,
                        total_recv_bytes,
                    );
                    self.maybe_emit_historical_coverage_stats(state, _mgr)?;
                    return Ok(exit_kind);
                }
                let cur_cpu_usage = match cpu_usage_observer.try_get_cur_cpu_usage() {
                    Some(cpu_usage) => cpu_usage,
                    None => {
                        error!(
                            "target process disappeared before CPU sampling, pid={}",
                            cpu_usage_observer.pid
                        );
                        exit_kind = ExitKind::Crash;
                        self.maybe_emit_historical_coverage_stats(state, _mgr)?;
                        return Ok(exit_kind);
                    }
                };
                cur_cpu_usages.push(cur_cpu_usage);
                debug!(
                    "recv_left_time: {:?},lost_time: {:?}",
                    recv_left_time, lost_time_dur
                );
            }
        }
        if need_rebuild_h3_conn {
            self.rebuild_h3_conn_struct();
        }

        for qpack_request in qpack_progress.iter_mut() {
            if let Some(request_index) = request_semantic_indexes.get(&qpack_request.stream_id) {
                let request = &request_semantics[*request_index];
                if qpack_request.first_terminal_batch.is_none() {
                    qpack_request.first_terminal_batch = request.first_terminal_batch;
                }
                qpack_request.stalled = qpack_request.requires_dynamic_state
                    && !request.saw_headers
                    && !request.saw_data
                    && !request.saw_reset
                    && !request.saw_finished
                    && exit_kind != ExitKind::Crash;
            }
        }

        self.update_h3_semantic_obs(H3RunSemanticSummary {
            requests: request_semantics,
            close: close_semantic,
            qpack_requests: qpack_progress,
            total_h3_frames: total_recv_h3_frames,
            total_batches: action_batches_len as u32,
        });

        log_h3_replay_stats(
            &replay_target,
            total_sent_actions,
            total_recv_h3_frames,
            total_sent_pkts,
            total_sent_initial_pkts,
            total_sent_handshake_pkts,
            total_sent_0rtt_pkts,
            total_sent_short_pkts,
            total_sent_short_data_pkts,
            total_sent_short_control_pkts,
            total_sent_ack_eliciting_pkts,
            total_recv_pkts,
            total_sent_bytes,
            total_recv_bytes,
        );

        if total_recv_pkts != 0 {
            self.change_recv_pkts(total_recv_pkts);
            self.change_non_res_times(0);
        } else {
            self.change_recv_pkts(0);
            self.change_non_res_times(self.non_res_times + 1);
        }
        buf_recv_pkt_num_observer.set_recv_bytes(total_recv_bytes as u64);
        buf_recv_pkt_num_observer.set_recv_pkts(total_recv_pkts as u64);
        buf_recv_pkt_num_observer.set_send_bytes(total_sent_bytes as u64);
        buf_recv_pkt_num_observer.set_send_pkts(total_sent_pkts as u64);
        self.update_recv_pkt_obs(buf_recv_pkt_num_observer);

        let valid_cpu_usage = match is_first {
            true => self.update_first_cpu_usage_obs(cur_cpu_usages),
            false => self.update_second_cpu_usage_obs(cur_cpu_usages),
        };
        if !valid_cpu_usage {
            error!("cannot find process while updating cpu usage");
            exit_kind = ExitKind::Crash;
            // stop_capture(capture_process);
            self.maybe_emit_historical_coverage_stats(state, _mgr)?;
            return Ok(exit_kind);
        }

        /* handle every frame */
        self.handle_frames(total_recv_frames);

        let res = self.judge_server_status();
        if self.non_res_times == 30 {
            error!("marked crashed");
            // kill self.pid
            let pid = self.pid;
            warn!("killing pid: {:?}", pid);
            let signal = self.kill_signal.unwrap_or(Signal::SIGKILL);
            unsafe {
                if let Err(e) = kill(Pid::from_raw(pid as i32), signal) {
                    warn!("failed to kill pid {:?}: {:?}", pid, e);
                }
            }
            exit_kind = ExitKind::Ok;
        }

        // stop_capture(capture_process);

        self.maybe_emit_historical_coverage_stats(state, _mgr)?;
        Ok(exit_kind)
    }
}

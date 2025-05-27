use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, vec
};
use libafl::prelude::{ExitKind, MapObserver};
use libafl::state::NopState;
use libafl_bolts::rands::RomuDuoJrRand;
use mylibafl::inputstruct::InputStruct;
use nix::sys::signal::sigprocmask;
use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::TimeSpec,
        wait::waitpid,
    },
    unistd::Pid,
};
use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase}, events::SimpleEventManager, executors::{forkserver::ForkserverExecutor, DiffExecutor, HasObservers}, feedback_and_fast, feedback_or, feedbacks::{differential::DiffResult, CrashFeedback, DiffFeedback, MaxMapFeedback, TimeFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::BytesInput, monitors::SimpleMonitor, mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens}, observers::{CanTrack, HitcountsIterableMapObserver, HitcountsMapObserver, MultiMapObserver, StdMapObserver, TimeObserver}, prelude::ExplicitTracking, schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler}, stages::mutational::StdMutationalStage, state::{HasCorpus, StdState}, HasMetadata
};
use libafl_bolts::ownedref::OwnedMutSlice;
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider, StdShMemProvider, UnixShMem},
    tuples::{tuple_list, Handled, MatchNameRef, Merge},
    AsSliceMut, Truncate,
};
use nix::libc::{rand, seccomp_notif_addfd};
use nix::{libc::srand};
use quiche::{frame::{self, EcnCounts, Frame, MAX_STREAM_SIZE}, packet, ranges::{self, RangeSet}, stream, Connection, ConnectionId, Error, FrameWithPkn, Header};
use rand::Rng;
use mylibafl::{
    executors::NetworkQuicExecutor, feedbacks::*, inputstruct::QuicStruct, mutators::quic_mutations, observers::*, schedulers::MCTSScheduler,
    misc::*,
};
use libafl::observers::{self, Observer}; // Import the trait defining `pre_exec`
use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};
use log::{error, info,debug,warn};
use ctrlc;


use crate::QUIC_SIZE;
use crate::OB_RESPONSE_SIZE;
use crate::MAP_SIZE;
use crate::MAX_DATAGRAM_SIZE;

pub struct QuicObservers {
    pub start_command: String,
    pub judge_command: String,
    pub param: String,
    pub ip:String,
    pub port:u16,
    pub pid:u32,
    pub observers:RemoteObsData,
}
impl QuicObservers {
    pub fn new(param:String,ip:String, port:u16, pid:u32,
        normal_conn_ob: NormalConnObserver,
        cc_time_ob: CCTimesObserver,
        misc_ob: MiscObserver,
        recv_pkt_num_ob: RecvPktNumObserver,
        ack_range_ob: ACKRangeObserver,
        control_frame_ob: RecvControlFrameObserver,
        data_frame_ob: RecvDataFrameObserver,
        cpu_usage_ob: CPUUsageObserver,
        mem_usage_ob: MemObserver,
        pcap_record_ob: PcapObserver,
        ucb_ob: UCBObserver
    ) -> Self {
        let base_dir = env::var("START_DIR").unwrap();
        let judge_base_dir = env::var("JUDGE_DIR").unwrap();
        QuicObservers {
            start_command: format!("{base_dir}/{param}.sh"),
            judge_command: format!("{judge_base_dir}/{param}-judge.sh"),
            param,
            ip,
            port,
            pid,
            observers:RemoteObsData::new(normal_conn_ob,
                cc_time_ob,
                misc_ob,
                recv_pkt_num_ob,
                ack_range_ob,
                control_frame_ob,
                data_frame_ob,
                cpu_usage_ob,
                mem_usage_ob,
                pcap_record_ob,
                ucb_ob
            ),
        }
    }



    pub fn start_harness(&self) -> std::process::Child {
        std::env::set_var("__AFL_SHM_ID",  env::var("__AFL_SHM_ID").unwrap());
        std::env::set_var("__AFL_SHM_ID_SIZE", MAP_SIZE.to_string());
        let mut child = std::process::Command::new("sh").arg("-c").arg(&self.start_command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start harness");
        child
    }
    pub fn judge_server_status(&self) -> u32 {

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
                    return 0
                },
            }
        } else {
            // 处理标准错误输出
            let stderr = str::from_utf8(&output.stderr).expect("Invalid UTF-8 in stderr");
            // eprintln!("Command failed with error:\n{}", stderr);
            return 0;
        }
    }



    // 在启动continer时进行的初始化操作
    pub fn init(&mut self,cpuid:String){
        self.start_harness();
        //cpuid: 0,1,2,3
        for i in cpuid.split(",") {
            let cpuid = i.parse::<u32>().unwrap();
            self.observers.cpu_usage_ob.add_cpu_id(cpuid);
        }
        
    }

    pub fn set_initial_mem_usage(&mut self) {
        let mut mem_observer = &mut self.observers.mem_usage_ob;
        if self.pid != mem_observer.pid as u32 {
            mem_observer.initial_mem = 0;
            mem_observer.set_pid(self.pid);
        }
        mem_observer.before_mem = 0;
        let map_file = format!("/proc/{}/maps", mem_observer.pid);
        let file = File::open(map_file).unwrap();
        let reader = io::BufReader::new(file);
        for cur_line in reader.lines() {
            let line = cur_line.unwrap();
            if let Some((start, end)) = mem_observer.parse_rw_memory_range(&line) {
                mem_observer.before_mem += end - start;
            }
        }
        if mem_observer.initial_mem == 0 {
            mem_observer.initial_mem = mem_observer.before_mem;
        }
    }

    pub fn inital_cpu_usage_obs(&mut self)  {

        let cpu_usage_observer = &mut self.observers.cpu_usage_ob;
        cpu_usage_observer.set_pid(self.pid);
        let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
        cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);
    }

    pub fn update_recv_pkt_obs(&mut self,recv_bytes: u64,recv_pkts: u64,send_bytes: u64,send_pkts: u64) {
        let recv_pkt_num_ob = &mut self.observers.recv_pkt_num_ob;
        recv_pkt_num_ob.recv_bytes = recv_bytes;
        recv_pkt_num_ob.recv_pkts = recv_pkts;
        recv_pkt_num_ob.send_bytes = send_bytes;
        recv_pkt_num_ob.send_pkts = send_pkts;
    }

    pub fn update_cpu_usage_obs(&mut self,cur_cpu_usages: Vec<f64>) ->bool {
        let cpu_usage_observer = &mut self.observers.cpu_usage_ob;
        if !cpu_usage_observer.judge_proc_exist() {
            return false;
        }
        for cur_cpu_usage in cur_cpu_usages.iter() {
            cpu_usage_observer.add_record_cpu_usage(*cur_cpu_usage);
            cpu_usage_observer.add_frame_record_times();
            let curr_process_time = get_process_cpu_time(cpu_usage_observer.pid).expect("Failed to get process CPU time");
            let curr_cpu_times = get_cpu_time(&cpu_usage_observer.cpu_ids).expect("Failed to get CPU core times");
            cpu_usage_observer.prev_cpu_times = curr_cpu_times.clone();
            cpu_usage_observer.prev_process_time = curr_process_time;
        }
        return true
    }

    pub fn cc_observer_update(&mut self, pkn:u64,error_code:u64,frame_type:u64,reason:Vec<u8>) {
        let cc_times_observer = &mut self.observers.cc_time_ob;
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

    pub fn ack_observer_add_range(&mut self, ranges:RangeSet) {
        let ack_observer = &mut self.observers.ack_range_ob;
        ranges.iter().for_each(|range| {
            ack_observer.add_ACK_range(range.start, range.end);
        });
    }

    pub fn ctrl_observer_add_frame(&mut self, frames:Vec<Frame>) {
        let ctrl_observer = &mut self.observers.control_frame_ob;
        for frame in frames.iter() {
            ctrl_observer.add_frame_list(frame.clone());
        }
    }

    pub fn data_observer_add_frame(&mut self, 
                                    crypto_frames:Vec<FrameWithPkn>,
                                    stream_frames:Vec<FrameWithPkn>,
                                    pr_frames:Vec<FrameWithPkn>,
                                    dgram_frames:Vec<FrameWithPkn>) {
        let data_observer = &mut self.observers.data_frame_ob;
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
    
    pub fn handle_frames(&mut self, recv_frames:Vec<FrameWithPkn>) {
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
                frame::Frame::ACK { ranges,ack_delay,ecn_counts } => {
                    self.ack_observer_add_range(ranges.clone());
                    ranges.iter().for_each(|range| {
                        debug!("ack range: {:?}", range);
                    });
                },
                frame::Frame::ResetStream{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StopSending{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Crypto{ data } => {
                    crypto_frames.push(recv_frame.clone());
                },
                frame::Frame::NewToken{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Stream{ data,stream_id } => {
                    stream_frames.push(recv_frame.clone());
                },
                frame::Frame::MaxData{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::MaxStreamData{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::MaxStreamsBidi{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::DataBlocked{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StreamDataBlocked{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StreamsBlockedBidi{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::NewConnectionId{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::RetireConnectionId{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::PathChallenge{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::PathResponse{ data } => {
                    pr_frames.push(recv_frame.clone());
                },
                frame::Frame::ConnectionClose{ error_code,frame_type,reason } => {
                    self.cc_observer_update(recv_frame.pkn,*error_code,*frame_type,reason.clone());
                },
                frame::Frame::ApplicationClose{ error_code,reason } => {
                    self.cc_observer_update(recv_frame.pkn,*error_code,0,reason.clone());
                },
                frame::Frame::HandshakeDone => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Datagram{ data } => {
                    dgram_frames.push(recv_frame.clone());
                },
                frame::Frame::DatagramHeader{ length} => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::CryptoHeader{ offset,length }  => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Others{ .. }  => (),
                frame::Frame::StreamHeader { stream_id, offset, length, fin } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::MaxStreamsUni { max } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StreamsBlockedUni { limit } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
            }
        }
        self.ctrl_observer_add_frame(ctrl_frames);
        self.data_observer_add_frame(crypto_frames,stream_frames,pr_frames,dgram_frames);
    }

    // 在每次发送数据前进行的observer初始化
    pub fn pre_exec_all(&mut self) {
        self.observers.normal_conn_ob.pre_execv();
        self.observers.cc_time_ob.pre_execv();
        self.observers.misc_ob.pre_execv();
        self.observers.recv_pkt_num_ob.pre_execv();
        self.observers.ack_range_ob.pre_execv();
        self.observers.control_frame_ob.pre_execv();
        self.observers.data_frame_ob.pre_execv();
        self.observers.cpu_usage_ob.pre_execv();
        self.inital_cpu_usage_obs();
        self.observers.mem_usage_ob.pre_execv();
        self.set_initial_mem_usage();
        self.observers.pcap_record_ob.pre_execv();
        self.observers.ucb_ob.pre_execv();
    }
    
    // 在每次发送数据后进行的observer统计
    pub fn post_exec_all(&mut self,exit_kind: &ExitKind) {
        self.observers.normal_conn_ob.post_execv(exit_kind);
        self.observers.cc_time_ob.post_execv(exit_kind).unwrap();
        self.observers.misc_ob.post_execv(exit_kind);
        self.observers.recv_pkt_num_ob.post_execv(exit_kind);
        self.observers.ack_range_ob.post_execv(exit_kind);
        self.observers.control_frame_ob.post_execv(exit_kind);
        self.observers.data_frame_ob.post_execv(exit_kind);
        self.observers.cpu_usage_ob.post_execv(exit_kind);
        self.observers.mem_usage_ob.post_execv(exit_kind);
        self.observers.pcap_record_ob.post_execv(exit_kind);
        self.observers.ucb_ob.post_execv(exit_kind);
    }

    pub fn process_quic_input(&mut self,rand_seed: u32, input_struct: InputStruct) {
        let mut pid = self.judge_server_status();
        info!("pid:{:?},recore_pid:{:?}",pid,self.pid);
        if pid != self.pid {
            error!("pid not match");
        }
        if pid == 0 || self.pid == 0 || pid != self.pid {
            while(true) {
                self.start_harness();
                // std::process::Command::new("sh").arg("-c").arg(&self.start_command)
                // .output()
                // .unwrap();
                sleep(Duration::from_millis(500));
                pid = self.judge_server_status();
                // info!("pid:{:?}",pid);
                if pid == 0 {
                    error!("Failed to start server");
                }
                else {
                    break;
                }
            }
            self.pid = pid;
        }
        self.pre_exec_all();
        let mut quic_st = QuicStruct::new("myserver.xx".to_owned(), self.port, self.ip.clone());
        unsafe { srand(rand_seed) };
        let mut exit_kind = ExitKind::Ok;
        match & mut quic_st.conn  {
            //conn不存在：重新建立连接
            None => {
                for i in 0..5 {
                    quic_st =QuicStruct::new("myserver.xx".to_owned(), self.port, self.ip.to_owned());
                    match quic_st.connect() {
                        Err(e) => {
                            error!("Failed to connect: {:?}", e);
                            sleep(Duration::from_secs(5));
                            //eprintln!("Failed to connect: {:?}", e);
                            exit_kind = ExitKind::Crash;
                        },
                        Ok(_) => {
                            exit_kind = ExitKind::Ok;
                            break;
                        },
                    }
                }
    
            },
            Some(conn) => {
            }
        }
        
    
    
        let mut out = [0; MAX_DATAGRAM_SIZE<<10];
        let mut exit_kind = ExitKind::Ok;
        let mut total_recv_pkts = 0;
        let mut total_recv_bytes = 0;
        let mut cur_cpu_usages: Vec<f64> = Vec::new();
        let mut total_recv_frames: Vec<FrameWithPkn> = Vec::new();
        let pkt_type = input_struct.pkt_type;
        let lost_time_dur = input_struct.send_timeout;
        // let lost_time_dur = 0;
        let recv_time = input_struct.recv_timeout;
        let mut recv_left_time = recv_time;
                
        let max_pkt_len = 0;
        let mut cur_pkt_len = 0;
        let mut total_sent_frames:u64 = 0;
        let mut total_sent_pkts: u64 = 0;
        let mut total_sent_bytes = 0;
        let mut total_recv_frames_len = 0;
        let cycles = input_struct.frames_cycle.len();
        for cur_cycle in 0..cycles{
            let repeat_num = input_struct.frames_cycle[cur_cycle].repeat_num;
            let mut start_pos = 0;
            for i in 0..repeat_num  {
                if i % 5001 == 5000 || i == repeat_num - 1 {
                    let frames = input_struct.gen_frames(start_pos,i as u64,cur_cycle);
                    start_pos = i as u64 + 1;
                    let mut frame_list: Vec<frame::Frame> = Vec::new();
                    let len_frames = frames.len();
                    println!("len_frames: {:?}", len_frames);
                    debug!("sending {:?} frames",frames.len());
                    for j in 0..len_frames {
                        let frame = &frames[j];
                        debug!("frame len: {:?}", frame.wire_len());
                        debug!("frame type: {:?}", frame);
                        // 注释代码是按照标准的MTU将帧尽可能的合并，在fuzz过程中这应该是负优化，于是每次只发送1个帧
                        if cur_pkt_len + frame.wire_len() < max_pkt_len {
                            frame_list.push(frame.clone());
                            cur_pkt_len += frame.wire_len();
                            total_sent_frames += 1;
                            total_sent_bytes += frame.wire_len();
                            debug!("sending frame: {:?}", frame);
                            continue;
                        }
                        frame_list.push(frame.clone());
                        total_sent_frames += 1;
                        total_sent_bytes += frame.wire_len();
                        total_sent_pkts += 1;
    
            
                        quic_st.send_pkt_to_server(pkt_type, &frame_list, &mut out);
                        match quic_st.handle_sending(){
                            Err(e) => {
                                error!("Failed to send data: {:?}", e);
                                eprintln!("Failed to send data: {:?}", e);
                                exit_kind = ExitKind::Crash;
                            },
                            Ok(_) => (),
                        }
                        // info!("total sent frames: {:?}, all: {:?}", total_sent_frames, frames.len());
                        sleep(Duration::from_micros(1));
                        if recv_left_time <= lost_time_dur {
                            let send_left_time = lost_time_dur - recv_left_time;
                            // sleep(Duration::from_millis(recv_left_time.try_into().unwrap()));
                            recv_left_time =  recv_time - send_left_time ;
                            //recv&handle conn's received packet 
                            match quic_st.handle_recving_once(){
                                Err(e) => {
                                    error!("Failed to recv data: {:?}", e);
                                    eprintln!("Failed to recv data: {:?}", e);
                                    exit_kind = ExitKind::Crash;
                                },
                                Ok(recv_frames) => {
                                    total_recv_frames_len += recv_frames.len();
                                    let mut recv_pkts = 0;
                                    let mut recv_bytes = 0;
                                    for recv_frame in recv_frames.iter() {
                                        total_recv_frames.push(recv_frame.clone());
                                        recv_pkts += 1;
                                        recv_bytes += recv_frame.frame.wire_len();
                                    }
                                    total_recv_pkts += recv_pkts;
                                    total_recv_bytes += recv_bytes;
            
                                    ()
                                }
                            }
            
                            // sleep(Duration::from_millis( send_left_time as u64));
                            
                        }
                        else {
                            // sleep(Duration::from_millis(lost_time_dur.try_into().unwrap()));
                            recv_left_time -= lost_time_dur;
                        }
                        if !self.observers.cpu_usage_ob.judge_proc_exist() {
                            error!("cannot find process");
                            info!("total send&recv frames : {:?} {:?}", total_sent_frames, total_recv_frames_len);
                            
                            exit_kind = ExitKind::Crash;
                            self.post_exec_all(&exit_kind);
                            self.observers.exit_kind = exit_kind;
                            return;
                        }
                        // 每发送100个包统计一下CPU使用率，不然统计的太多了
                        if total_sent_frames %100 ==0 {
                            let cur_cpu_usage = self.observers.cpu_usage_ob.get_cur_cpu_usage();
                            cur_cpu_usages.push(cur_cpu_usage);
                        }
            
                        debug!("recv_left_time: {:?},lost_time: {:?}", recv_left_time,lost_time_dur);
                        cur_pkt_len = frame.wire_len();
                        frame_list.clear();
                        // frame_list.push(frame.clone());
            
                    }
                    debug!("sent {:?} frames",frames.len());
                    
    
                }
            }
    
        } 
    
        while true {
            match quic_st.handle_recving_once(){
                Err(e) => {
                    eprintln!("Failed to recv data: {:?}", e);
                    break;
                    // exit_kind = ExitKind::Crash;
                },
                Ok(recv_frames) => {
                    if recv_frames.len() == 0 {
                        break;
                    }
                    total_recv_frames_len += recv_frames.len();
                    let mut recv_pkts = 0;
                    let mut recv_bytes = 0;
                    for recv_frame in recv_frames.iter() {
                        total_recv_frames.push(recv_frame.clone());
                        recv_pkts += 1;
                        recv_bytes += recv_frame.frame.wire_len();
                    }
                    total_recv_pkts += recv_pkts;
                    total_recv_bytes += recv_bytes;
                    ()
                }
            }
        }
        // sleep(Duration::from_secs(100));
        info!("total send&recv frames : {:?} {:?}", total_sent_frames, total_recv_frames_len);
        self.update_recv_pkt_obs(total_recv_bytes as u64,total_recv_pkts,total_sent_bytes as u64 ,total_sent_pkts);
        
        let valid_cpu_usage = self.update_cpu_usage_obs(cur_cpu_usages);
        if !valid_cpu_usage {
            error!("cannot find process while updating cpu usage");
            exit_kind = ExitKind::Crash;
            self.post_exec_all(&exit_kind);
            self.observers.exit_kind = exit_kind;
            // stop_capture(capture_process);
            return;
        }
    
        /* handle every frame */
        self.handle_frames(total_recv_frames);    
        
        
        
        // ... 原有处理逻辑保持不变 ...
        // 包括帧处理、发送接收数据等代码
        self.post_exec_all(&exit_kind);
        self.observers.exit_kind = exit_kind;
    }
    
    


}
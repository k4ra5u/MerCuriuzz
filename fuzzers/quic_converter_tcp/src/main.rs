use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, vec
};
use libafl::prelude::ExitKind;
use libafl_bolts::shmem::ShMemId;
use libafl_bolts::AsSlice;
use mylibafl::inputstruct::quic_input::InputStruct_deserialize;
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
use clap::{Parser};


use nix::libc::{rand, seccomp_notif_addfd};
use nix::{libc::srand};
use quiche::FrameWithPkn;
use rand::Rng;
use mylibafl::{
    executors::NetworkRestartExecutor, feedbacks::*, inputstruct::QuicStruct, mutators::quic_mutations, observers::*, schedulers::MCTSScheduler
};
use mylibafl::inputstruct::*;
use libafl_bolts::ownedref::OwnedMutSlice;
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider, StdShMemProvider, UnixShMem},
    tuples::{tuple_list, Handled, MatchNameRef, Merge},
    AsSliceMut, Truncate,
};
// use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};
use log::{error, info,debug,warn};
use ctrlc;
use quiche::{frame, packet, stream::RangeBuf, Connection, ConnectionId, Error, Header};

use ring::aead::quic;
use std::net::{TcpListener, TcpStream};
// use crate::models::QuicObservers;


#[derive(Debug, Parser)]
#[command(
    name = "quic converter",
    about = "",
    author = "k4ra5u"
)]
struct Opt {

    #[arg(
        short = 'a',  // 显式设置为 'a',
        help = "host name",
        name = "a",
        default_value = "127.0.0.1"

    )]
    host: String,

    #[arg(
        short,
        help = "port",
        name = "p",
        default_value = "58443"
    )]
    port: u16,

    #[arg(
        long,
        help = "Transport type (shm or tcp)",
        name = "transport",
        default_value = "tcp"
    )]
    transport: String,

    #[arg(
        long,
        help = "TCP server address (when transport is tcp)",
        name = "tcp-addr",
        default_value = "127.0.0.1:12345"
    )]
    tcp_addr: String,

    #[arg(
        long,
        help = "para_name",
        name = "param",
        default_value = "127.0.0.1:12345"
    )]
    param: String,
}



const QUIC_SIZE: usize = 0x8000000;//128MB
const OB_RESPONSE_SIZE: usize = 0x100000;//16MB
const MAP_SIZE: usize = 1048260; 
const MAX_DATAGRAM_SIZE: usize = 1350;

fn start_harness(name: &str, shmem_id: String) -> std::process::Child {
    std::env::set_var("__AFL_SHM_ID", shmem_id);
    std::env::set_var("__AFL_SHM_ID_SIZE", MAP_SIZE.to_string());
    let base_dir = env::var("START_DIR").unwrap();
    let start_command = format!("{base_dir}/{name}.sh");
    let mut child = std::process::Command::new("sh").arg("-c").arg(&start_command)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("Failed to start harness");
    child
}

// 移除全局共享内存变量
struct ShmData {
    mem: UnixShMem,
    id: String,
}


fn read_from_tcp_stream(stream: &mut TcpStream) -> io::Result<(u32, InputStruct)> {
    // 设置读取超时
    stream.set_read_timeout(Some(Duration::from_secs(1500)))?;

    // 读取头部分 [4字节seed][8字节数据长度]
    let mut header = [0u8; 12];
    stream.read_exact(&mut header)?;
    
    let rand_seed = u32::from_be_bytes(header[0..4].try_into().unwrap());
    let data_len = u64::from_be_bytes(header[4..12].try_into().unwrap()) as usize;

    // 读取序列化数据
    let mut data = vec![0u8; data_len];
    stream.read_exact(&mut data)?;

    Ok((rand_seed, InputStruct_deserialize(&data)))
}

fn handle_tcp_connection(mut stream: TcpStream, opt: &Opt) {
    let (rand_seed, input_struct) = match read_from_tcp_stream(&mut stream) {
        Ok(data) => data,
        Err(e) => {
            error!("TCP数据读取失败: {:?}", e);
            return;
        }
    };

    // // 为每个连接创建新的QUIC实例
    // let mut quic_st = QuicStruct::new("myserver.xx".to_owned(), opt.port, opt.host.clone());
    
    // 处理输入（复用原有逻辑）
    process_quic_input(rand_seed, input_struct,opt);
}

fn process_quic_input(rand_seed: u32, input_struct: InputStruct,opt: &Opt) {
    let mut quic_st = QuicStruct::new("myserver.xx".to_owned(), opt.port, opt.host.clone());
    unsafe { srand(rand_seed) };
    let mut exit_kind = ExitKind::Ok;
    match & mut quic_st.conn  {
        //conn不存在：重新建立连接
        None => {
            for i in 0..5 {
                quic_st =QuicStruct::new("myserver.xx".to_owned(), opt.port, opt.host.to_owned());
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
                    // if !cpu_usage_observer.judge_proc_exist() {
                    //     error!("cannot find process");
                    //     exit_kind = ExitKind::Crash;
                    //     // stop_capture(capture_process);
                    //     info!("total send&recv frames : {:?} {:?}", total_sent_frames, total_recv_frames_len);
                    //     return Ok(exit_kind);
                    // }
                    // // 每发送100个包统计一下CPU使用率，不然统计的太多了
                    // if total_sent_frames %100 ==0 {
                    //     let cur_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
                    //     cur_cpu_usages.push(cur_cpu_usage);
                    // }
        
                    debug!("recv_left_time: {:?},lost_time: {:?}", recv_left_time,lost_time_dur);
                    cur_pkt_len = frame.wire_len();
                    frame_list.clear();
                    // frame_list.push(frame.clone());
        
                }
                

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


    // if total_recv_pkts != 0 {
    //     self.change_recv_pkts(total_recv_pkts);
    //     self.change_non_res_times(0);

    // }
    // else {
    //     self.change_recv_pkts(0);
    //     self.change_non_res_times(self.non_res_times + 1);
    // }
    // buf_recv_pkt_num_observer.set_recv_bytes(total_recv_bytes as u64);
    // buf_recv_pkt_num_observer.set_recv_pkts(total_recv_pkts as u64);
    // buf_recv_pkt_num_observer.set_send_bytes(total_sent_bytes as u64);
    // buf_recv_pkt_num_observer.set_send_pkts(total_sent_pkts  as u64);
    // self.update_recv_pkt_obs(buf_recv_pkt_num_observer);
    
    // let valid_cpu_usage = match is_first {
    //     true => self.update_first_cpu_usage_obs(cur_cpu_usages),
    //     false => self.update_second_cpu_usage_obs(cur_cpu_usages),
    // };
    // if !valid_cpu_usage {
    //     error!("cannot find process while updating cpu usage");
    //     exit_kind = ExitKind::Crash;
    //     // stop_capture(capture_process);
    //     return Ok(exit_kind);
    // }

    // /* handle every frame */
    // self.handle_frames(total_recv_frames);    
    // let res = self.judge_server_status();
    // if self.non_res_times == 30{
    //     error!("marked crashed");
    //     // kill self.pid
    //     let pid = self.pid;
    //     warn!("killing pid: {:?}", pid);
    //     let signal = self.kill_signal.unwrap_or(Signal::SIGKILL);
    //     unsafe {
    //         kill(Pid::from_raw(pid), signal).unwrap();
    //     }
    //     exit_kind = ExitKind::Ok;
    // }
    
    // let mut quic_shmem_buf = unsafe {SHMEM_QUIC_STRUCT.as_mut().unwrap().as_slice_mut()};
    // quic_shmem_buf[0] = 0;
    
    
    // ... 原有处理逻辑保持不变 ...
    // 包括帧处理、发送接收数据等代码
}


pub fn main() {
    // std::env::set_var("SSLKEYLOGFILE", "/media/john/Data/key.log");
    let opt = Opt::parse();
        // 根据传输类型初始化不同资源
    let mut shm_data = if opt.transport == "shm" {
        // 共享内存初始化
        let mut quic_shmem_provider = StdShMemProvider::new().unwrap();
        let shmem_id = std::env::var("QUIC_STRUCT").unwrap();
        println!("shm_buf: {:?}", shmem_id);
        Some(ShmData {
            mem: quic_shmem_provider.shmem_from_id_and_size(
                ShMemId::from_string(&shmem_id),
                QUIC_SIZE
            ).unwrap(),
            id: shmem_id
        })
    } else {
        None // TCP模式不初始化共享内存
    };

    // TCP模式初始化监听
    let listener = if opt.transport == "tcp" {
        Some(TcpListener::bind(&opt.tcp_addr).expect("TCP监听失败"))
    } else {
        None
    };

    loop {

        match opt.transport.as_str() {
            "shm" => {
                // 共享内存处理逻辑（保持原有）
                let shmem = shm_data.as_mut().unwrap();
                if shmem.mem.as_slice()[0] == 0 {
                    sleep(Duration::from_millis(10));
                    continue;
                }

                let buf = shmem.mem.as_slice();
                let data_len = u64::from_be_bytes(buf[1..9].try_into().unwrap()) as usize;
                let rand_seed = u32::from_be_bytes(buf[9..13].try_into().unwrap());
                let input_struct = InputStruct_deserialize(&buf[13..13+data_len]);

                // 复用原有QUIC实例
                process_quic_input(rand_seed, input_struct,&opt);

                // 标记处理完成
                shmem.mem.as_slice_mut()[0] = 0;
            }
            "tcp" => {
                // 接受新连接
                let listener = listener.as_ref().unwrap();
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        // 为每个连接生成新的QUIC会话
                        handle_tcp_connection(stream, &opt);
                    }
                    Err(e) => error!("接受连接失败: {:?}", e),
                }
            }
            _ => panic!("不支持的传输类型"),
        }
    }

}
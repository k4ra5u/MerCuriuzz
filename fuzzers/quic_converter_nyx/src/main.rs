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
use models::QuicObservers;
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

mod models;
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
        default_value = "58440"
    )]
    port: u16,
    
    // --cpuid 0,1,2,3
    #[arg(
        long,
        help = "CPU affinity",
        name = "cpuid",
        default_value = "0"
    )]
    cpuid: String,
    
}



const QUIC_SIZE: usize = 0x100000;//128MB
const OB_RESPONSE_SIZE: usize = 0x100000;//16MB
const MAP_SIZE: usize = 1048260; 
const MAX_DATAGRAM_SIZE: usize = 1350;


// 移除全局共享内存变量
struct ShmData {
    mem: UnixShMem,
    id: String,
}



pub fn main() {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("SSLKEYLOGFILE", "key.log");
    std::env::set_var("PCAPS_DIR", "pcaps");
    let opt = Opt::parse();
    // 根据传输类型初始化不同资源
    // 共享内存初始化
    let mut quic_shmem_provider = StdShMemProvider::new().unwrap();
    let input_shm_id =std::env::var("__EXECUTION_PATH").unwrap();
    let res_shm_id = std::env::var("__QUIC_RESPONSE").unwrap();
    println!("input_shm_id: {}", input_shm_id);
    println!("res_shm_id: {}", res_shm_id);

    let mut shm_data = Some(ShmData {
        mem: quic_shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&input_shm_id),
            QUIC_SIZE
        ).unwrap(),
        id: input_shm_id
    });
    let mut ob_shm_data = Some(ShmData {
        mem: quic_shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&res_shm_id),
            OB_RESPONSE_SIZE
        ).unwrap(),
        id: res_shm_id
    });

    
    let host = opt.host.clone();
    let port = opt.port;
    let mut recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
    let mut conn_observer = NormalConnObserver::new("conn","127.0.0.1".to_owned(),opt.port,"localhost".to_owned());
    let mut cc_time_observer = CCTimesObserver::new("cc_time");
    let mut cpu_usage_observer = CPUUsageObserver::new("cpu_usage");
    let mut ctrl_observer = RecvControlFrameObserver::new("ctrl");
    let mut data_observer = RecvDataFrameObserver::new("data");
    let mut ack_observer = ACKRangeObserver::new("ack");
    let mut mem_observer = MemObserver::new("mem");
    let mut ucb_observer = UCBObserver::new("ucb");
    let mut misc_ob = MiscObserver::new("misc");
    let mut pcap_ob = PcapObserver::new("pcap");
    let mut quic_obs = QuicObservers::new(host,port,0,
        conn_observer,
        cc_time_observer,
        misc_ob,
        recv_pkt_num_observer,
        ack_observer,
        ctrl_observer,
        data_observer,
        cpu_usage_observer,
        mem_observer,
        pcap_ob,
        ucb_observer
    );

    quic_obs.init(opt.cpuid);
    // println!("wrote AAAAAA to quic_response shared memory");
    // let ob_shmem = ob_shm_data.as_mut().unwrap();
    // let ob_buf = ob_shmem.mem.as_slice_mut();
    // ob_buf[0] = 42; // 标记为有效数据
    // ob_buf[1..7].copy_from_slice(&b"AAAAAA"[..]); // 写入AAAAAA

    loop {
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
        println!("Received input struct: {:?}", input_struct);

        // 判断服务器是否存活

        // 复用原有QUIC实例
        quic_obs.process_quic_input(rand_seed, input_struct);

        println!("Processed QUIC input with rand_seed: {}", rand_seed);
        println!("Observers: {:?}", quic_obs.observers);
        //bincode::deserialize::<RemoteObsData>(&serde_obs_buf).unwrap();
        let serislized_data = bincode::serialize(&quic_obs.observers).unwrap();
        let ob_shmem = ob_shm_data.as_mut().unwrap();
        let ob_buf = ob_shmem.mem.as_slice_mut();
        let ob_len = serislized_data.len();
        // ob_buf[0..8].copy_from_slice(&(ob_len as u64).to_be_bytes());

        ob_buf[1..ob_len+1].copy_from_slice(&serislized_data);
        ob_buf[0] = 1;  

    

        // 标记处理完成
        shmem.mem.as_slice_mut()[0] = 0;
    }

}
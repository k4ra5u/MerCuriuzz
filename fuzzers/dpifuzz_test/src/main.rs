use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, vec
};
use libafl::prelude::{hitcount_map, ExitKind, MapObserver, Observer};
use libafl_bolts::AsSlice;
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
use rand::Rng;
use mylibafl::{
    executors::NetworkRestartExecutor, feedbacks::*, inputstruct::QuicStruct, mutators::quic_mutations, observers::*, schedulers::MCTSScheduler
};
use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};
use log::{error, info,debug,warn};
use ctrlc;

#[derive(Debug, Parser)]
#[command(
    name = "forkserver_simple",
    about = "This is a simple example fuzzer to fuzz a executable instrumented by afl-cc.",
    author = "tokatoka <tokazerkje@outlook.com>"
)]
struct Opt {

    #[arg(
        help = "first harness name",
        name = "first_name",
        default_value = "xquic"

    )]
    first_name: String,

    #[arg(
        help = "first conn port",
        name = "first_port",
        default_value = "58443"
    )]
    first_port: u16,

    #[arg(
        help = "second harness name",
        name = "second_name",
        default_value = "picoquic"
    )]
    second_name: String,

    #[arg(
        help = "second conn port",
        name = "second_port",
        default_value = "58440"
    )]
    second_port: u16,

    #[arg(
        help = "Signal used to stop child",
        short = 's',
        long = "signal",
        value_parser = str::parse::<Signal>,
        default_value = "SIGKILL"
    )]
    signal: Signal,
}


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

fn start_quic_converter(port: &str, shmem_id: String, tcp_listen_addr: String) -> std::process::Child {
    std::env::set_var("QUIC_STRUCT", shmem_id);
    let base_dir = env::var("START_DIR").unwrap();
    let start_command = format!("{base_dir}/quic_converter_tcp");
    let mut child = std::process::Command::new("sh").arg("-c").arg(&start_command)
    .arg("-a")
    .arg("127.0.0.1")
    .arg("-p")
    .arg(port)
    .arg("--tcp-addr")
    .arg(tcp_listen_addr)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("Failed to start quic converter");
    child
}

#[allow(clippy::similar_names)]
const QUIC_SIZE: usize = 0x8000000;//128MB
const OB_RESPONSE_SIZE: usize = 0x100000;//16MB
const MAP_SIZE: usize = 0x100000; 
static mut SHMEM_EDGE_MAP_FIRST: Option<UnixShMem> = None;
static mut SHMEM_EDGE_MAP_SECOND: Option<UnixShMem> = None;
static mut SHMEM_QUIC_STRUCT_FIRST: Option<UnixShMem> = None;
static mut SHMEM_QUIC_STRUCT_SECOND: Option<UnixShMem> = None;


// 设置共享内存，用来获取覆盖率
// 设置环境变量和参数，启动被测程序和quic中转器
// 每1s获取覆盖率情况，并输出


fn main() {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("START_DIR", "/home/john/quic-fuzz/LibAFL/fuzzers/my_fuzzers/dpifuzz_test/start");
    std::env::set_var("JUDGE_DIR", "/home/john/quic-fuzz/LibAFL/fuzzers/my_fuzzers/dpifuzz_test/judge");
    std::env::set_var("SSLKEYLOGFILE", "/media/john/Data/key.log");
    std::env::set_var("PCAPS_DIR", "pcaps");
    env_logger::init();
    let opt = Opt::parse();
    // const MAP_SIZE: usize = 65536;

    let mut shmem_provider = StdShMemProvider::new().unwrap();

    unsafe {
        SHMEM_QUIC_STRUCT_FIRST = Some(shmem_provider.new_shmem(QUIC_SIZE).unwrap());
        SHMEM_QUIC_STRUCT_SECOND = Some(shmem_provider.new_shmem(QUIC_SIZE).unwrap());
        SHMEM_EDGE_MAP_FIRST = Some(shmem_provider.new_shmem(MAP_SIZE).unwrap());
        SHMEM_EDGE_MAP_SECOND = Some(shmem_provider.new_shmem(MAP_SIZE).unwrap());
    }


    // let mut capture_process = start_capture();
    let mut edges_observer = MultiMapObserver::new(
        "combined-edges",
        vec![
            unsafe { OwnedMutSlice::from_raw_parts_mut(SHMEM_EDGE_MAP_FIRST.as_mut().unwrap().as_slice_mut().as_mut_ptr(), MAP_SIZE) },
            unsafe { OwnedMutSlice::from_raw_parts_mut(SHMEM_EDGE_MAP_SECOND.as_mut().unwrap().as_slice_mut().as_mut_ptr(), MAP_SIZE) },
        ],
    );
    edges_observer.reset_map();
    let mut first_harness = start_harness(&opt.first_name,unsafe {SHMEM_EDGE_MAP_FIRST.as_ref().unwrap().id().to_string()});
    let mut second_harness = start_harness(&opt.second_name,unsafe {SHMEM_EDGE_MAP_SECOND.as_ref().unwrap().id().to_string()});
    // let mut first_quic_converter = start_quic_converter(&opt.first_port.to_string(),unsafe {SHMEM_QUIC_STRUCT_FIRST.as_ref().unwrap().id().to_string()},"127.0.0.1:12345".to_string());
    // let mut second_quic_converter = start_quic_converter(&opt.second_port.to_string(),unsafe {SHMEM_QUIC_STRUCT_SECOND.as_ref().unwrap().id().to_string()},"127.0.0.1:12346".to_string());
    
    let mut coverage_map1 = vec![false; MAP_SIZE];
    for i in 0..MAP_SIZE {
        coverage_map1[i] = false;
    }
    let mut coverage_map2 = vec![false; MAP_SIZE];
    for i in 0..MAP_SIZE {
        coverage_map2[i] = false;
    }
    let mut state = StdState::new(
        StdRand::with_seed(0),
        OnDiskCorpus::<BytesInput>::new(PathBuf::from("./corpus")).unwrap(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut (),
        &mut (),
    )
    .unwrap();
    loop {
        sleep(Duration::from_millis(1000));
        let input = BytesInput::new(Vec::new());
        edges_observer.post_exec(&mut state, &input, &ExitKind::Ok);
        let map_fir = &edges_observer.maps[0];
        let map_sec = &edges_observer.maps[1];
        let first_total = map_fir.as_slice().len();
        let sec_total = map_sec.as_slice().len();
        let initial = edges_observer.initial();
        let mut first_count = 0;
        let mut sec_count = 0;
        for i in 0..first_total {
            if map_fir[i] != initial {
                coverage_map1[i] = true;

            }
            if coverage_map1[i] == true {
                first_count += 1;
            }
        }
        for i in 0..sec_total {
            if map_sec[i] != initial {
                coverage_map2[i] = true;

            }
            if coverage_map2[i] == true {
                sec_count += 1;
            }
        }

        info!("fir:{:?}/{:?} sec:{:?}/{:?}",first_count,first_total,sec_count,sec_total);
        edges_observer.pre_exec(&mut state, &input);
    }

}

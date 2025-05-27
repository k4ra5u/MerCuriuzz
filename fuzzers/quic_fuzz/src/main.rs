use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, vec
};
use libafl::prelude::MapObserver;
use mylibafl::executors::QuicExecutor;
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

/// The commandline args this fuzzer accepts
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
        default_value = "lsquic"

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
        default_value = "h2o"
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

fn start_capture() -> std::process::Child {

    let filter = format!("udp");
    // 捕获 stdout 和 stderr
    Command::new("sudo")
        .arg("tshark")
        .arg("-i")
        .arg("lo")
        .arg("-f")
        .arg(&filter)
        .arg("-w")
        .arg("record.pcap")
        .arg("-q")
        .stdout(Stdio::piped()) // 捕获输出
        .stderr(Stdio::piped()) // 捕获错误
        .spawn()
        .expect("Failed to start capture process")
}


fn stop_capture(mut child: std::process::Child) {
    debug!("Stopping capture");
    child.kill().expect("Failed to stop capture");
    child.wait().expect("Failed to wait for process termination");
}

fn register_signal_handler() -> Result<(), Box<dyn std::error::Error>> {
    //when user input ctrl_c or process crashed or kill the process, we should stop the capture process
    // ctrlc::set_handler(move || {
    //     Command::new("sudo")
    //     .arg("killall")
    //     .arg("tshark")
    //     .stdout(Stdio::piped()) // 捕获输出
    //     .stderr(Stdio::piped()) // 捕获错误
    //     .spawn()
    //     .expect("Failed to start capture process");
    // }).expect("Error setting Ctrl-C handler");
    Ok(())
}


fn start_quic_converter(port: &str, io_shmem_id: String,cov_shmem_id: String,ob_shm_id:String,cpuid:String,param:String) -> std::process::Child {
    let mut envs = Vec::new();
    envs.push(("QUIC_STRUCT".to_owned(), io_shmem_id.to_owned()));
    envs.push(("__AFL_SHM_ID".to_owned(), cov_shmem_id.to_owned()));
    envs.push(("__AFL_SHM_ID_SIZE".to_owned(), MAP_SIZE.to_string()));
    envs.push(("OB_STRUCT".to_owned(), ob_shm_id.to_owned()));
    envs.push(("SSLKEYLOGFILE".to_owned(), keylog_file.to_owned()));
    envs.push(("START_DIR".to_owned(), env::var("START_DIR").unwrap()));
    envs.push(("JUDGE_DIR".to_owned(), env::var("JUDGE_DIR").unwrap()));
    envs.push(("PCAPS_DIR".to_owned(), env::var("PCAPS_DIR").unwrap()));
    let base_dir = env::var("START_DIR").unwrap();
    let start_command = format!("{base_dir}/quic_converter");
    let mut output_cmd = String::new();
    for (k,v) in envs.iter() {
        env::set_var(k,v);
        output_cmd.push_str(&format!("{}={} ",k,v));
    }
    info!("RUST_BACKTRACE=1 {output_cmd} {start_command} -a 127.0.0.1 -p {port} --transport shm --cpuid {cpuid} --param {} |tee {}_converter.log",param.clone(),param.clone());
    // let mut child = std::process::Command::new(&start_command)
    //     .arg("-a")
    //     .arg("127.0.0.1")
    //     .arg("-p")
    //     .arg(port)
    //     .arg("--transport")
    //     .arg("shm")
    //     .arg("--cpuid")
    //     .arg(cpuid)
    //     .arg("--param")
    //     .arg(param.clone())
    //     .stdout(Stdio::piped())
    //     .stderr(Stdio::piped())
    //     .spawn()
    //     .expect("Failed to start quic converter");
    // child
    sleep(Duration::from_secs(5));
    let mut child = std::process::Command::new("sh")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start quic converter");
    child

}

#[allow(clippy::similar_names)]
const QUIC_SIZE: usize = 0x8000000;//128MB
const OB_RESPONSE_SIZE: usize = 0x8000000;//128MB
const MAP_SIZE: usize = 0x100000; 
static mut SHMEM_EDGE_MAP_FIRST: Option<UnixShMem> = None;
static mut SHMEM_EDGE_MAP_SECOND: Option<UnixShMem> = None;
static mut SHMEM_QUIC_STRUCT_FIRST: Option<UnixShMem> = None;
static mut SHMEM_QUIC_STRUCT_SECOND: Option<UnixShMem> = None;
static mut SHMEM_OB_RESPONSE_FIRST: Option<UnixShMem> = None;
static mut SHMEM_OB_RESPONSE_SECOND: Option<UnixShMem> = None;

const keylog_file: &str = "/media/john/Data/key.log";
const start_dir: &str = "/home/john/quic-fuzz/LibAFL/fuzzers/my_fuzzers/start";
const judge_dir: &str = "/home/john/quic-fuzz/LibAFL/fuzzers/my_fuzzers/judge";

pub fn main() {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("START_DIR", start_dir);
    std::env::set_var("JUDGE_DIR", judge_dir);
    std::env::set_var("SSLKEYLOGFILE", keylog_file);
    std::env::set_var("PCAPS_DIR", "pcaps");
    env_logger::init();
    let opt = Opt::parse();

    let mut shmem_provider = StdShMemProvider::new().unwrap();

    unsafe {
        SHMEM_QUIC_STRUCT_FIRST = Some(shmem_provider.new_shmem(QUIC_SIZE).unwrap());
        SHMEM_QUIC_STRUCT_SECOND = Some(shmem_provider.new_shmem(QUIC_SIZE).unwrap());
        SHMEM_OB_RESPONSE_FIRST = Some(shmem_provider.new_shmem(OB_RESPONSE_SIZE).unwrap());
        SHMEM_OB_RESPONSE_SECOND = Some(shmem_provider.new_shmem(OB_RESPONSE_SIZE).unwrap());
        SHMEM_EDGE_MAP_FIRST = Some(shmem_provider.new_shmem(MAP_SIZE).unwrap());
        SHMEM_EDGE_MAP_SECOND = Some(shmem_provider.new_shmem(MAP_SIZE).unwrap());
    }
    



    let mut diff_map_observer = HitcountsIterableMapObserver::new(
        MultiMapObserver::new(
            "combined-edges",
            vec![
                unsafe { OwnedMutSlice::from_raw_parts_mut(SHMEM_EDGE_MAP_FIRST.as_mut().unwrap().as_slice_mut().as_mut_ptr(), MAP_SIZE) },
                unsafe { OwnedMutSlice::from_raw_parts_mut(SHMEM_EDGE_MAP_SECOND.as_mut().unwrap().as_slice_mut().as_mut_ptr(), MAP_SIZE) },
            ],
    ));
    diff_map_observer.base.reset_map(); 
    // let mut capture_process = start_capture();
    // let mut first_harness = start_harness(&opt.first_name,unsafe {SHMEM_EDGE_MAP_FIRST.as_ref().unwrap().id().to_string()});
    // let mut second_harness = start_harness(&opt.second_name,unsafe {SHMEM_EDGE_MAP_SECOND.as_ref().unwrap().id().to_string()});
    let mut first_quic_converter = start_quic_converter(
        &opt.first_port.to_string(),
        unsafe {SHMEM_QUIC_STRUCT_FIRST.as_ref().unwrap().id().to_string()},
        unsafe {SHMEM_EDGE_MAP_FIRST.as_ref().unwrap().id().to_string()},
        unsafe {SHMEM_OB_RESPONSE_FIRST.as_ref().unwrap().id().to_string()},
        "50,51".to_owned(),
        opt.first_name.to_owned(),
    );
    let mut second_quic_converter = start_quic_converter(
        &opt.second_port.to_string(),
        unsafe {SHMEM_QUIC_STRUCT_SECOND.as_ref().unwrap().id().to_string()},
        unsafe {SHMEM_EDGE_MAP_SECOND.as_ref().unwrap().id().to_string()},
        unsafe {SHMEM_OB_RESPONSE_SECOND.as_ref().unwrap().id().to_string()},
        "52,53".to_owned(),
        opt.second_name.to_owned(),
    );


    let corpus_dirs: Vec<PathBuf> = vec![PathBuf::from("/home/john/quic-fuzz/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/corpus-nor/")];



    let mut first_time_observer = TimeObserver::new("time");
    let mut first_recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
    let mut first_conn_observer = NormalConnObserver::new("conn","127.0.0.1".to_owned(),opt.first_port,"myserver.xx".to_owned());
    let mut first_cc_time_observer = CCTimesObserver::new("cc_time");
    let mut first_cpu_usage_observer = CPUUsageObserver::new("first_cpu_usage");
    let mut first_ctrl_observer = RecvControlFrameObserver::new("ctrl");
    let mut first_data_observer = RecvDataFrameObserver::new("data");
    let mut first_ack_observer = ACKRangeObserver::new("ack");
    let mut first_mem_observer = MemObserver::new("mem");
    let mut first_ucb_observer = UCBObserver::new("ucb");
    let mut first_misc_ob = MiscObserver::new("misc");
    let mut first_pcap_ob = PcapObserver::new("pcap");
    let first_recv_pkt_num_observer_ref = first_recv_pkt_num_observer.handle();
    let first_conn_observer_ref = first_conn_observer.handle();
    let first_cc_time_observer_ref = first_cc_time_observer.handle();
    let first_cpu_usage_observer_ref = first_cpu_usage_observer.handle();
    let first_ctrl_observer_ref = first_ctrl_observer.handle();
    let first_data_observer_ref = first_data_observer.handle();
    let first_ack_observer_ref = first_ack_observer.handle();
    let first_mem_observer_ref = first_mem_observer.handle();
    let first_ucb_observer_ref = first_ucb_observer.handle();
    let first_misc_ob_ref = first_misc_ob.handle();
    let first_pcap_ob_ref = first_pcap_ob.handle();
    first_conn_observer.set_record_remote(true);
    first_cc_time_observer.set_record_remote(true);
    first_cpu_usage_observer.set_record_remote(true);
    first_ctrl_observer.set_record_remote(true);
    first_data_observer.set_record_remote(true);
    first_ack_observer.set_record_remote(true);
    first_mem_observer.set_record_remote(true);
    first_ucb_observer.set_record_remote(true);
    first_misc_ob.set_record_remote(true);
    first_pcap_ob.set_record_remote(true);



    let mut second_time_observer = TimeObserver::new("time");
    let mut second_recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
    let mut second_conn_observer = NormalConnObserver::new("conn","127.0.0.1".to_owned(),opt.second_port,"myserver.xx".to_owned());
    let mut second_cc_time_observer = CCTimesObserver::new("cc_time");
    let mut second_cpu_usage_observer = CPUUsageObserver::new("second_cpu_usage");
    let mut second_ctrl_observer = RecvControlFrameObserver::new("ctrl");
    let mut second_data_observer = RecvDataFrameObserver::new("data");
    let mut second_ack_observer = ACKRangeObserver::new("ack");
    let mut second_mem_observer = MemObserver::new("mem");
    let mut second_ucb_observer = UCBObserver::new("ucb");
    let mut second_misc_ob = MiscObserver::new("misc");
    let mut second_pcap_ob = PcapObserver::new("pcap");
    let second_recv_pkt_num_observer_ref = second_recv_pkt_num_observer.handle();
    let second_conn_observer_ref = second_conn_observer.handle();
    let second_cc_time_observer_ref = second_cc_time_observer.handle();
    let second_cpu_usage_observer_ref = second_cpu_usage_observer.handle();
    let second_ctrl_observer_ref = second_ctrl_observer.handle();
    let second_data_observer_ref = second_data_observer.handle();
    let second_ack_observer_ref = second_ack_observer.handle();
    let second_mem_observer_ref = second_mem_observer.handle();
    let second_ucb_observer_ref = second_ucb_observer.handle();
    let second_misc_ob_ref = second_misc_ob.handle();
    let second_pcap_ob_ref = second_pcap_ob.handle();
    second_conn_observer.set_record_remote(true);
    second_cc_time_observer.set_record_remote(true);
    second_cpu_usage_observer.set_record_remote(true);
    second_ctrl_observer.set_record_remote(true);
    second_data_observer.set_record_remote(true);
    second_ack_observer.set_record_remote(true);
    second_mem_observer.set_record_remote(true);
    second_ucb_observer.set_record_remote(true);
    second_misc_ob.set_record_remote(true);
    second_pcap_ob.set_record_remote(true);
    


    let diff_cc_ob = DifferentialCCTimesObserver::new(&mut first_cc_time_observer, &mut second_cc_time_observer);
    let diff_cpu_ob = DifferentialCPUUsageObserver::new(&mut first_cpu_usage_observer, &mut second_cpu_usage_observer);
    let diff_ctrl_ob = DifferentialRecvControlFrameObserver::new(&mut first_ctrl_observer, &mut second_ctrl_observer);
    let diff_data_ob = DifferentialRecvDataFrameObserver::new(&mut first_data_observer, &mut second_data_observer);
    let diff_ack_ob = DifferentialACKRangeObserver::new(&mut first_ack_observer, &mut second_ack_observer);
    let diff_mem_ob = DifferentialMemObserver::new(&mut first_mem_observer, &mut second_mem_observer);
    let diff_pcap_ob = DifferentialPcapObserver::new(&mut first_pcap_ob, &mut second_pcap_ob);
    let diff_misc_ob = DifferentialMiscObserver::new(&mut first_misc_ob, &mut second_misc_ob);

    


    let scheduler =  MCTSScheduler::new(&first_ucb_observer);
    // let diff_fb = DiffFeedback::new(name, o1, o2, compare_fn);
    let first_normal_conn_fb = NormalConnFeedback::new(&first_conn_observer);
    let second_normal_conn_fb = NormalConnFeedback::new(&second_conn_observer);


    let mut feedback = feedback_or!(
        // TimeFeedback::new(&time_observer),
        // RecvPktNumFeedback::new(&recv_pkt_num_observer),
        UCBFeedback::new(&first_ucb_observer),
        MaxMapFeedback::new(&diff_map_observer)
        
    );    
    let mut objective = feedback_or!(
        CrashFeedback::new(),
        DifferFeedback::new(&diff_cc_ob, &diff_cpu_ob, &diff_mem_ob, &diff_ctrl_ob, &diff_data_ob, &diff_ack_ob,&diff_pcap_ob,&diff_misc_ob),
        first_normal_conn_fb,
        second_normal_conn_fb,
    ); 

    let mut state = StdState::new(
        StdRand::with_seed(0),
        OnDiskCorpus::<BytesInput>::new(PathBuf::from("./corpus")).unwrap(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let monitor = SimpleMonitor::with_user_monitor(|s| {
        println!("{s}\n");
    });
    let mut mgr = SimpleEventManager::new(monitor);

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);  

    let first_observers = tuple_list!(
        first_time_observer,
        first_recv_pkt_num_observer,
        first_ucb_observer,
        first_conn_observer,
        first_cc_time_observer,
        first_cpu_usage_observer,
        first_ctrl_observer,
        first_data_observer,
        first_ack_observer,
        first_mem_observer,
        first_misc_ob,
        first_pcap_ob,
        diff_map_observer
        );

    let second_observers = tuple_list!(
        second_time_observer,
        second_recv_pkt_num_observer,
        second_ucb_observer,
        second_conn_observer,
        second_cc_time_observer,
        second_cpu_usage_observer,
        second_ctrl_observer,
        second_data_observer,
        second_ack_observer,
        second_mem_observer,
        second_misc_ob,
        second_pcap_ob,
        );
    let diff_observers = tuple_list!(
        diff_cc_ob,
        diff_cpu_ob,
        diff_ctrl_ob,
        diff_data_ob,
        diff_ack_ob,
        diff_mem_ob,
        diff_pcap_ob,
        diff_misc_ob,
    );

    let mut rng = rand::thread_rng();
    let frame_rand_seed = rng.gen();
    unsafe { srand(frame_rand_seed) };
    let mut first_executor = QuicExecutor::new(first_observers,shmem_provider.clone(),
        first_conn_observer_ref,
        first_cc_time_observer_ref,
        first_misc_ob_ref,
        first_recv_pkt_num_observer_ref,
        first_ack_observer_ref,
        first_ctrl_observer_ref,
        first_data_observer_ref,
        first_cpu_usage_observer_ref,
        first_mem_observer_ref,
        first_pcap_ob_ref,
        first_ucb_observer_ref,

    )
        .start_command(opt.first_name.to_owned())
        .judge_command(opt.first_name.to_owned())
        .coverage_map_size(MAP_SIZE)
        .envs(vec![
            ("__AFL_SHM_ID".to_string(), unsafe { SHMEM_EDGE_MAP_FIRST.as_ref().unwrap().id().to_string() }),
            ("__AFL_SHM_ID_SIZE".to_string(), MAP_SIZE.to_string()),
            ("OB_STRUCT".to_string(), unsafe {SHMEM_OB_RESPONSE_FIRST.as_ref().unwrap().id().to_string()}),
            ("QUIC_STRUCT".to_string(), unsafe {SHMEM_QUIC_STRUCT_FIRST.as_ref().unwrap().id().to_string()}),
        ])
        .set_frame_seed(frame_rand_seed)
        .quic_shm_id(unsafe {SHMEM_QUIC_STRUCT_FIRST.as_ref().unwrap().id().to_string()})
        .quic_shm_size(QUIC_SIZE)
        .ob_shm_id(unsafe {SHMEM_OB_RESPONSE_FIRST.as_ref().unwrap().id().to_string()})
        .ob_shm_size(OB_RESPONSE_SIZE);
        // .build_quic_struct("myserver.xx".to_owned(),58443, "127.0.0.1".to_owned())

    let mut second_executor = QuicExecutor::new(second_observers,shmem_provider.clone(),
        second_conn_observer_ref,
        second_cc_time_observer_ref,
        second_misc_ob_ref,
        second_recv_pkt_num_observer_ref,
        second_ack_observer_ref,
        second_ctrl_observer_ref,
        second_data_observer_ref,
        second_cpu_usage_observer_ref,
        second_mem_observer_ref,
        second_pcap_ob_ref,
        second_ucb_observer_ref,
    )
    .start_command(opt.second_name.to_owned())
    .judge_command(opt.second_name.to_owned())
    .coverage_map_size(MAP_SIZE)
    .envs(vec![
        ("__AFL_SHM_ID".to_string(), unsafe { SHMEM_EDGE_MAP_SECOND.as_ref().unwrap().id().to_string() }),
        ("__AFL_SHM_ID_SIZE".to_string(), MAP_SIZE.to_string()),
        ("OB_STRUCT".to_string(), unsafe {SHMEM_OB_RESPONSE_SECOND.as_ref().unwrap().id().to_string()}),
        ("QUIC_STRUCT".to_string(), unsafe {SHMEM_QUIC_STRUCT_SECOND.as_ref().unwrap().id().to_string()}),
    ])
    .set_frame_seed(frame_rand_seed)
    .quic_shm_id(unsafe {SHMEM_QUIC_STRUCT_SECOND.as_ref().unwrap().id().to_string()})
    .quic_shm_size(QUIC_SIZE)
    .ob_shm_id(unsafe {SHMEM_OB_RESPONSE_SECOND.as_ref().unwrap().id().to_string()})
    .ob_shm_size(OB_RESPONSE_SIZE);

    let mut differential_executor = DiffExecutor::new(
        first_executor,
        second_executor,
        diff_observers,
    );   

    register_signal_handler().expect("Failed to register signal handler");


    if state.must_load_initial_inputs() {
        println!("Loading initial corpus from {:?}", &corpus_dirs);
        state
            .load_initial_inputs(&mut fuzzer, &mut differential_executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }
    let mut tokens = Tokens::new();
    state.add_metadata(tokens);
    let mutator = StdScheduledMutator::new(quic_mutations());
    // let mutator = StdScheduledMutator::with_max_stack_pow(quic_mutations(), 6);
    // let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(
        StdMutationalStage::new(mutator),
        // StdTMinMutationalStage::new(minimizer, factory, 128)
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut differential_executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

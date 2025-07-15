use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, vec
};
use libafl::prelude::MapObserver;
use libafl::stages::{CalibrationStage, StdPowerMutationalStage};
use mylibafl::executors::NyxQuicExecutor;
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
use nix::libc::{rand, seccomp_notif_addfd, suseconds_t};
use nix::{libc::srand};
use rand::Rng;
use mylibafl::{
    executors::NetworkRestartExecutor, feedbacks::*, inputstruct::QuicStruct, mutators::quic_mutations, observers::*, schedulers::MCTSScheduler
};
use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};
use log::{error, info,debug,warn};
use ctrlc;
use libafl_nyx::executor::NyxExecutorBuilder;
use libafl_nyx::helper::NyxHelper;
use libafl_nyx::settings::NyxSettings;


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
        default_value = "h2o"

    )]
    first_name: String,

    #[arg(
        help = "first conn port",
        name = "first_port",
        default_value = "58440"
    )]
    first_port: u16,

    #[arg(
        help = "second harness name",
        name = "second_name",
        default_value = "lsquic"
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



const start_dir: &str = "/tmp/quic-fuzzer-workspace/";
#[allow(clippy::similar_names)]

pub fn main( ) {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    let opt = Opt::parse();


    let corpus_dirs: Vec<PathBuf> = vec![PathBuf::from("corpus-nor/")];

    let first_path = format!("{start_dir}/{0}/", opt.first_name);
    let second_path = format!("{start_dir}/{0}/", opt.second_name);

    let helper = (
        NyxHelper::new(
            Path::new(&first_path), NyxSettings::builder().cpu_id(0).parent_cpu_id(None).build()).unwrap(),
        NyxHelper::new(
            Path::new(&second_path), NyxSettings::builder().cpu_id(0).parent_cpu_id(None).build()).unwrap(),
    );
    let map_observer = HitcountsIterableMapObserver::new(
        MultiMapObserver::differential(
            "combined-edges",
            vec![
                unsafe { OwnedMutSlice::from_raw_parts_mut(helper.0.bitmap_buffer, helper.0.bitmap_size) },
                unsafe { OwnedMutSlice::from_raw_parts_mut(helper.1.bitmap_buffer, helper.1.bitmap_size) },
            ],
        )
    ).track_indices();


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
    let first_normal_conn_fb = NormalConnFeedback::new(&first_conn_observer);
    let second_normal_conn_fb = NormalConnFeedback::new(&second_conn_observer);


    let mut feedback = feedback_or!(
        UCBFeedback::new(&first_ucb_observer,&first_cpu_usage_observer,&first_mem_observer,&first_cc_time_observer,&first_recv_pkt_num_observer,&first_ack_observer,&first_ctrl_observer,&first_data_observer),
        UCBFeedback::new(&second_ucb_observer,&second_cpu_usage_observer,&second_mem_observer,&second_cc_time_observer,&second_recv_pkt_num_observer,&second_ack_observer,&second_ctrl_observer,&second_data_observer),
        MaxMapFeedback::new(&map_observer),
        
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

    let monitor = SimpleMonitor::with_user_monitor(|s| { println!("{s}\n"); });
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
        map_observer,
    );

    let mut rng = rand::thread_rng();
    let frame_rand_seed = rng.gen();
    unsafe { srand(frame_rand_seed) };
    let mut first_executor = NyxQuicExecutor::new(
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
        NyxExecutorBuilder::new().build(helper.0, first_observers),
        true



    )
        .set_frame_seed(frame_rand_seed);

    let mut second_executor = NyxQuicExecutor::new(
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
        NyxExecutorBuilder::new().build(helper.1, second_observers),
        false
    )
    .set_frame_seed(frame_rand_seed);

    let mut differential_executor = DiffExecutor::new(
        first_executor,
        second_executor,
        diff_observers,
    );   



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
        // StdPowerMutationalStage::new(mutator),
        // StdTMinMutationalStage::new(minimizer, factory, 128)
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut differential_executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

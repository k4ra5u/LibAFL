use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;

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
use nix::{libc::srand, sys::signal::Signal};
use rand::Rng;
use mylibafl::{
    executors::NetworkRestartExecutor, feedbacks::*, inputstruct::QuicStruct, mutators::quic_mutations, observers::*, schedulers::MCTSScheduler
};
use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "forkserver_simple",
    about = "This is a simple example fuzzer to fuzz a executable instrumented by afl-cc.",
    author = "tokatoka <tokazerkje@outlook.com>"
)]
struct Opt {

    #[arg(
        help = "The directory to read initial inputs from ('seeds')",
        name = "INPUT_DIR",
        default_value = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/check_corpus/corpus/"

    )]
    in_dir: PathBuf,

    #[arg(
        help = "Timeout for each individual execution, in milliseconds",
        short = 't',
        long = "timeout",
        default_value = "1200"
    )]
    timeout: u64,

    #[arg(
        help = "If not set, the child's stdout and stderror will be redirected to /dev/null",
        short = 'd',
        long = "debug-child",
        default_value = "false"
    )]
    debug_child: bool,

    #[arg(
        help = "Arguments passed to the target",
        name = "arguments",
        num_args(1..),
        allow_hyphen_values = true,
    )]
    arguments: Vec<String>,

    #[arg(
        help = "Signal used to stop child",
        short = 's',
        long = "signal",
        value_parser = str::parse::<Signal>,
        default_value = "SIGKILL"
    )]
    signal: Signal,
}

#[allow(clippy::similar_names)]
static mut SHMEM_EDGE_MAP: Option<UnixShMem> = None;

pub fn main() {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("START_DIR", "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/check_corpus/start");
    std::env::set_var("JUDGE_DIR", "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/check_corpus/judge");
    std::env::set_var("SSLKEYLOGFILE", "/media/john/Data/key.log");
    std::env::set_var("PCAPS_DIR", "pcaps");
    env_logger::init();
    const MAP_SIZE: usize = 65536;
    let corpus_dirs: Vec<PathBuf> = vec![PathBuf::from("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/check_corpus/corpus/")];

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    unsafe{
        SHMEM_EDGE_MAP = Some(shmem_provider.new_shmem(65536).unwrap());
    }

    let first_time_observer = TimeObserver::new("time");
    let first_recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
    let mut first_conn_observer = NormalConnObserver::new("conn","127.0.0.1".to_owned(),58443,"myserver.xx".to_owned());
    let mut first_cc_time_observer = CCTimesObserver::new("cc_time");
    let mut first_cpu_usage_observer = CPUUsageObserver::new("first_cpu_usage");
    let mut first_ctrl_observer = RecvControlFrameObserver::new("ctrl");
    let mut first_data_observer = RecvDataFrameObserver::new("data");
    let mut first_ack_observer = ACKRangeObserver::new("ack");
    let mut first_mem_observer = MemObserver::new("mem");
    let mut first_ucb_observer = UCBObserver::new("ucb1");
    let mut first_misc_ob = MiscObserver::new("misc");




    let second_time_observer = TimeObserver::new("time");
    let second_recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
    let mut second_conn_observer = NormalConnObserver::new("conn","127.0.0.1".to_owned(),58443,"myserver.xx".to_owned());
    let mut second_cc_time_observer = CCTimesObserver::new("cc_time");
    let mut second_cpu_usage_observer = CPUUsageObserver::new("second_cpu_usage");
    let mut second_ctrl_observer = RecvControlFrameObserver::new("ctrl");
    let mut second_data_observer = RecvDataFrameObserver::new("data");
    let mut second_ack_observer = ACKRangeObserver::new("ack");
    let mut second_mem_observer = MemObserver::new("mem");
    let mut second_ucb_observer = UCBObserver::new("ucb2");
    let mut second_misc_ob = MiscObserver::new("misc");


    


    let diff_cc_ob = DifferentialCCTimesObserver::new(&mut first_cc_time_observer, &mut second_cc_time_observer);
    let diff_cpu_ob = DifferentialCPUUsageObserver::new(&mut first_cpu_usage_observer, &mut second_cpu_usage_observer);
    let diff_ctrl_ob = DifferentialRecvControlFrameObserver::new(&mut first_ctrl_observer, &mut second_ctrl_observer);
    let diff_data_ob = DifferentialRecvDataFrameObserver::new(&mut first_data_observer, &mut second_data_observer);
    let diff_ack_ob = DifferentialACKRangeObserver::new(&mut first_ack_observer, &mut second_ack_observer);
    let diff_mem_ob = DifferentialMemObserver::new(&mut first_mem_observer, &mut second_mem_observer);
    let diff_misc_fb = DifferentialMiscObserver::new(&mut first_misc_ob, &mut second_misc_ob);


    let scheduler =  MCTSScheduler::new(&first_ucb_observer);
    // let diff_fb = DiffFeedback::new(name, o1, o2, compare_fn);
    let first_normal_conn_fb = NormalConnFeedback::new(&first_conn_observer);
    let second_normal_conn_fb = NormalConnFeedback::new(&second_conn_observer);


    let mut feedback = feedback_or!(
        CrashFeedback::new(),

        // TimeFeedback::new(&time_observer),
        // RecvPktNumFeedback::new(&recv_pkt_num_observer),
        UCBFeedback::new(&first_ucb_observer),
        
    );    
    let mut objective = feedback_or!(
        CrashFeedback::new(),
        DifferFeedback::new(&diff_cc_ob, &diff_cpu_ob, &diff_mem_ob, &diff_ctrl_ob, &diff_data_ob, &diff_ack_ob,&diff_misc_fb),
        first_normal_conn_fb,
        second_normal_conn_fb,
    ); 

    let mut state = StdState::new(
        StdRand::with_seed(0),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let monitor = SimpleMonitor::with_user_monitor(|s| {
        println!("{s}");
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
        );
    let diff_observers = tuple_list!(
        diff_cc_ob,
        diff_cpu_ob,
        diff_ctrl_ob,
        diff_data_ob,
        diff_ack_ob,
        diff_mem_ob,
        diff_misc_fb,
    );

    let mut rng = rand::thread_rng();
    let frame_rand_seed = rng.gen();
    unsafe { srand(frame_rand_seed) };
    let mut first_executor = NetworkRestartExecutor::new(first_observers,shmem_provider.clone())
        .start_command("h2o.sh".to_owned())
        .judge_command("h2o-judge.sh".to_owned())
        .port(58443)
        .timeout(Duration::from_millis(1000))
        .coverage_map_size(MAP_SIZE)
        .set_frame_seed(frame_rand_seed)
        .build_quic_struct("myserver.xx".to_owned(),58443, "127.0.0.1".to_owned())
        .build();

    let mut second_executor = NetworkRestartExecutor::new(second_observers,shmem_provider.clone())
    .start_command("aioquic.sh".to_owned())
    .judge_command("aioquic-judge.sh".to_owned())
    .port(58440)
    .timeout(Duration::from_millis(1000))
    .coverage_map_size(MAP_SIZE)
    .set_frame_seed(frame_rand_seed)
    .build_quic_struct("myserver.xx".to_owned(),58440, "127.0.0.1".to_owned())
    .build();

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

}

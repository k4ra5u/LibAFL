use core::time::Duration;
use std::path::PathBuf;

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::{forkserver::ForkserverExecutor, HasObservers},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    HasMetadata,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider, StdShMemProvider, UnixShMem},
    tuples::{tuple_list, Handled, MatchNameRef, Merge},
    AsSliceMut, Truncate,
};
use nix::sys::signal::Signal;
use mylibafl::{
    executors::NetworkRestartExecutor, 
    mutators::quic_mutations, 
    inputstruct::QuicStruct,
    observers::*,
    feedbacks::*,
};

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
        default_value = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/corpus/"

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
    std::env::set_var("SSLKEYLOGFILE", "/home/john/Desktop/cjj_related/quic-go/example/key.log");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    const MAP_SIZE: usize = 65536;

    let corpus_dirs: Vec<PathBuf> = vec![PathBuf::from("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/corpus/")];

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    unsafe{
        SHMEM_EDGE_MAP = Some(shmem_provider.new_shmem(65536).unwrap());
    }


    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_slice_mut();

    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    let time_observer = TimeObserver::new("time");
    let recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
    let cc_time_observer = CCTimesObserver::new("cc_time");
    let cpu_usage_observer = CPUUsageObserver::new("cpu_usage");
    // let normal_conn_observer = NormalConnObserver::new("normal_conn", "127.0.0.1".to_owned(), 58443, "myserver.xx".to_owned());


    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer),
        RecvPktNumFeedback::new(&recv_pkt_num_observer),
        CCTimesFeedback::new(&cc_time_observer),
        CPUUsageFeedback::new(&cpu_usage_observer),
        // NormalConnFeedback::new(&normal_conn_observer),

    );


    let mut objective = feedback_or!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer),
        CPUUsageFeedback::new(&cpu_usage_observer),
        // NormalConnFeedback::new(&normal_conn_observer),
        //CCTimesFeedback::new(&cc_time_observer),
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
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

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let observer_ref = edges_observer.handle();

    let mut tokens = Tokens::new();
    let mut executor = NetworkRestartExecutor::new(tuple_list!(time_observer, edges_observer,recv_pkt_num_observer,cc_time_observer,cpu_usage_observer),shmem_provider)
        .start_command("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/start.sh".to_owned())
        .judge_command("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/judge.sh".to_owned())
        .port(58443)
        .timeout(Duration::from_millis(1000))
        .coverage_map_size(MAP_SIZE)
        .build_quic_struct("myserver.xx".to_owned(),58443, "127.0.0.1".to_owned())
        .build();

    if let Some(dynamic_map_size) = executor.get_coverage_map_size() {
        executor.observers_mut()[&observer_ref]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    if state.must_load_initial_inputs() {
        println!("Loading initial corpus from {:?}", &corpus_dirs);
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    state.add_metadata(tokens);
    let mutator = StdScheduledMutator::with_max_stack_pow(quic_mutations(), 6);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

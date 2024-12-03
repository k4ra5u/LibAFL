use core::time::Duration;
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
use nix::sys::signal::Signal;
use mylibafl::{
    executors::NetworkRestartExecutor, 
    mutators::quic_mutations, 
    inputstruct::QuicStruct,
    observers::*,
    feedbacks::*,
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
        default_value = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/corpus/"

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
    env_logger::init();
    const MAP_SIZE: usize = 65536;
    let corpus_dirs: Vec<PathBuf> = vec![PathBuf::from("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/corpus/")];

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    unsafe{
        SHMEM_EDGE_MAP = Some(shmem_provider.new_shmem(65536).unwrap());
    }

    let time_observer = TimeObserver::new("time");
    // let mut first_shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // first_shmem.write_to_env("__AFL_SHM_ID").unwrap();
    // let first_shmem_buf = first_shmem.as_slice_mut();

    // let first_edges_observer = unsafe {
    //     HitcountsMapObserver::new(StdMapObserver::new("first_shared_mem", first_shmem_buf)).track_indices()
    // };
    // let first_time_observer = TimeObserver::new("first_time");
    // let first_recv_pkt_num_observer = RecvPktNumObserver::new("first_recv_pkt_num");

    // let mut first_feedback = feedback_or!(
    //     MaxMapFeedback::new(&first_edges_observer),
    //     TimeFeedback::new(&first_time_observer),
    //     RecvPktNumFeedback::new(&first_recv_pkt_num_observer)
    // );

    // let mut second_shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // second_shmem.write_to_env("__AFL_SHM_ID").unwrap();
    // let second_shmem_buf = second_shmem.as_slice_mut();

    // let second_edges_observer = unsafe {
    //     HitcountsMapObserver::new(StdMapObserver::new("second_shared_mem", second_shmem_buf)).track_indices()
    // };
    // let second_time_observer = TimeObserver::new("second_time");
    // let second_recv_pkt_num_observer = RecvPktNumObserver::new("second_recv_pkt_num");

    // let mut second_feedback = feedback_or!(
    //     MaxMapFeedback::new(&second_edges_observer),
    //     TimeFeedback::new(&second_time_observer),
    //     RecvPktNumFeedback::new(&second_recv_pkt_num_observer)
    // );


    let recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");

    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
    );
    let mut feedback = feedback_or!(
        TimeFeedback::new(&time_observer),
        RecvPktNumFeedback::new(&recv_pkt_num_observer)
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

    let scheduler =  QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let observers = tuple_list!(
        time_observer,
        recv_pkt_num_observer,
    );
    let mut first_executor = NetworkRestartExecutor::new(observers.clone(),shmem_provider.clone())
        .start_command("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/start.sh".to_owned())
        .judge_command("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/judge.sh".to_owned())
        .port(58443)
        .timeout(Duration::from_millis(1000))
        .coverage_map_size(MAP_SIZE)
        .build_quic_struct("myserver.xx".to_owned(),58443, "127.0.0.1".to_owned())
        .build();

    let mut second_executor = NetworkRestartExecutor::new(observers.clone(),shmem_provider.clone())
    .start_command("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/start.sh".to_owned())
    .judge_command("/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc_Diff/judge.sh".to_owned())
    .port(58440)
    .timeout(Duration::from_millis(1000))
    .coverage_map_size(MAP_SIZE)
    .build_quic_struct("myserver.xx".to_owned(),58440, "127.0.0.1".to_owned())
    .build();

    let mut differential_executor = DiffExecutor::new(
        first_executor,
        second_executor,
        tuple_list!(),
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
        // StdTMinMutationalStage::new(minimizer, factory, 128)
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut differential_executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

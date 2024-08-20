use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::write_volatile;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NautilusChunksMetadata, NautilusFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator},
    inputs::NautilusInput,
    monitors::SimpleMonitor,
    mutators::{
        NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator, StdScheduledMutator,
    },
    mutators::scheduled::havoc_mutations,
    observers::{StdMapObserver, HitcountsIterableMapObserver, MultiMapObserver, TimeObserver},
    schedulers::{QueueScheduler,StdWeightedScheduler},
    stages::mutational::StdMutationalStage,
    state::StdState,
    HasMetadata,
};
use libafl_bolts::AsSliceMut;
use libafl_bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider, UnixShMem};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_bolts::ownedref::OwnedMutSlice;
use hdhunter::executors::NetworkRestartExecutor;
use std::time::Duration;



static mut SHMEM_EDGE_MAP: Option<UnixShMem> = None;
static mut SHMEM_HTTP_PARAM: Option<UnixShMem> = None;

pub fn main1() {
    let mut shmem_provider = StdShMemProvider::new().unwrap();

    unsafe {
        SHMEM_EDGE_MAP = Some(shmem_provider.new_shmem(65536).unwrap());
    }

    let map_observer = HitcountsIterableMapObserver::new(MultiMapObserver::new(
        "combined-edges",
        vec![unsafe {
            OwnedMutSlice::from_raw_parts_mut(
                SHMEM_EDGE_MAP.as_mut().unwrap().as_slice_mut().as_mut_ptr(),
                65536,
            )
        }],
    ));
    
    let mut objective = CrashFeedback::new();
    let mut map_feedback = MaxMapFeedback::new(&map_observer);

    let monitor = SimpleMonitor::with_user_monitor(|s| println!("{}", s));

    let mut mgr = SimpleEventManager::new(monitor);

    // let minimizer = StdScheduledMutator::new(http_remove_mutations());
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut map_feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();
    let scheduler = StdWeightedScheduler::new(&mut state, &map_observer);
    let mut fuzzer = StdFuzzer::new(scheduler, map_feedback, objective);
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(
        StdMutationalStage::new(mutator),
        // StdTMinMutationalStage::new(minimizer, factory, 128)
    );

    let mut executor = NetworkRestartExecutor::new(
        "./udp_server",
        "ps aux | grep udp_server | awk '{print $2}' | xargs kill -9",
        vec![
            ("__AFL_SHM".to_string(), unsafe {
                SHMEM_EDGE_MAP.as_ref().unwrap().id().to_string()
            }),
            ("__AFL_SHM_SIZE".to_string(), 65536.to_string()),
        ],
        12345,
        Duration::from_millis(100),
        tuple_list!(),
    );

    let corpus_dirs: Vec<PathBuf> = vec![PathBuf::from("./corpus_initial")];
    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
        .unwrap_or_else(|e| {
            panic!("Failed to load initial inputs: {}", e);
        });
    // info!("Loaded {} inputs", state.corpus().count());

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}



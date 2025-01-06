use std::borrow::Cow;

use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::inputs::HasMutatorBytes;
use libafl::observers::ObserversTuple;
use libafl::state::State;
use libafl::HasMetadata;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::Handle;
use libafl_bolts::tuples::Handled;
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::{Error, Named,tuples::MatchName};
use log::error;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState, feedbacks::Feedback};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::observers::*;

pub fn cmp_ctrl_frames(a:Vec<Frame_info>,b:Vec<Frame_info>) -> bool {

    return true;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Deduplication {
    pub cc_time_state: CCTimesObserverState,
    pub cpu_usage_state: CPUUsageObserverState,
    pub mem_state: MemObserverState,
    pub ctrl_state: CtrlObserverState,
    pub data_state: DataObserverState,
    pub ack_state: ACKObserverState,
    pub ctrl_seq: Vec<Frame_info>,
}

impl Deduplication {
    /// Creates a new [`Deduplication`] with the given name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cc_time_state: CCTimesObserverState::OK,
            cpu_usage_state: CPUUsageObserverState::OK,
            mem_state: MemObserverState::OK,
            ctrl_state: CtrlObserverState::OK,
            data_state: DataObserverState::OK,
            ack_state: ACKObserverState::OK,
            ctrl_seq: Vec::new(),
        }
    }
}
impl PartialEq for Deduplication {
    fn eq(&self, other: &Self) -> bool {
        self.cc_time_state == other.cc_time_state &&
        self.cpu_usage_state == other.cpu_usage_state &&
        self.mem_state == other.mem_state &&
        self.ctrl_state == other.ctrl_state &&
        self.data_state == other.data_state &&
        self.ack_state == other.ack_state &&
        cmp_ctrl_frames(self.ctrl_seq.clone(),other.ctrl_seq.clone())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DifferFeedback {
    diff_cc_ob_handle: Handle<DifferentialCCTimesObserver>,
    diff_cpu_ob_handle: Handle<DifferentialCPUUsageObserver>,
    diff_mem_ob_handle: Handle<DifferentialMemObserver>,
    diff_ctrl_ob_handle: Handle<DifferentialRecvControlFrameObserver>,
    diff_data_ob_handle: Handle<DifferentialRecvDataFrameObserver>,
    diff_ack_ob_handle: Handle<DifferentialACKRangeObserver>,
    history_object:Vec<Deduplication>,
}

impl<S> Feedback<S> for DifferFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        
        // let observer = _observers.get(&self.observer_handle).unwrap();
        let diff_cc_ob = _observers.get(&self.diff_cc_ob_handle).unwrap();
        let diff_cpu_ob = _observers.get(&self.diff_cpu_ob_handle).unwrap();
        let diff_mem_ob = _observers.get(&self.diff_mem_ob_handle).unwrap();
        let diff_ctrl_ob = _observers.get(&self.diff_ctrl_ob_handle).unwrap();
        let diff_data_ob = _observers.get(&self.diff_data_ob_handle).unwrap();
        let diff_ack_ob = _observers.get(&self.diff_ack_ob_handle).unwrap();

        let mut interesting_flag = false;
        let diff_cc_ob_judge_type = diff_cc_ob.judge_type();
        if *diff_cc_ob_judge_type != CCTimesObserverState::OK && *diff_cc_ob_judge_type != CCTimesObserverState::MistypeCCReason {
            error!("vul of CC testcase");
            interesting_flag = true;
        }
        if *diff_cpu_ob.judge_type() != CPUUsageObserverState::OK {
            error!("vul of CPU testcase");
            interesting_flag = true;
        }
        if *diff_mem_ob.judge_type() != MemObserverState::OK && *diff_mem_ob.judge_type() != MemObserverState::BothMemLeak {
            error!("vul of Mem testcase");
            interesting_flag = true;
        }
        if *diff_ctrl_ob.judge_type() != CtrlObserverState::OK {
            error!("vul of Control Frame testcase");
            interesting_flag = true;
        }
        if *diff_data_ob.judge_type() != DataObserverState::OK {
            error!("vul of Data Frame testcase");
            interesting_flag = true;
        }
        if *diff_ack_ob.judge_type() != ACKObserverState::OK {
            error!("vul of ACK Range testcase");
            interesting_flag = true;
        }
        if interesting_flag {
            let mut new_deduplication = Deduplication::new();
            new_deduplication.cc_time_state = diff_cc_ob.judge_type().clone();
            new_deduplication.cpu_usage_state = diff_cpu_ob.judge_type().clone();
            new_deduplication.mem_state = diff_mem_ob.judge_type().clone();
            new_deduplication.ctrl_state = diff_ctrl_ob.judge_type().clone();
            new_deduplication.data_state = diff_data_ob.judge_type().clone();
            new_deduplication.ack_state = diff_ack_ob.judge_type().clone();
            new_deduplication.ctrl_seq = diff_ctrl_ob.get_ctrl_frames();
            for old_object in self.history_object.iter() {
                if old_object == &new_deduplication {
                    error!("Deduplication testcase");
                    return Ok(false);
                }
            }
            self.history_object.push(new_deduplication);
            error!("Interesting testcase");

            return Ok(true);
        }
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        // let observer = observers.get(&self.observer_handle).unwrap();
        // if true {
        //     info!("Appending Differ Interesting testcase");
        // }
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Named for DifferFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("DifferFeedback");
        &NAME
        // self.observer_handle.name()
    }
}

impl DifferFeedback {
    /// Creates a new [`DifferFeedback`]
    #[must_use]
    pub fn new(diff_cc_ob: &DifferentialCCTimesObserver,
                diff_cpu_ob: &DifferentialCPUUsageObserver,
                diff_mem_ob: &DifferentialMemObserver,
                diff_ctrl_ob: &DifferentialRecvControlFrameObserver,
                diff_data_ob: &DifferentialRecvDataFrameObserver,
                diff_ack_ob: &DifferentialACKRangeObserver,
    ) -> Self {
        Self {
            diff_cc_ob_handle: diff_cc_ob.handle(),
            diff_cpu_ob_handle: diff_cpu_ob.handle(),
            diff_mem_ob_handle: diff_mem_ob.handle(),
            diff_ctrl_ob_handle: diff_ctrl_ob.handle(),
            diff_data_ob_handle: diff_data_ob.handle(),
            diff_ack_ob_handle: diff_ack_ob.handle(),
            history_object: Vec::new(),
        }
    }
}


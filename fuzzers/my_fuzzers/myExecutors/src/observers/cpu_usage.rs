use std::borrow::Cow;
use std::time::Duration;

use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::{Error, Named,tuples::MatchName};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::misc::*;
use std::thread::sleep;
#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct CPUUsageObserver {
    pub name: Cow<'static, str>,
    pub pid: u32,
    pub cpu_ids: Vec<u32>,
    pub based_cpu_usage: f64,
    pub final_based_cpu_usage: f64,
    pub prev_process_time: (u64,u64),
    pub prev_cpu_times: Vec<(u64,u64)>,
    pub record_times: u64,
    pub record_cpu_usages: Vec<f64>,


}

impl CPUUsageObserver {
    /// Creates a new [`CPUUsageObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            pid: 0,
            name: Cow::from(name),
            cpu_ids: Vec::new(),
            based_cpu_usage: 0.0,
            final_based_cpu_usage: 0.0,
            prev_process_time: (0,0),
            prev_cpu_times: Vec::new(),
            record_times: 0,
            record_cpu_usages: Vec::new(),

        }
    }

    pub fn get_cur_cpu_usage(&mut self) -> f64 {
        // 获取初始的进程和指定CPU核心的时间
        let pid = self.pid;
        let cpu_ids = self.cpu_ids.clone();

        // 获取当前的进程和指定CPU核心的时间
        let curr_process_time = get_process_cpu_time(pid).expect("Failed to get process CPU time");
        let curr_cpu_times = get_cpu_time(&cpu_ids).expect("Failed to get CPU core times");

        // 克隆 curr_cpu_times 以避免移动
        let curr_cpu_times_clone = curr_cpu_times.clone();

        // 计算 CPU 占用率
        let cpu_usage = calculate_cpu_usage(
            self.prev_process_time,
            curr_process_time,
            self.prev_cpu_times.clone(),
            curr_cpu_times_clone,
        );

        // 更新 prev_process_time 和 prev_cpu_times
        self.prev_process_time = curr_process_time;
        self.prev_cpu_times = curr_cpu_times;

        debug!(
            "Process {} CPU Usage on cores {:?}: {:.2}%",
            pid, cpu_ids, cpu_usage
        );

        cpu_usage
    }

    pub fn get_cur_cpu_usage_imut(&self) -> f64 {
        // 获取初始的进程和指定CPU核心的时间
        let pid = self.pid;
        let cpu_ids = self.cpu_ids.clone();

        // 获取当前的进程和指定CPU核心的时间
        let curr_process_time = get_process_cpu_time(pid).expect("Failed to get process CPU time");
        let curr_cpu_times = get_cpu_time(&cpu_ids).expect("Failed to get CPU core times");

        // 克隆 curr_cpu_times 以避免移动
        let curr_cpu_times_clone = curr_cpu_times.clone();

        // 计算 CPU 占用率
        let cpu_usage = calculate_cpu_usage(
            self.prev_process_time,
            curr_process_time,
            self.prev_cpu_times.clone(),
            curr_cpu_times_clone,
        );

        // 更新 prev_process_time 和 prev_cpu_times
        // self.prev_process_time = curr_process_time;
        // self.prev_cpu_times = curr_cpu_times;

        debug!(
            "Process {} CPU Usage on cores {:?}: {:.2}%",
            pid, cpu_ids, cpu_usage
        );

        cpu_usage
    }
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn add_cpu_id(&mut self, cpu_id: u32) {
        self.cpu_ids.push(cpu_id);
    }
    pub fn set_based_cpu_usage(&mut self, based_cpu_usage: f64) {
        self.based_cpu_usage = based_cpu_usage;
    }
    pub fn set_final_based_cpu_usage(&mut self, final_based_cpu_usage: f64) {
        self.final_based_cpu_usage = final_based_cpu_usage;
    }
    pub fn add_frame_record_times(&mut self) {
        self.record_times += 1;
    }
    pub fn add_record_cpu_usage(&mut self, record_cpu_usage: f64) {
        self.record_cpu_usages.push(record_cpu_usage);
    }
    pub fn record_cur_cpu_usage(&mut self) {
        let cur_cpu_usage = self.get_cur_cpu_usage();
        self.add_record_cpu_usage(cur_cpu_usage);
        self.add_frame_record_times();
    }


}

impl<S> Observer<S> for CPUUsageObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.cpu_ids = Vec::new();
        self.based_cpu_usage = 0.0;
        self.final_based_cpu_usage = 0.0;
        self.record_times = 0;
        self.record_cpu_usages.clear();
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let mut total_cpu = 0.0;
        for cpu_usage in self.record_cpu_usages.iter() {
            total_cpu += cpu_usage;
        }
        info!("post_exec of CPUUsageObserver: {:?}", self);
        Ok(())
    }
}

impl Named for CPUUsageObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

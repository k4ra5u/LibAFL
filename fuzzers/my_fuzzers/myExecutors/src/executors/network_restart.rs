use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, time::Duration, vec
};
use std::num::ParseIntError;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use libc::{rand, srand, ETH_DATA_LEN};
use libc::{CODA_SUPER_MAGIC, ERA};
use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::TimeSpec,
        wait::waitpid,
    },
    unistd::Pid,
};
use libafl::{
    corpus::Corpus, executors::{
        Executor, ExitKind, HasObservers
    }, inputs::HasTargetBytes, observers::{
        get_asan_runtime_flags_with_log_path, AsanBacktraceObserver, ObserversTuple, UsesObservers
    }, prelude::{multi_map, HitcountsIterableMapObserver, MapObserver, MultiMapObserver}, state::{
        HasCorpus, HasExecutions, HasRandSeed, HasSolutions, State, UsesState
    }
};
use libafl_bolts::{
    rands, shmem::{ShMem, ShMemId, ShMemProvider, UnixShMemProvider}, tuples::{Handle, Handled,MatchName ,MatchNameRef, Prepend, RefIndexable}, AsSlice, AsSliceMut, Truncate
};
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug,warn};

use quiche::{frame::{self, EcnCounts, Frame, MAX_STREAM_SIZE}, packet, ranges::{self, RangeSet}, stream, Connection, ConnectionId, Error, FrameWithPkn, Header};

use crate::inputstruct::{pkt_resort_type, quic_input::InputStruct_deserialize, FramesCycleStruct, InputStruct, QuicStruct};
use crate::observers::*;
use crate::misc::*;

//use crate::QuicStruct;
// use quic_input::{FramesCycleStruct, InputStruct, pkt_resort_type, QuicStruct};

const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP_REQ_STREAM_ID: u64 = 4;

/// For experiment only, please use `STNyxExecutor` in production.




pub struct NetworkRestartExecutor<OT, S, SP>
where SP: ShMemProvider,
{
    pub start_command: String,
    pub judge_command: String,
    pub envs: Vec<(OsString, OsString)>,
    pub port: u16,
    pub timeout: Duration,
    pub observers: OT,
    pub phantom: std::marker::PhantomData<S>,
    pub map: Option<SP::ShMem>,
    pub map_size: Option<usize>,
    pub kill_signal: Option<Signal>,
    pub asan_obs: Option<Handle<AsanBacktraceObserver>>,
    pub crash_exitcode: Option<i8>,
    pub shmem_provider: SP,
    pub pid: u32,
    pub quic_shm_id: String,
    pub quic_shm_size: usize,
    // pub quic_st: Option<QuicStruct>,
    pub recv_pkts: usize,
    pub non_res_times: usize,
    pub frame_rand_seed: u32,
}

pub struct NetworkRestartExecutorBuilder<'a,SP>
where SP: ShMemProvider,
{
    start_command: String,
    judge_command: String,
    envs: Vec<(OsString, OsString)>,
    port: u16,
    timeout: Duration,
    map: Option<SP::ShMem>,
    map_size: Option<usize>,
    kill_signal: Option<Signal>,
    asan_obs: Option<Handle<AsanBacktraceObserver>>,
    crash_exitcode: Option<i8>,
    shmem_provider: &'a mut SP,
    pid: u32,
    // quic_st: Option<QuicStruct>,
    frame_rand_seed: u64,
}


// impl NetworkRestartExecutor<(), (), UnixShMemProvider> {
//     /// Builder for `NetworkRestartExecutor`
//     #[must_use]
//     pub fn builder() -> NetworkRestartExecutorBuilder<'static, UnixShMemProvider> {
//         NetworkRestartExecutorBuilder::new()
//     }
// }

impl<OT, S,SP> NetworkRestartExecutor<OT, S,SP> 
where 
OT: ObserversTuple<S>,
S: State, 
SP: ShMemProvider,
{
    pub fn new(observers: OT,shmem_provider:SP) -> Self {
        Self {
            start_command: "".to_owned(),
            judge_command: "".to_owned(),
            envs: vec![],
            port: 80,
            timeout: Duration::from_millis(100),
            observers,
            phantom: std::marker::PhantomData,
            map:None,
            map_size:None,
            kill_signal:None,
            asan_obs:None,
            crash_exitcode:None,
            shmem_provider,
            pid:0,
            quic_shm_id:String::new() ,
            quic_shm_size:0,
            // quic_st:None,
            recv_pkts:0,
            non_res_times:0,
            frame_rand_seed:0,
        }
    }

    pub fn start_command(mut self,str:String) -> Self {
        let base_dir = env::var("START_DIR").unwrap();
        self.start_command = format!("{base_dir}/{str}.sh");
        info!("start_command: {:?}",self.start_command);
        self

    }

    pub fn judge_command(mut self,str:String) -> Self {
        let base_dir = env::var("JUDGE_DIR").unwrap();
        self.judge_command = format!("{base_dir}/{str}-judge.sh");
        info!("judge_command: {:?}",self.judge_command);
        self
    }

    pub fn port(mut self,port:u16) -> Self {
        self.port = port;
        self
    }

    pub fn timeout(mut self,timeout:Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn coverage_map_size(mut self, size: usize) -> Self {
        self.map_size = Some(size);
        self
    }

    pub fn set_frame_seed(mut self, seed: u32) -> Self {
        self.frame_rand_seed = seed;
        self
    }
    pub fn change_recv_pkts(&mut self, nums:usize)  {
        self.recv_pkts = nums;
    }

    pub fn change_non_res_times(&mut self,nums:usize) {
        self.non_res_times = nums;
    }

    pub fn env<K, V>(mut self, key: K, val: V) -> Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.envs
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Adds environmental vars to the harness's commandline
    pub fn envs<IT, K, V>(mut self, vars: IT) -> Self
    where
        IT: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut res = vec![];
        for (ref key, ref val) in vars {
            res.push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        }
        self.envs.append(&mut res);
        self
    }

    pub fn kill_signal(mut self, kill_signal: Signal) -> Self {
        self.kill_signal = Some(kill_signal);
        self
    }


    pub fn asan_obs(mut self, asan_obs: Handle<AsanBacktraceObserver>) -> Self {
        self.asan_obs = Some(asan_obs);
        self
    }

    pub fn quic_shm_id(mut self, quic_shm_id: String) -> Self {
        self.quic_shm_id = quic_shm_id;
        self
    }

    pub fn quic_shm_size(mut self, quic_shm_size: usize) -> Self {
        self.quic_shm_size = quic_shm_size;
        self
    }
    pub fn write_to_quic_shm_seed(&mut self, data: &[u8],seed: u32) {
        let mut quic_shm = self.shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&format!("{}",self.quic_shm_id)),self.quic_shm_size)
            .unwrap();
        let quic_shm_buf = quic_shm.as_slice_mut();

        quic_shm_buf[1..9].copy_from_slice( &data.len().to_be_bytes());
        quic_shm_buf[9..13].copy_from_slice(&seed.to_be_bytes());
        quic_shm_buf[13..13+data.len()].copy_from_slice(data);
        quic_shm_buf[0] = 1;
    } 
    pub fn wait_for_quic_shm_res(&mut self) {
        let mut quic_shm = self.shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&format!("{}",self.quic_shm_id)),self.quic_shm_size)
            .unwrap();
        let quic_shm_buf = quic_shm.as_slice();
        while true {
            if(quic_shm_buf[0] == 0) {
                break;
            }
            else {
                sleep(Duration::from_millis(100));
            }
        }
    } 




    pub fn update_recv_pkt_obs(&mut self, buf_obs: RecvPktNumObserver) {
        let recv_pkt_num_observer_ref = RecvPktNumObserver::new("recv_pkt_num").handle();
        if let Some(recv_pkt_num_observer) = self.observers.get_mut(&recv_pkt_num_observer_ref) {
            recv_pkt_num_observer.set_recv_bytes(buf_obs.get_recv_bytes());
            recv_pkt_num_observer.set_recv_pkts(buf_obs.get_recv_pkts());
            recv_pkt_num_observer.set_send_bytes(buf_obs.get_send_bytes());
            recv_pkt_num_observer.set_send_pkts(buf_obs.get_send_pkts());
        }
    }

    pub fn set_initial_mem_usage(&mut self) {
        let mem_observer_ref = MemObserver::new("mem").handle();
        if let Some(mem_observer) = self.observers.get_mut(&mem_observer_ref) {
            if self.pid != mem_observer.pid {
                mem_observer.initial_mem = 0;
                mem_observer.set_pid(self.pid);
            }
            mem_observer.before_mem = 0;
            let map_file = format!("/proc/{}/maps", mem_observer.pid);
            let file = File::open(map_file).unwrap();
            let reader = io::BufReader::new(file);
            for cur_line in reader.lines() {
                let line = cur_line.unwrap();
                if let Some((start, end)) = mem_observer.parse_rw_memory_range(&line) {
                    mem_observer.before_mem += end - start;
                }
            }
            if mem_observer.initial_mem == 0 {
                mem_observer.initial_mem = mem_observer.before_mem;
            }
        }
    }

    pub fn inital_first_cpu_usage_obs(&mut self)  {

        let cpu_usage_observer = CPUUsageObserver::new("first_cpu_usage");
        let cpu_usage_observer_ref = cpu_usage_observer.handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            cpu_usage_observer.set_pid(self.pid as u32);
            cpu_usage_observer.add_cpu_id(50);
            cpu_usage_observer.add_cpu_id(51);
            // cpu_usage_observer.add_cpu_id(22);
            // cpu_usage_observer.add_cpu_id(23);
            let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
            cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);
        }
    }

    pub fn inital_second_cpu_usage_obs(&mut self)   {

        let cpu_usage_observer = CPUUsageObserver::new("second_cpu_usage");
        let cpu_usage_observer_ref = cpu_usage_observer.handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            cpu_usage_observer.set_pid(self.pid as u32);
            cpu_usage_observer.add_cpu_id(52);
            cpu_usage_observer.add_cpu_id(53);
            // cpu_usage_observer.add_cpu_id(22);
            // cpu_usage_observer.add_cpu_id(23);
            let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
            cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);
        }
    }

    pub fn get_first_cpu_usage_ob_mut (&mut self) -> &mut CPUUsageObserver {
        let cpu_usage_observer_ref = CPUUsageObserver::new("first_cpu_usage").handle();
        self.observers.get_mut(&cpu_usage_observer_ref).unwrap()
    }
    pub fn get_second_cpu_usage_ob_mut (&mut self) -> &mut CPUUsageObserver {
        let cpu_usage_observer_ref = CPUUsageObserver::new("second_cpu_usage").handle();
        self.observers.get_mut(&cpu_usage_observer_ref).unwrap()
    }


    pub fn update_first_cpu_usage_obs(&mut self,cur_cpu_usages: Vec<f64>) ->bool {
        let cpu_usage_observer_ref = CPUUsageObserver::new("first_cpu_usage").handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            if !cpu_usage_observer.judge_proc_exist() {
                return false;
            }
            for cur_cpu_usage in cur_cpu_usages.iter() {
                cpu_usage_observer.add_record_cpu_usage(*cur_cpu_usage);
                cpu_usage_observer.add_frame_record_times();
                let curr_process_time = get_process_cpu_time(cpu_usage_observer.pid).expect("Failed to get process CPU time");
                let curr_cpu_times = get_cpu_time(&cpu_usage_observer.cpu_ids).expect("Failed to get CPU core times");
                cpu_usage_observer.prev_cpu_times = curr_cpu_times.clone();
                cpu_usage_observer.prev_process_time = curr_process_time;
            }
        }
        return true
    }

    pub fn update_second_cpu_usage_obs(&mut self,cur_cpu_usages: Vec<f64>) ->bool {
        let cpu_usage_observer_ref = CPUUsageObserver::new("second_cpu_usage").handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            if !cpu_usage_observer.judge_proc_exist() {
                return false;
            }
            for cur_cpu_usage in cur_cpu_usages.iter() {
                cpu_usage_observer.add_record_cpu_usage(*cur_cpu_usage);
                cpu_usage_observer.add_frame_record_times();
                let curr_process_time = get_process_cpu_time(cpu_usage_observer.pid).expect("Failed to get process CPU time");
                let curr_cpu_times = get_cpu_time(&cpu_usage_observer.cpu_ids).expect("Failed to get CPU core times");
                cpu_usage_observer.prev_cpu_times = curr_cpu_times.clone();
                cpu_usage_observer.prev_process_time = curr_process_time;
            }
        }
        return true
    }

    pub fn cc_observer_update(&mut self, pkn:u64,error_code:u64,frame_type:u64,reason:Vec<u8>) {
        let cc_times_observer_ref = CCTimesObserver::new("cc_time").handle();
        if let Some(cc_times_observer) = self.observers.get_mut(&cc_times_observer_ref) {
            cc_times_observer.pkn = pkn;
            cc_times_observer.error_code = error_code;
            cc_times_observer.frame_type = frame_type;
            cc_times_observer.reason = match String::from_utf8(reason) {
                Ok(val) => val,
                Err(e) => {
                    error!("Failed to convert reason to UTF-8: {}", e);
                    "Invalid UTF-8".to_string()
                }
            };
        }
    }

    pub fn ack_observer_add_range(&mut self, ranges:RangeSet) {
        let ack_observer_ref = ACKRangeObserver::new("ack").handle();
        if let Some(ack_observer) = self.observers.get_mut(&ack_observer_ref) {
            ranges.iter().for_each(|range| {
                ack_observer.add_ACK_range(range.start, range.end);
            });
        }
    }

    pub fn ctrl_observer_add_frame(&mut self, frames:Vec<Frame>) {
        let ctrl_observer_ref = RecvControlFrameObserver::new("ctrl").handle();
        if let Some(ctrl_observer) = self.observers.get_mut(&ctrl_observer_ref) {
            for frame in frames.iter() {
                ctrl_observer.add_frame_list(frame.clone());
            }
        }
    }

    pub fn data_observer_add_frame(&mut self, 
                                    crypto_frames:Vec<FrameWithPkn>,
                                    stream_frames:Vec<FrameWithPkn>,
                                    pr_frames:Vec<FrameWithPkn>,
                                    dgram_frames:Vec<FrameWithPkn>) {
        let data_observer_ref = RecvDataFrameObserver::new("data").handle();
        if let Some(data_observer) = self.observers.get_mut(&data_observer_ref) {
            for frame in crypto_frames.iter() {
                data_observer.add_crypto_frame_list(frame.clone());
            }
            for frame in stream_frames.iter() {
                data_observer.add_stream_frame_list(frame.clone());
            }
            for frame in pr_frames.iter() {
                data_observer.add_pr_frame_list(frame.clone());
            }
            for frame in dgram_frames.iter() {
                data_observer.add_dgram_frame_list(frame.clone());
            }
        }
    }

    pub fn handle_frames(&mut self, recv_frames:Vec<FrameWithPkn>) {
        let mut ctrl_frames: Vec<Frame> = Vec::new();
        let mut crypto_frames: Vec<FrameWithPkn> = Vec::new();
        let mut stream_frames: Vec<FrameWithPkn> = Vec::new();
        let mut pr_frames: Vec<FrameWithPkn> = Vec::new();
        let mut dgram_frames: Vec<FrameWithPkn> = Vec::new();
        let mut cc_times = 0;
        for recv_frame in recv_frames.iter() {
            match &recv_frame.frame {
                frame::Frame::Padding { .. } => (),
                frame::Frame::Ping { .. } => (),
                frame::Frame::ACK { ranges,ack_delay,ecn_counts } => {
                    self.ack_observer_add_range(ranges.clone());
                    ranges.iter().for_each(|range| {
                        debug!("ack range: {:?}", range);
                    });
                },
                frame::Frame::ResetStream{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StopSending{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Crypto{ data } => {
                    crypto_frames.push(recv_frame.clone());
                },
                frame::Frame::NewToken{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Stream{ data,stream_id } => {
                    stream_frames.push(recv_frame.clone());
                },
                frame::Frame::MaxData{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::MaxStreamData{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::MaxStreamsBidi{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::DataBlocked{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StreamDataBlocked{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StreamsBlockedBidi{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::NewConnectionId{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::RetireConnectionId{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::PathChallenge{ .. } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::PathResponse{ data } => {
                    pr_frames.push(recv_frame.clone());
                },
                frame::Frame::ConnectionClose{ error_code,frame_type,reason } => {
                    self.cc_observer_update(recv_frame.pkn,*error_code,*frame_type,reason.clone());
                },
                frame::Frame::ApplicationClose{ error_code,reason } => {
                    self.cc_observer_update(recv_frame.pkn,*error_code,0,reason.clone());
                },
                frame::Frame::HandshakeDone => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Datagram{ data } => {
                    dgram_frames.push(recv_frame.clone());
                },
                frame::Frame::DatagramHeader{ length} => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::CryptoHeader{ offset,length }  => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::Others{ .. }  => (),
                frame::Frame::StreamHeader { stream_id, offset, length, fin } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::MaxStreamsUni { max } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
                frame::Frame::StreamsBlockedUni { limit } => {
                    ctrl_frames.push(recv_frame.frame.clone());
                },
            }
        }
        self.ctrl_observer_add_frame(ctrl_frames);
        self.data_observer_add_frame(crypto_frames,stream_frames,pr_frames,dgram_frames);
    }

    pub fn pcap_observer_update_get_name(&mut self) -> String {
        let pcap_observer_ref = PcapObserver::new("pcap").handle();
        if let Some(pcap_observer) = self.observers.get_mut(&pcap_observer_ref) {
            pcap_observer.port = self.port;
            pcap_observer.new_record.port = self.port;
            pcap_observer.new_record.name.clone()
        }
        else {
            String::new()
        }
    }

    pub fn sync_srand_seed_path(&mut self,pcap_path:String) {
        let misc_observer_ref = MiscObserver::new("misc").handle();
        if let Some(misc_observer) = self.observers.get_mut(&misc_observer_ref) {
            misc_observer.srand_seed =  self.frame_rand_seed;
        }
    }

    pub fn nor_conn_ob_connect(&mut self) {
        let conn_observer_ref = NormalConnObserver::new("conn","127.0.0.1".to_owned(),self.port,"myserver.xx".to_owned()).handle();
        if let Some(conn_observer) = self.observers.get_mut(&conn_observer_ref) {
            conn_observer.calc_pre_spend_time();
        }
    }
    // pub fn build_quic_struct(mut self, server_name: String, server_port: u16, server_host: String) -> Self {

    
    //     let quic_st = QuicStruct::new(server_name, server_port, server_host);
    //     self.quic_st = Some(quic_st);
    //     self
    // }

    // pub fn rebuild_quic_struct(&mut self) {
    //     let server_name = self.quic_st.as_ref().unwrap().server_name.clone();
    //     let server_port = self.quic_st.as_ref().unwrap().server_port;
    //     let server_host = self.quic_st.as_ref().unwrap().server_host.clone();
    //     //drop(self.quic_st);
    //     self.quic_st = Some(QuicStruct::new(server_name, server_port, server_host));


    // }


    pub fn build(mut self) -> Self
    where
        SP: ShMemProvider,
    {
        let mut shmem = self.shmem_provider.new_shmem(0x10000).unwrap();
        shmem.write_to_env("__AFL_SHM_FUZZ_ID");

        let size_in_bytes = (0x1000u32).to_ne_bytes();
        shmem.as_slice_mut()[..4].clone_from_slice(&size_in_bytes[..4]);
        let map = shmem ;
        self.map = Some(map);
        self
            
            
    }

    pub fn get_coverage_map_size(&self) -> Option<usize> {
        self.map_size
    }

    pub fn judge_server_status(&self) -> u32 {

        let output = std::process::Command::new(&self.judge_command)
        .output()
        .expect("Failed to execute command");

        // 检查命令的执行状态
        if output.status.success() {
            // 处理标准输出
            let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");
            debug!("Command executed successfully:\n{}", stdout);
            // println!("Command executed successfully:\n{}", stdout);
            match stdout.trim().parse::<u32>() {
                Ok(value) => return value,
                //Err(e) => {eprintln!("Failed to parse integer: {}", e);return 0},
                Err(e) => {
                    debug!("Failed to parse integer: {}", e);
                    return 0
                },
            }
        } else {
            // 处理标准错误输出
            let stderr = str::from_utf8(&output.stderr).expect("Invalid UTF-8 in stderr");
            // eprintln!("Command failed with error:\n{}", stderr);
            return 0;
        }
    }



}

impl<OT, S,SP> UsesState for NetworkRestartExecutor<OT, S, SP>
where
    S: State, 
    SP: ShMemProvider
{
    type State = S;
}

impl<OT, S,SP> UsesObservers for NetworkRestartExecutor<OT, S,SP>
where
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider
{
    type Observers = OT;
}

impl<OT, S,SP> HasObservers for NetworkRestartExecutor<OT, S,SP>
where
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<EM, OT, S,SP, Z> Executor<EM, Z> for NetworkRestartExecutor<OT, S,SP>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions + HasCorpus + HasSolutions +HasRandSeed,
    S::Input: HasTargetBytes,
    SP: ShMemProvider,
    OT: MatchName + ObserversTuple<S>,
    Z: UsesState<State = S> {
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<libafl::prelude::ExitKind, libafl::prelude::Error> {
        //let mut observers: RefIndexable<&mut OT, OT> = self.observers_mut();
        // info!("now seed:{:?}",self.frame_rand_seed);

        // TODO: 确定共享内存在修改时2个中转器都已经完成测试

        for (key, value) in &self.envs {
            std::env::set_var(key, value);
        }
        let mut is_first = false;
        if self.start_command.contains("lsquic.sh") {
            is_first = true;
        }
        if state.rand_seed() != 0{
            self.frame_rand_seed = state.rand_seed();
            if !is_first {
                state.set_rand_seed(0);
            }
        }
        let pcap_path = self.pcap_observer_update_get_name();
        self.sync_srand_seed_path(pcap_path.clone());
        let rand_seed = self.frame_rand_seed;

        self.frame_rand_seed = unsafe {rand().try_into().unwrap()};
        // info!("now {:?} corpus",state.corpus().count());
        info!("running corpus: {:?}", state.corpus().current());
        

        
        //let mut recv_pkt_num_observer = None;
        // for observer in observers.iter() {
        //     if let Some(recv_pkt_num_observer) = observer.downcast_mut::<RecvPktNumObserver>() {}
        // }

        let mut buf_recv_pkt_num_observer = RecvPktNumObserver::new("recv_pkt_num");
        // let cc_times_observer_ref = CCTimesObserver::new("cc_times").handle();
        // let mut cc_times_observer = self.observers.get_mut(&cc_times_observer_ref).unwrap();
        // let mut buf_asan_backtrace_observer = AsanBacktraceObserver::new("asan_backtrace");


        let mut out = [0; MAX_DATAGRAM_SIZE<<10];
        let mut exit_kind = ExitKind::Ok;
        let mut total_recv_pkts = 0;
        let mut total_recv_bytes = 0;
        let mut cur_cpu_usages: Vec<f64> = Vec::new();
        let mut total_recv_frames: Vec<FrameWithPkn> = Vec::new();
        *state.executions_mut() += 1;

        // let res = self.judge_server_status();
        // // 快照功能不完善，目前每次fuzz重启服务
        // // 尝试不重启服务，只重新建立连接
        // if res !=0 {
        //     std::process::Command::new("sh").arg("-c").arg(format!("kill -9 {}",res))
        //     .stdout(Stdio::null())
        //     .stderr(Stdio::null())
        //     .status()
        //     .unwrap();
        // }
        let mut pid = self.judge_server_status();
        // 如果服务未启动，则启动服务
        // warn!("non_res_times:{:?} recv_pkts:{:?}",self.non_res_times,self.recv_pkts);
        if pid == 0 || self.pid == 0 {
            while(true) {
                std::process::Command::new("sh").arg("-c").arg(&self.start_command)
                .output()
                .unwrap();
                sleep(Duration::from_millis(500));
                pid = self.judge_server_status();
                // info!("pid:{:?}",pid);
                if pid == 0 {
                    error!("Failed to start server");
                }
                else {
                    break;
                }
            }
            self.pid = pid;
        }
        self.set_initial_mem_usage();


         if is_first {
            self.inital_first_cpu_usage_obs();
        } else {
            self.inital_second_cpu_usage_obs();
        };

        self.nor_conn_ob_connect();

        let cpu_usage_observer_ref = if is_first {
            CPUUsageObserver::new("first_cpu_usage").handle()
        } else {
            CPUUsageObserver::new("second_cpu_usage").handle()
        };

        
       
        let cpu_usage_observer = self.observers.get_mut(&cpu_usage_observer_ref).unwrap();

        let binding = input.target_bytes();
        let mut inputs = binding.as_slice();   
        self.write_to_quic_shm_seed(&inputs,rand_seed);
        self.wait_for_quic_shm_res();
        if is_first {
            let multi_map_ob_handle = HitcountsIterableMapObserver::new(MultiMapObserver::new("combined-edges", Vec::<libafl_bolts::ownedref::OwnedMutSlice<u8>>::new())).handle();
            let hit_multi_map_ob = self.observers.get(&multi_map_ob_handle).unwrap();
            let multi_map_ob = &hit_multi_map_ob.base;
            let map_fir = &multi_map_ob.maps[0];
            let map_sec = &multi_map_ob.maps[1];
            let initial = multi_map_ob.initial();
            let mut first_count = 0;
            let mut sec_count = 0;
            for x in map_fir.as_slice() {
                if *x != initial {
                    first_count += 1;
                }
            }
            for x in map_sec.as_slice() {
                if *x != initial {
                    sec_count += 1;
                }
            }
            let first_total = map_fir.as_slice().len();
            let sec_total = map_sec.as_slice().len();
            info!("fir_cnt/fir_tot: {:?}/{:?}",first_count,first_total);
            info!("sec_cnt/sec_tot: {:?}/{:?}",sec_count,sec_total);
    
        }

        


        // stop_capture(capture_process);
        
        Ok(exit_kind)
    }
}

use std::{
    any::Any, env, ffi::{OsStr, OsString}, io::{self, prelude::*, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, time::Duration, vec
};
use std::num::ParseIntError;
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
    }, state::{
        HasCorpus, HasExecutions, State, UsesState
    }
};
use libafl_bolts::{
    rands, shmem::{ShMem, ShMemProvider, UnixShMemProvider}, tuples::{Handle, Handled,MatchName ,MatchNameRef, Prepend, RefIndexable}, AsSlice, AsSliceMut, Truncate
};
use rand::Rng;
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug,warn};

use quiche::{frame, packet, Connection, ConnectionId, Error, Header};

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
    pub pid: i32,
    pub quic_st: Option<QuicStruct>,
    pub recv_pkts: usize,
    pub non_res_times: usize,
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
    pid: i32,
    quic_st: Option<QuicStruct>,
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
            quic_st:None,
            recv_pkts:0,
            non_res_times:0,
        }
    }

    pub fn start_command(mut self,str:String) -> Self {
        self.start_command = str;
        self

    }

    pub fn judge_command(mut self,str:String) -> Self {
        self.judge_command = str;
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

    pub fn update_recv_pkt_obs(&mut self, buf_obs: RecvPktNumObserver) {
        let recv_pkt_num_observer_ref = RecvPktNumObserver::new("recv_pkt_num").handle();
        if let Some(recv_pkt_num_observer) = self.observers.get_mut(&recv_pkt_num_observer_ref) {
            recv_pkt_num_observer.set_recv_bytes(buf_obs.get_recv_bytes());
            recv_pkt_num_observer.set_recv_pkts(buf_obs.get_recv_pkts());
            recv_pkt_num_observer.set_send_bytes(buf_obs.get_send_bytes());
            recv_pkt_num_observer.set_send_pkts(buf_obs.get_send_pkts());
        }
    }

    pub fn inital_cpu_usage_obs(&mut self) {
        let cpu_usage_observer_ref = CPUUsageObserver::new("cpu_usage").handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            cpu_usage_observer.set_pid(self.pid as u32);
            cpu_usage_observer.add_cpu_id(20);
            cpu_usage_observer.add_cpu_id(21);
            // cpu_usage_observer.add_cpu_id(22);
            // cpu_usage_observer.add_cpu_id(23);
            let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
            cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);
        }
    }

    pub fn update_cpu_usage_obs(&mut self,cur_cpu_usages: Vec<f64>) {
        let cpu_usage_observer_ref = CPUUsageObserver::new("cpu_usage").handle();
        if let Some(cpu_usage_observer) = self.observers.get_mut(&cpu_usage_observer_ref) {
            for cur_cpu_usage in cur_cpu_usages.iter() {
                cpu_usage_observer.add_record_cpu_usage(*cur_cpu_usage);
                cpu_usage_observer.add_frame_record_times();
                let curr_process_time = get_process_cpu_time(cpu_usage_observer.pid).expect("Failed to get process CPU time");
                let curr_cpu_times = get_cpu_time(&cpu_usage_observer.cpu_ids).expect("Failed to get CPU core times");
                cpu_usage_observer.prev_cpu_times = curr_cpu_times.clone();
                cpu_usage_observer.prev_process_time = curr_process_time;
            }
        }
    }

    pub fn build_quic_struct(mut self, server_name: String, server_port: u16, server_host: String) -> Self {

    
        let quic_st = QuicStruct::new(server_name, server_port, server_host);
        self.quic_st = Some(quic_st);
        self
    }

    pub fn rebuild_quic_struct(&mut self) {
        let server_name = self.quic_st.as_ref().unwrap().server_name.clone();
        let server_port = self.quic_st.as_ref().unwrap().server_port;
        let server_host = self.quic_st.as_ref().unwrap().server_host.clone();
        //drop(self.quic_st);
        self.quic_st = Some(QuicStruct::new(server_name, server_port, server_host));


    }


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

    pub fn judge_server_status(&self) -> i32 {

        //println!("Judge server status {}", self.judge_command);
        let output = std::process::Command::new(&self.judge_command)
        .output()
        .expect("Failed to execute command");

        // 检查命令的执行状态
        if output.status.success() {
            // 处理标准输出
            let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");
            // println!("Command executed successfully:\n{}", stdout);
            match stdout.trim().parse::<i32>() {
                Ok(value) => return value,
                //Err(e) => {eprintln!("Failed to parse integer: {}", e);return 0},
                Err(e) => {
                    warn!("Failed to parse integer: {}", e);
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
    S: State + HasExecutions + HasCorpus,
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
        info!("now {:?} corpus",state.corpus().count());
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
        *state.executions_mut() += 1;
        for (key, value) in &self.envs {
            std::env::set_var(key, value);
        }
        let res = self.judge_server_status();
        // 如果服务未启动，则启动服务
        warn!("non_res_times:{:?} recv_pkts:{:?}",self.non_res_times,self.recv_pkts);
        if res == 0 || self.pid == 0 {
            std::process::Command::new("sh").arg("-c").arg(&self.start_command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        }
        
        let pid = self.judge_server_status();
        self.pid = pid;
        self.inital_cpu_usage_obs();
        
        // cpu_usage_observer.set_pid(self.pid as u32);
        // cpu_usage_observer.add_cpu_id(20);
        // cpu_usage_observer.add_cpu_id(21);
        // cpu_usage_observer.add_cpu_id(22);
        // cpu_usage_observer.add_cpu_id(23);
        // let based_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
        // cpu_usage_observer.set_based_cpu_usage(based_cpu_usage);

        //quic_st 必须存在，检查 quic_st 合法性
        let mut valid_quic_st = false;
        if let Some(quic_st) = self.quic_st.as_ref() {
            valid_quic_st = quic_st.judge_conn_status();
        } 
        if valid_quic_st == false || self.non_res_times >= 3{
            error!("judged connection closed");
            self.rebuild_quic_struct();
            self.change_non_res_times(0);
            self.change_recv_pkts(0);
        }
        
        let mut quic_st = self.quic_st.as_mut().unwrap();
        let cpu_usage_observer_ref = CPUUsageObserver::new("cpu_usage").handle();
        let cpu_usage_observer = self.observers.get_mut(&cpu_usage_observer_ref).unwrap();
        match & mut quic_st.conn  {
            //conn不存在：重新建立连接
            None => {
                match quic_st.connect() {
                    Err(e) => {
                        //eprintln!("Failed to connect: {:?}", e);
                        exit_kind = ExitKind::Crash;
                    },
                    Ok(_) => (),
                }
            },
            
            Some(conn) => {
                
        
                // send packet
                // let buf = input.target_bytes();
                // let buf_slice = buf.as_slice();
                // println!("sending packet: {:?}", buf_slice);
                // //使用 conn 发送一个PATH_CHALLENGE帧
                // let mut d = [42; 128];
                // let frame = frame::Frame::PathChallenge {
                //     data: [1, 2, 3, 4, 5, 6, 7, 8],
                // };
                // let wire_len = {
                //     let mut b = octets::OctetsMut::with_slice(&mut d);
                //     frame.to_bytes(&mut b).unwrap()
                // };
                //assert_eq!(wire_len, 9);
                //let mut b = octets::Octets::with_slice(&d);
        
                /*
                let stream_id = conn.stream_writable_next();
                match stream_id {
                    None => {
                        eprintln!("No stream id available");
                        //exit_kind = ExitKind::Crash;
                    },
                    Some(stream_id) => {
                        println!("Stream id: {:?}", stream_id);
                        // let input = input.target_bytes();
                        conn.stream_send(stream_id, input.target_bytes().as_slice(), false);
                        match quic_st.handle_sending(){
                            Err(e) => {
                                eprintln!("Failed to send data: {:?}", e);
                                exit_kind = ExitKind::Crash;
                            },
                            Ok(_) => (),
                        }
                        match quic_st.handle_recving(){
                            Err(e) => {
                                eprintln!("Failed to recv data: {:?}", e);
                                exit_kind = ExitKind::Crash;
                            },
                            Ok(_) => (),
                        }
                    //println!("Server name: {:?}", sn);
                    }
                }
                */
            }
        }
        //conn 必然存在，直接发送数据
        //测试:手动生成5000个path challenge帧 + Ping帧和2000个Padding帧
        // let mut input_struct = InputStruct::new();
        // input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(100).set_send_timeout(5);
        // input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
        // let mut frame_cycle1 = FramesCycleStruct::new();
        // frame_cycle1 = frame_cycle1.set_repeat_num(500);
        // // let pc_frame = frame::Frame::PathChallenge {
        // //     data: [1, 2, 3, 4, 5, 6, 7, 8],
        // // };
        // let nci_frame = frame::Frame::NewConnectionId {
        //     seq_num: 2,
        //     retire_prior_to:2,
        //     conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
        //     reset_token: [100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115],
        // };
        // //let ping_frame = frame::Frame::Ping { mtu_probe: Some(0) };
        // //frame_cycle1 = frame_cycle1.add_frame(pc_frame);
        // frame_cycle1 = frame_cycle1.add_frame(nci_frame);

        // // let mut frame_cycle2 = FramesCycleStruct::new();
        // // frame_cycle2 = frame_cycle2.set_repeat_num(200);
        // // let pad_frame = frame::Frame::Padding { len: (100) };
        // // frame_cycle2 = frame_cycle2.add_frame(pad_frame);
        // input_struct = input_struct.add_frames_cycle(frame_cycle1);
        // // input_struct = input_struct.add_frames_cycle(frame_cycle2);
        // input_struct = input_struct.calc_frames_cycle_len();


        //通过input 生成frames
        let binding = input.target_bytes();
        let mut inputs = binding.as_slice();        
        let mut input_struct = InputStruct::new();
        input_struct = InputStruct_deserialize(inputs);

        let pkt_type = input_struct.pkt_type;
        // let lost_time_dur = input_struct.send_timeout;
        let lost_time_dur = 0;
        let recv_time = input_struct.recv_timeout;
        let mut recv_left_time = recv_time;
                
        let max_pkt_len = 0;
        let mut cur_pkt_len = 0;
        let mut total_sent_frames:u64 = 0;
        let mut total_sent_pkts: u64 = 0;
        let mut total_sent_bytes = 0;
        let cycles = input_struct.frames_cycle.len();
        for cur_cycle in 0..cycles{
            let repeat_num = input_struct.frames_cycle[cur_cycle].repeat_num;
            let mut start_pos = 0;
            for i in 0..repeat_num  {
                if i % 5001 == 5000 || i == repeat_num - 1 {
                    let frames = input_struct.gen_frames(start_pos,i as u64,cur_cycle);
                    start_pos = i as u64 + 1;
                    let mut frame_list: Vec<frame::Frame> = Vec::new();
                    for frame in frames.iter() {
    
                        debug!("frame len: {:?}", frame.wire_len());
                        debug!("frame type: {:?}", frame);
                        // 注释代码是按照标准的MTU讲帧尽可能的合并，在fuzz过程中这应该是负优化，于是每次只发送1个帧
                        if cur_pkt_len + frame.wire_len() < max_pkt_len {
                            frame_list.push(frame.clone());
                            cur_pkt_len += frame.wire_len();
                            total_sent_frames += 1;
                            total_sent_bytes += frame.wire_len();
                            debug!("sending frame: {:?}", frame);
                            continue;
                        }
                        frame_list.push(frame.clone());
                        total_sent_frames += 1;
                        total_sent_bytes += frame.wire_len();
                        total_sent_pkts += 1;
    
            
                        quic_st.send_pkt_to_server(pkt_type, &frame_list, &mut out);
                        match quic_st.handle_sending(){
                            Err(e) => {
                                eprintln!("Failed to send data: {:?}", e);
                                exit_kind = ExitKind::Crash;
                            },
                            Ok(_) => (),
                        }
                        // info!("total sent frames: {:?}, all: {:?}", total_sent_frames, frames.len());
                        sleep(Duration::from_micros(10));
                        if recv_left_time <= lost_time_dur {
                            let send_left_time = lost_time_dur - recv_left_time;
                            // sleep(Duration::from_millis(recv_left_time.try_into().unwrap()));
                            recv_left_time =  recv_time - send_left_time ;
                            //recv&handle conn's received packet 
                            match quic_st.handle_recving_once(){
                                Err(e) => {
                                    eprintln!("Failed to recv data: {:?}", e);
                                    exit_kind = ExitKind::Crash;
                                },
                                Ok((recv_pkts,recv_bytes)) => {
                                    total_recv_pkts += recv_pkts;
                                    total_recv_bytes += recv_bytes;
            
                                    ()
                                }
                            }
            
                            // sleep(Duration::from_millis( send_left_time as u64));
                            
                        }
                        else {
                            // sleep(Duration::from_millis(lost_time_dur.try_into().unwrap()));
                            recv_left_time -= lost_time_dur;
                        }
                        // 每发送100个包统计一下CPU使用率，不然统计的太多了
                        if total_sent_frames %100 ==0 {
                            let cur_cpu_usage = cpu_usage_observer.get_cur_cpu_usage();
                            cur_cpu_usages.push(cur_cpu_usage);
                        }
            
                        debug!("recv_left_time: {:?},lost_time: {:?}", recv_left_time,lost_time_dur);
                        cur_pkt_len = frame.wire_len();
                        frame_list.clear();
                        // frame_list.push(frame.clone());
            
                    }
                    info!("sent {:?} frames",frames.len());
    
                }
            }
    
        } 

        for i in 0..10 {
            match quic_st.handle_recving(){
                Err(e) => {
                    eprintln!("Failed to recv data: {:?}", e);
                    exit_kind = ExitKind::Crash;
                },
                Ok((recv_pkts,recv_bytes)) => {
                    total_recv_pkts += recv_pkts;
                    total_recv_bytes += recv_bytes;
                    ()
                }
            }
        }
        // sleep(Duration::from_secs(100));


        if total_recv_pkts != 0 {
            self.change_recv_pkts(total_recv_pkts);
            self.change_non_res_times(0);

        }
        else {
            self.change_recv_pkts(0);
            self.change_non_res_times(self.non_res_times + 1);
        }
        buf_recv_pkt_num_observer.set_recv_bytes(total_recv_bytes as u64);
        buf_recv_pkt_num_observer.set_recv_pkts(total_recv_pkts as u64);
        buf_recv_pkt_num_observer.set_send_bytes(total_sent_bytes as u64);
        buf_recv_pkt_num_observer.set_send_pkts(total_sent_pkts  as u64);
        self.update_recv_pkt_obs(buf_recv_pkt_num_observer);
        self.update_cpu_usage_obs(cur_cpu_usages);
        // for i in 0..frames.len() {
        //     quic_st.handle_recving();
        // }
        
        let res = self.judge_server_status();
        if self.non_res_times == 30{
            error!("marked crashed");
            // kill self.pid
            let pid = self.pid;
            warn!("killing pid: {:?}", pid);
            let signal = self.kill_signal.unwrap_or(Signal::SIGKILL);
            unsafe {
                kill(Pid::from_raw(pid), signal).unwrap();
            }
            exit_kind = ExitKind::Ok;
        }

        Ok(exit_kind)
    }
}

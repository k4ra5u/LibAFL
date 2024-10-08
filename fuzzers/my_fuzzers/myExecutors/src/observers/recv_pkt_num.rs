use std::borrow::Cow;

use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::{Error, Named,tuples::MatchName};
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecvPktNumObserver {
    name: Cow<'static, str>,
    send_pkts: u64,
    recv_pkts: u64,
    send_bytes: u64,
    recv_bytes: u64,
}

impl RecvPktNumObserver {
    /// Creates a new [`RecvPktNumObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            send_pkts: 0,
            recv_pkts: 0,
            send_bytes: 0,
            recv_bytes: 0,
        }
    }

}

pub trait QUICObserver<S>: Observer<S>
where 
    S: UsesInput,
{
    fn get_input_struct(&mut self, state: &mut S) -> InputStruct 
    where 
        S: HasMutatorBytes,
    {
        let mut send_pkts = 0;
        let mut recv_pkts = 0;
        let mut useful_frames = 0;
        let mut quic_corp = quic_input::InputStruct_deserialize(state.bytes());
        quic_corp
        
    }

}
impl<S> QUICObserver<S> for RecvPktNumObserver
where 
    S: UsesInput+HasMutatorBytes,
{}
impl<S> Observer<S> for RecvPktNumObserver
where
    S: UsesInput + HasMutatorBytes ,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.send_pkts = 0;
        self.recv_pkts = 0;
        self.send_bytes = 0;
        self.recv_bytes = 0;
        let mut quic_corp = self.get_input_struct(_state);
        let mut total_send_pkts = 0;
        let mut total_send_bytes = 0;
        for cycle in quic_corp.frames_cycle.iter() {
            total_send_pkts += cycle.repeat_num as u64 * cycle.basic_frames.len() as u64;
            for frame in cycle.basic_frames.iter(){
                total_send_bytes += cycle.repeat_num as u64 * frame.wire_len() as u64;                
            }
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for RecvPktNumObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

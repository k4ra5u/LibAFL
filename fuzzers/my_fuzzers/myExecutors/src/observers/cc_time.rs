use std::borrow::Cow;

use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::{Error, Named,tuples::MatchName};
use log::info;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct CCTimesObserver {
    name: Cow<'static, str>,
    cc_pkn: u64,
    cc_res_pkn: u64,
    cc_reason_num: u64,
    cc_res_frame_type: usize,
    cc_reason: String,

}

impl CCTimesObserver {
    /// Creates a new [`CPUUsageObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            cc_pkn: 0,
            cc_res_pkn: 0,
            cc_res_frame_type : 0,
            cc_reason_num: 0,
            cc_reason: String::from(""),
        }
    }
    pub fn set_cc_pkn(&mut self, cc_pkn: u64) {
        self.cc_pkn = cc_pkn;
    }
    pub fn set_cc_res_pkn(&mut self, cc_res_pkn: u64) {
        self.cc_res_pkn = cc_res_pkn;
    }
    pub fn set_cc_reason_num(&mut self, cc_reason_num: u64) {
        self.cc_reason_num = cc_reason_num;
    }
    pub fn set_cc_reason(&mut self, cc_reason: String) {
        self.cc_reason = cc_reason.clone();
    }
    pub fn set_cc_res_frame_type(&mut self, cc_res_frame_type: usize) {
        self.cc_res_frame_type = cc_res_frame_type;
    }

}

impl<S> Observer<S> for CCTimesObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.cc_pkn = 0;
        self.cc_reason_num = 0;
        self.cc_res_pkn = 0;
        self.cc_res_frame_type = 0;
        self.cc_reason = String::from("");
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        info!("post_exec of CCTimesObserver: {:?}", self);
        Ok(())
    }
}

impl Named for CCTimesObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

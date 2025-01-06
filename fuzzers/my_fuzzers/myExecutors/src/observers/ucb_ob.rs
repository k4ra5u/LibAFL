use std::borrow::Cow;
use std::time::Duration;
use std::net::ToSocketAddrs;

use std::io::prelude::*;

use std::rc::Rc;

use std::cell::RefCell;


use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::{Error, Named,tuples::MatchName, rands::Rand,};
use log::{debug, error, info};
use ring::rand::*;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState,state::HasRand};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::misc::*;
use std::thread::sleep;

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct UCBObserver {
    pub name: Cow<'static, str>,
    reward: f64,
}

impl UCBObserver {
    /// Creates a new [`CPUUsageObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            reward: 0.0,
        }
    }
    pub fn get_reward(&self) -> f64 {
        self.reward
    }
}

impl<S> Observer<S> for UCBObserver
where
    S: UsesInput + HasRand,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reward = 0.0;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        debug!("post_exec of UCBObserver: {:?}", self);
        let rand_0 = _state.rand_mut().below(10000);
        let rand_0_1 = rand_0 as f64 / 10000.0;
        self.reward = rand_0_1;
        Ok(())
    }
}

impl Named for UCBObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

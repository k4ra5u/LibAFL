use core::{
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use std::{cmp::min, sync::Arc};

use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type, Merge, NamedTuple},
    Named,
};
use libafl_bolts::alloc::{borrow::Cow, vec::Vec};

use log::{info, warn,debug};
use nix::sys::select;
use quiche::{frame, packet, stream, Connection, ConnectionId, Header};
use ring::aead::quic;
use serde::{Deserialize, Serialize};

use libafl::{mutators::MutationId};
use libafl::prelude::buffer_copy;
use libafl::{
    corpus::{Corpus, CorpusId},
    mutators::{
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
            ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
            BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator,
            BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator,
            CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator,
            DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
        },
        token_mutations::{TokenInsert, TokenReplace},
        MutationResult, Mutator, MutatorsTuple,
    },
    state::{HasCorpus, HasRand},
    Error, HasMetadata,
    inputs::{HasMutatorBytes},
};
use crate::inputstruct::*;

// pub struct InputStruct {
//     pub pkt_type: packet::Type,
//     pub send_timeout: Duration,
//     pub recv_timeout: Duration,
//     pub packet_resort_type: pkt_resort_type,
//     pub number_of_cycles: usize,
//     pub cycles_len: Vec<usize>,
//     pub frames_cycle: Vec<FramesCycleStruct>,
// }

// pub struct FramesCycleStruct {
//     pub repeat_num: usize,
//     pub basic_frames: Vec<frame::Frame>,
// }

// 变异quic数据包的类型
pub struct QuicPktTypeMutator;
impl QuicPktTypeMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicPktTypeMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicPktTypeMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicPktTypeMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicPktTypeMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let changed_pkt_type = state.rand_mut().below(6);
        match changed_pkt_type {
            0 => {
                quic_corp.pkt_type = packet::Type::Initial;
            }
            1 => {
                quic_corp.pkt_type = packet::Type::ZeroRTT;
            }
            2 => {
                quic_corp.pkt_type = packet::Type::Handshake;
            }
            3 => {
                quic_corp.pkt_type = packet::Type::Retry;
            }
            4 => {
                quic_corp.pkt_type = packet::Type::VersionNegotiation;
            }
            5 => {
                quic_corp.pkt_type = packet::Type::Short;
            }
            _ => {
                quic_corp.pkt_type = packet::Type::Initial;
            }
        } 
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        
        Ok(MutationResult::Mutated)
    }
}

// 变异quic数据包收发的比例
pub struct QuicSendRecvTimesMutator;
impl QuicSendRecvTimesMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicSendRecvTimesMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicSendRecvTimesMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicSendRecvTimesMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicSendRecvTimesMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let mut changed_recv_time = state.rand_mut().below(1000);
        //let mut changed_send_time = state.rand_mut().below(1000);
        let mut changed_send_time = 200;
        if changed_recv_time < changed_send_time {
            changed_recv_time = changed_send_time;
        }
        quic_corp.recv_timeout = changed_recv_time as u64;
        quic_corp.send_timeout = changed_send_time as u64;
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)
    }
}

// 变异数据包重新排序的方式
pub struct QuicResortMutator;
impl QuicResortMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicResortMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicResortMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicResortMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicResortMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let changed_packet_resort_type = state.rand_mut().below(4);
        match changed_packet_resort_type {
            0 => {
                quic_corp.packet_resort_type = pkt_resort_type::None;
            }
            1 => {
                quic_corp.packet_resort_type = pkt_resort_type::Random;
            }
            2 => {
                quic_corp.packet_resort_type = pkt_resort_type::Reverse;
            }
            3 => {
                quic_corp.packet_resort_type = pkt_resort_type::Odd_even;
            }
            _ => {
                quic_corp.packet_resort_type = pkt_resort_type::None;
            }
        }
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)
    }
}

// 变异数据包的循环节
pub struct QuicFrameCyclesMutator;
impl QuicFrameCyclesMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicFrameCyclesMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicFrameCyclesMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicFrameCyclesMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicFrameCyclesMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());

        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)
    }
}

// 变异每个数据包的重复次数
pub struct QuicFrameRepeatNumMutator;
impl QuicFrameRepeatNumMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicFrameRepeatNumMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicFrameRepeatNumMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicFrameRepeatNumMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicFrameRepeatNumMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        let base_repeat_num = quic_corp.frames_cycle[selected_cycle].repeat_num;
        //let changed_repeat_num = state.rand_mut().between(base_repeat_num >> 1, base_repeat_num << 1);
        let changed_repeat_num = base_repeat_num +10;
        quic_corp.frames_cycle[selected_cycle].repeat_num = changed_repeat_num;
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }
}

//变异循环节的帧类型及帧内容
pub struct QuicFrameItemMutator;
impl QuicFrameItemMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicFrameItemMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicFrameItemMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicFrameItemMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicFrameItemMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        let frames_len = quic_corp.frames_cycle[selected_cycle].basic_frames.len();
        let selected_frame = state.rand_mut().below(frames_len);
        let mut frame = quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame].clone();



        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }

}

// 增加循环节中帧
pub struct QuicAddFrameItemMutator;
impl QuicAddFrameItemMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicAddFrameItemMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicAddFrameItemMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicAddFrameItemMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicAddFrameItemMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        
        // TODO: 更加精细化的生成一个新的frame，需要修改现行的state，加入当前连接的状态
        let mut buf = vec![61u8; 100];
        buf[0] = state.rand_mut().below(25) as u8;
        for i in 1..100 {
            buf[i] = state.rand_mut().below(256) as u8;
        }
        let mut buf_slice: &[u8] = &buf;
        let frame = gen_quic_frame(&mut buf_slice, 100).unwrap();
        quic_corp.frames_cycle[selected_cycle].basic_frames.push(frame);



        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }

}

// 删除循环节中的帧
pub struct QuicDelFrameItemMutator;
impl QuicDelFrameItemMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicDelFrameItemMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicDelFrameItemMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicDelFrameItemMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicDelFrameItemMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        let frames_len = quic_corp.frames_cycle[selected_cycle].basic_frames.len();
        if frames_cycle_len == 1 && frames_len == 1 {
            return Ok(MutationResult::Skipped);
        }   
        if frames_len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let selected_frame = state.rand_mut().below(frames_len);
        quic_corp.frames_cycle[selected_cycle].basic_frames.remove(selected_frame);
        if frames_len == 1 {
            quic_corp.frames_cycle.remove(selected_cycle);
        }



        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }

}

// 变异帧中的一个数字类型的字段
pub struct QuicFrameItemNumMutator;
impl QuicFrameItemNumMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicFrameItemNumMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicFrameItemNumMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicFrameItemNumMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicFrameItemNumMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        let frames_len = quic_corp.frames_cycle[selected_cycle].basic_frames.len();
        let selected_frame = state.rand_mut().below(frames_len);
        let frame = match quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame].clone() {
            frame::Frame::Padding { len } => {
                let changed_len = state.rand_mut().between(0, 1200);
                frame::Frame::Padding { len: changed_len }
            },
            frame::Frame::Ping { mtu_probe } => {
                if let Some(mtu_probe) = mtu_probe {
                    let changed_mtu_probe = state.rand_mut().between(mtu_probe >> 2, mtu_probe << 2);
                    frame::Frame::Ping { mtu_probe: Some(changed_mtu_probe) }
                } else {
                    frame::Frame::Ping { mtu_probe: None }
                }
            },
            frame::Frame::ACK { ack_delay, ranges, ecn_counts } => {
                let change_type = state.rand_mut().below(3);
                match change_type {
                    0 => {
                        let changed_ack_delay = state.rand_mut().between(ack_delay as usize >> 2, (ack_delay << 2).try_into().unwrap());
                        frame::Frame::ACK { ack_delay: changed_ack_delay as u64, ranges: ranges.clone(), ecn_counts: ecn_counts.clone() }
                    },
                    1 => {
                        // TODO 设计如何针对ACK中的ranges进行变异
                        // let changed_ranges = ranges.iter().map(|range| {
                        //     let changed_range = frame::AckRange {
                        //         gap: state.rand_mut().between(range.gap >> 2, range.gap << 2),
                        //         range: state.rand_mut().between(range.range >> 2, range.range << 2),
                        //     };
                        //     changed_range
                        // }).collect();
                        frame::Frame::ACK { ack_delay: ack_delay, ranges: ranges.clone(), ecn_counts: ecn_counts.clone() }
                    },
                    2 => {
                        // TODO 设计如何针对ecn_conunts字段进行变异
                        // let changed_ecn_counts = ecn_counts.iter().map(|count| {
                        //     state.rand_mut().between(count >> 2, count << 2)
                        // }).collect();
                        frame::Frame::ACK { ack_delay: ack_delay, ranges: ranges.clone(), ecn_counts: ecn_counts.clone() }
                    }
                    _ => unreachable!(),
                }
            },
            frame::Frame::ResetStream { stream_id, error_code, final_size } => {
                let change_type = state.rand_mut().below(3);
                match change_type {
                    0 => {
                        let changed_stream_id = state.rand_mut().between(stream_id as usize >> 2, (stream_id << 2).try_into().unwrap());
                        frame::Frame::ResetStream { stream_id: changed_stream_id as u64, error_code, final_size }
                    },
                    1 => {
                        let changed_error_code = state.rand_mut().between(error_code as usize >> 2 , (error_code << 2).try_into().unwrap());
                        frame::Frame::ResetStream { stream_id, error_code: changed_error_code as u64, final_size }
                    },
                    2 => {
                        let changed_final_size = state.rand_mut().between(final_size as usize >> 2, (final_size << 2).try_into().unwrap());
                        frame::Frame::ResetStream { stream_id, error_code, final_size: changed_final_size as u64 }
                    }
                    _ => unreachable!(),
                }

            },
            frame::Frame::StopSending { stream_id, error_code } => {
                let change_type = state.rand_mut().below(2);
                match change_type {
                    0 => {
                        let changed_stream_id = state.rand_mut().between(stream_id as usize >> 2, (stream_id << 2).try_into().unwrap());
                        frame::Frame::StopSending { stream_id: changed_stream_id as u64, error_code }
                    }
                    1 => {
                        let changed_error_code = state.rand_mut().between(error_code as usize >> 2 , (error_code << 2).try_into().unwrap());
                        frame::Frame::StopSending { stream_id, error_code: changed_error_code as u64 }
                    }
                    _ => unreachable!(),
                }
            },
            frame::Frame::Crypto { data } => {
                // pub struct RangeBuf {
                //     data: Arc<Vec<u8>>,
                //     start: usize,
                //     pos: usize,
                //     len: usize,
                //     off: u64,
                //     fin: bool,
                //     /* … */
                // }
                let change_type = state.rand_mut().below(5);
                match change_type {
                    0 => {
                        let changed_start = state.rand_mut().between(data.start >> 2, data.start << 2);
                        frame::Frame::Crypto { data: stream::RangeBuf { data: data.data.clone(), start: changed_start, pos: data.pos, len: data.len, off: data.off ,fin: data.fin} }
                    }
                    1 => {
                        let changed_pos = state.rand_mut().between(data.pos >> 2, data.pos << 2);
                        frame::Frame::Crypto { data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: changed_pos, len: data.len, off: data.off ,fin: data.fin } }
                    }
                    2 => {
                        let changed_len = state.rand_mut().between(data.len >> 2, data.len << 2);
                        // TODO
                        // frame::Frame::Crypto { data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: changed_len, off: data.off ,fin: data.fin } }
                        frame::Frame::Crypto { data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: data.len, off: data.off ,fin: data.fin } }
                    }
                    3 => {
                        let changed_off = state.rand_mut().between(data.off as usize >> 2, (data.off << 2).try_into().unwrap());
                        frame::Frame::Crypto { data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: data.len, off: changed_off as u64 ,fin: data.fin } }
                    }
                    4 => {
                        let changed_fin = data.fin ^ true;
                        frame::Frame::Crypto { data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: data.len, off: data.off, fin: changed_fin } }
                    }
                    _ => unreachable!(),
                }
            },
            frame::Frame::CryptoHeader { offset, length } => {
                let change_type = state.rand_mut().below(2);
                match change_type {
                    0 => {
                        let changed_offset = state.rand_mut().between(offset as usize >> 2, (offset << 2).try_into().unwrap());
                        frame::Frame::CryptoHeader { offset: changed_offset as u64, length }
                    }
                    1 => {
                        let changed_length = state.rand_mut().between(length as usize >> 2, (length << 2).try_into().unwrap());
                        frame::Frame::CryptoHeader { offset, length: changed_length }
                    }
                    _ => unreachable!(),
                }
                
            },
            frame::Frame::NewToken { token } => {
                frame::Frame::NewToken { token }
            },
            frame::Frame::Stream { stream_id, data } => {
                let change_type = state.rand_mut().below(5);
                match change_type {
                    0 => {
                        let changed_start = state.rand_mut().between(data.start >> 2, data.start << 2);
                        frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: data.data.clone(), start: changed_start, pos: data.pos, len: data.len, off: data.off ,fin: data.fin} }
                    }
                    1 => {
                        let changed_pos = state.rand_mut().between(data.pos >> 2, data.pos << 2);
                        frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: changed_pos, len: data.len, off: data.off ,fin: data.fin } }
                    }
                    2 => {
                        let changed_len = state.rand_mut().between(data.len >> 2, data.len << 2);
                        // TODO
                        // frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: changed_len, off: data.off ,fin: data.fin } }
                        frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: data.len, off: data.off ,fin: data.fin } }
                    }
                    3 => {
                        let changed_off = state.rand_mut().between(data.off as usize >> 2, (data.off << 2).try_into().unwrap());
                        frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: data.len, off: changed_off as u64 ,fin: data.fin } }
                    }
                    4 => {
                        let changed_fin = data.fin ^ true;
                        frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: data.data.clone(), start: data.start, pos: data.pos, len: data.len, off: data.off, fin: changed_fin } }
                    }
                    _ => unreachable!(),
                }
            },
            frame::Frame::StreamHeader { stream_id, offset, length, fin } => {
                let change_type = state.rand_mut().below(3);
                match change_type {
                    0 => {
                        let changed_offset = state.rand_mut().between(offset as usize >> 2, (offset << 2).try_into().unwrap());
                        frame::Frame::StreamHeader { stream_id, offset: changed_offset as u64, length, fin }
                    }
                    1 => {
                        let changed_length = state.rand_mut().between(length as usize >> 2, (length << 2).try_into().unwrap());
                        frame::Frame::StreamHeader { stream_id, offset, length: changed_length, fin }
                    }
                    2 => {
                        let changed_fin = fin ^ true;
                        frame::Frame::StreamHeader { stream_id, offset, length, fin: changed_fin }
                    }
                    _ => unreachable!(),
                }
                
            },
            frame::Frame::MaxData { max } => {
                let changed_max = state.rand_mut().between(max as usize >> 2, (max << 2).try_into().unwrap());
                frame::Frame::MaxData { max: changed_max as u64 }
            },
            frame::Frame::MaxStreamData { stream_id, max } => {
                let changed_max = state.rand_mut().between(max as usize >> 2, (max << 2).try_into().unwrap());
                frame::Frame::MaxStreamData { stream_id, max: changed_max as u64 }
            },
            frame::Frame::MaxStreamsBidi { max } => {
                let changed_max = state.rand_mut().between(max as usize >> 2, (max << 2).try_into().unwrap());
                frame::Frame::MaxStreamsBidi { max: changed_max as u64 }
            },
            frame::Frame::MaxStreamsUni { max } => {
                let changed_max = state.rand_mut().between(max as usize >> 2, (max << 2).try_into().unwrap());
                frame::Frame::MaxStreamsUni { max: changed_max as u64 }
            },
            frame::Frame::DataBlocked { limit } => {
                let changed_limit = state.rand_mut().between(limit as usize >> 2, (limit << 2).try_into().unwrap());
                frame::Frame::DataBlocked { limit: changed_limit as u64 }
            },
            frame::Frame::StreamDataBlocked { stream_id, limit } => {
                let changed_limit = state.rand_mut().between(limit as usize >> 2, (limit << 2).try_into().unwrap());
                frame::Frame::StreamDataBlocked { stream_id, limit: changed_limit as u64 }
            },
            frame::Frame::StreamsBlockedBidi { limit } => {
                let changed_limit = state.rand_mut().between(limit as usize >> 2, (limit << 2).try_into().unwrap());
                frame::Frame::StreamsBlockedBidi { limit: changed_limit as u64 }
            },
            frame::Frame::StreamsBlockedUni { limit } => {
                let changed_limit = state.rand_mut().between(limit as usize >> 2, (limit << 2).try_into().unwrap());
                frame::Frame::StreamsBlockedUni { limit: changed_limit as u64 }
            },
            frame::Frame::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token } => {
                let changed_type = state.rand_mut().below(2);
                match changed_type {
                    0 => {
                        let changed_seq_num = state.rand_mut().between(seq_num as usize >> 2, (seq_num << 2).try_into().unwrap());
                        frame::Frame::NewConnectionId { seq_num: changed_seq_num as u64, retire_prior_to, conn_id, reset_token }
                    }
                    1 => {
                        let changed_retire_prior_to = state.rand_mut().between(retire_prior_to as usize >> 2, (retire_prior_to << 2).try_into().unwrap());
                        frame::Frame::NewConnectionId { seq_num, retire_prior_to: changed_retire_prior_to as u64, conn_id, reset_token }
                    }
                    _ => unreachable!(),
                }
            },
            frame::Frame::RetireConnectionId { seq_num } => {
                let changed_seq_num = state.rand_mut().between(seq_num as usize >> 2, (seq_num << 2).try_into().unwrap());
                frame::Frame::RetireConnectionId { seq_num: changed_seq_num as u64 }
            },
            frame::Frame::PathChallenge { data } => {
                frame::Frame::PathChallenge { data }
            },
            frame::Frame::PathResponse { data } => {
                frame::Frame::PathResponse { data }
            },
            frame::Frame::ConnectionClose { error_code, frame_type, reason } => {
                let change_type = state.rand_mut().below(2);
                match change_type {
                    0 => {
                        let changed_error_code = state.rand_mut().between(error_code as usize >> 2, (error_code << 2).try_into().unwrap());
                        frame::Frame::ConnectionClose { error_code: changed_error_code as u64, frame_type, reason }
                    }
                    1 => {
                        let changed_frame_type = state.rand_mut().between(frame_type as usize >> 2, (frame_type << 2).try_into().unwrap());
                        frame::Frame::ConnectionClose { error_code, frame_type: changed_frame_type as u64, reason }
                    }
                    _ => unreachable!(),
                    
                }
            },
            frame::Frame::ApplicationClose { error_code, reason } => {
                let changed_error_code = state.rand_mut().between(error_code as usize >> 2, (error_code << 2).try_into().unwrap());
                frame::Frame::ApplicationClose { error_code: changed_error_code as u64, reason }
            },
            frame::Frame::HandshakeDone => {
                frame::Frame::HandshakeDone
            },
            frame::Frame::Datagram { data } => {
                frame::Frame::Datagram { data }
            },
            frame::Frame::DatagramHeader { length } => {
                let changed_length = state.rand_mut().between(length as usize >> 2, (length << 2).try_into().unwrap());
                frame::Frame::DatagramHeader { length: changed_length }
            },
            frame::Frame::Others { data } => {
                frame::Frame::Others { data }
            },
        };
        debug!("changing num of frame: {:?}", frame);
        quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame] = frame;
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }

}

// 变异帧中的一个字符串长度的字段
pub struct QuicFrameItemStrLenMutator;
impl QuicFrameItemStrLenMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicFrameItemStrLenMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicFrameItemStrLenMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicFrameItemStrLenMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicFrameItemStrLenMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        let frames_len = quic_corp.frames_cycle[selected_cycle].basic_frames.len();
        debug!("frames_len: {:?}",frames_len);
        let selected_frame = state.rand_mut().below(frames_len);
        let frame = match quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame].clone() {
            frame::Frame::Padding { len } => {
                frame::Frame::Padding { len }
            },
            frame::Frame::Ping { mtu_probe } => {
                frame::Frame::Ping { mtu_probe }
            },
            frame::Frame::ACK { ack_delay, ranges, ecn_counts } => {
                frame::Frame::ACK { ack_delay, ranges, ecn_counts }
            },
            frame::Frame::ResetStream { stream_id, error_code, final_size } => {
                frame::Frame::ResetStream { stream_id, error_code, final_size }
            },
            frame::Frame::StopSending { stream_id, error_code } => {
                frame::Frame::StopSending { stream_id, error_code }
            },
            frame::Frame::Crypto { data } => {
                let mut data_data_len = data.data.len();
                let changed_data_data_len = state.rand_mut().between(data_data_len >> 2, min(data_data_len << 2,1500));
                let mut data_data = vec![0u8; changed_data_data_len];
                for i in 0..min(data_data_len, changed_data_data_len) {
                    data_data[i] = data.data[i];
                }
                frame::Frame::Crypto { data: stream::RangeBuf { data: Arc::new(data_data), start: data.start, pos: data.pos, len: changed_data_data_len, off: data.off ,fin: data.fin} }
            },
            frame::Frame::CryptoHeader { offset, length } => {
                frame::Frame::CryptoHeader { offset, length }
            },
            frame::Frame::NewToken { token } => {
                let token_len = token.len();
                let changed_token_len = state.rand_mut().between(token_len >> 2, min(token_len << 2,1500));
                let mut token_data = vec![0u8; changed_token_len];
                for i in 0..min(token_len, changed_token_len){
                    token_data[i] = token[i];
                }
                frame::Frame::NewToken { token: token_data }
            },
            frame::Frame::Stream { stream_id, data } => {
                let mut data_data_len = data.data.len();
                let changed_data_data_len = state.rand_mut().between(data_data_len >> 2, min(data_data_len << 2,1500));
                let mut data_data = vec![0u8; changed_data_data_len];
                for i in 0..min(changed_data_data_len,data_data_len) {
                    data_data[i] = data.data[i];
                }
                frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: Arc::new(data_data), start: data.start, pos: data.pos, len: changed_data_data_len, off: data.off ,fin: data.fin} }
            },
            frame::Frame::StreamHeader { stream_id, offset, length, fin } => {
                frame::Frame::StreamHeader { stream_id, offset, length, fin }
            },
            frame::Frame::MaxData { max } => {
                frame::Frame::MaxData { max }
            },
            frame::Frame::MaxStreamData { stream_id, max } => {
                frame::Frame::MaxStreamData { stream_id, max }
            },
            frame::Frame::MaxStreamsBidi { max } => {
                frame::Frame::MaxStreamsBidi { max }
            },
            frame::Frame::MaxStreamsUni { max } => {
                frame::Frame::MaxStreamsUni { max }
            },
            frame::Frame::DataBlocked { limit } => {
                frame::Frame::DataBlocked { limit }
            },
            frame::Frame::StreamDataBlocked { stream_id, limit } => {
                frame::Frame::StreamDataBlocked { stream_id, limit }
            },
            frame::Frame::StreamsBlockedBidi { limit } => {
                frame::Frame::StreamsBlockedBidi { limit }
            },
            frame::Frame::StreamsBlockedUni { limit } => {
                frame::Frame::StreamsBlockedUni { limit }
            },
            frame::Frame::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token } => {
                frame::Frame::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token }
            },
            frame::Frame::RetireConnectionId { seq_num } => {
                frame::Frame::RetireConnectionId { seq_num }
            },
            frame::Frame::PathChallenge { data } => {
                frame::Frame::PathChallenge { data }
            },
            frame::Frame::PathResponse { data } => {
                frame::Frame::PathResponse { data }
            },
            frame::Frame::ConnectionClose { error_code, frame_type, reason } => {
                let changed_reason_len = state.rand_mut().between(reason.len() >> 2, min(reason.len() << 2,1500));
                let mut reason_data = vec![0u8; changed_reason_len];
                for i in 0..min(reason.len(), changed_reason_len) {
                    reason_data[i] = reason[i];
                }
                frame::Frame::ConnectionClose { error_code, frame_type, reason: reason_data }
            },
            frame::Frame::ApplicationClose { error_code, reason } => {
                let changed_reason_len = state.rand_mut().between(reason.len() >> 2, min(reason.len() << 2,1500));
                let mut reason_data = vec![0u8; changed_reason_len];
                for i in 0..min(reason.len(), changed_reason_len) {
                    reason_data[i] = reason[i];
                }
                frame::Frame::ApplicationClose { error_code, reason: reason_data }
            },
            frame::Frame::HandshakeDone => {
                frame::Frame::HandshakeDone
            },
            frame::Frame::Datagram { data } => {
                let changed_data_len = state.rand_mut().between(data.len() >> 2, min(data.len() << 2,1500));
                let mut data_data = vec![0u8; changed_data_len];
                for i in 0..min(data.len(),changed_data_len) {
                    data_data[i] = data[i];
                }
                frame::Frame::Datagram { data: data_data }
            },
            frame::Frame::DatagramHeader { length } => {
                frame::Frame::DatagramHeader { length }
            },
            frame::Frame::Others { data } => {
                frame::Frame::Others { data }
            },
        };

        debug!("changing str len of frame: {:?}", frame);
        quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame] = frame;
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }

}

// 变异帧中的一个字符串内容的字段
pub struct QuicFrameItemStrContentMutator;
impl QuicFrameItemStrContentMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for QuicFrameItemStrContentMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("QuicFrameItemStrContentMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for QuicFrameItemStrContentMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        debug!("QuicFrameItemStrContentMutator");
        let mut quic_corp = quic_input::InputStruct_deserialize(input.bytes());
        let frames_cycle_len = quic_corp.frames_cycle.len();
        let selected_cycle = state.rand_mut().below(frames_cycle_len);
        let frames_len = quic_corp.frames_cycle[selected_cycle].basic_frames.len();
        let selected_frame = state.rand_mut().below(frames_len);
        let frame = match quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame].clone() {
            frame::Frame::Padding { len } => {
                frame::Frame::Padding { len }
            },
            frame::Frame::Ping { mtu_probe } => {
                frame::Frame::Ping { mtu_probe }
            },
            frame::Frame::ACK { ack_delay, ranges, ecn_counts } => {
                frame::Frame::ACK { ack_delay, ranges, ecn_counts }
            },
            frame::Frame::ResetStream { stream_id, error_code, final_size } => {
                frame::Frame::ResetStream { stream_id, error_code, final_size }
            },
            frame::Frame::StopSending { stream_id, error_code } => {
                frame::Frame::StopSending { stream_id, error_code }
            },
            frame::Frame::Crypto { data } => {
                let data_data_len = data.data.len();
                let mut data_data = vec![0u8; data_data_len];
                for i in 0..data_data_len {
                    data_data[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::Crypto { data: stream::RangeBuf { data: Arc::new(data_data), start: data.start, pos: data.pos, len: data.len, off: data.off ,fin: data.fin} }
            },
            frame::Frame::CryptoHeader { offset, length } => {
                frame::Frame::CryptoHeader { offset, length }
            },
            frame::Frame::NewToken { token } => {
                let token_len = token.len();
                let mut changed_token_data = vec![0u8; token_len];
                for i in 0..token_len {
                    changed_token_data[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::NewToken { token: changed_token_data }
            },
            frame::Frame::Stream { stream_id, data } => {
                let data_data_len = data.data.len();
                let mut data_data = vec![0u8; data_data_len];
                for i in 0..data_data_len {
                    data_data[i] = state.rand_mut().below(256) as u8;
                }

                frame::Frame::Stream { stream_id, data: stream::RangeBuf { data: Arc::new(data_data), start: data.start, pos: data.pos, len: data.len, off: data.off ,fin: data.fin} }
            },
            frame::Frame::StreamHeader { stream_id, offset, length, fin } => {
                frame::Frame::StreamHeader { stream_id, offset, length, fin }
            },
            frame::Frame::MaxData { max } => {
                frame::Frame::MaxData { max }
            },
            frame::Frame::MaxStreamData { stream_id, max } => {
                frame::Frame::MaxStreamData { stream_id, max }
            },
            frame::Frame::MaxStreamsBidi { max } => {
                frame::Frame::MaxStreamsBidi { max }
            },
            frame::Frame::MaxStreamsUni { max } => {
                frame::Frame::MaxStreamsUni { max }
            },
            frame::Frame::DataBlocked { limit } => {
                frame::Frame::DataBlocked { limit }
            },
            frame::Frame::StreamDataBlocked { stream_id, limit } => {
                frame::Frame::StreamDataBlocked { stream_id, limit }
            },
            frame::Frame::StreamsBlockedBidi { limit } => {
                frame::Frame::StreamsBlockedBidi { limit }
            },
            frame::Frame::StreamsBlockedUni { limit } => {
                frame::Frame::StreamsBlockedUni { limit }
            },
            frame::Frame::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token } => {
                let change_type = state.rand_mut().below(2);
                match change_type {
                    0 => {
                        let conn_id_len = conn_id.len();
                        let mut changed_conn_id = vec![0u8; conn_id_len];
                        for i in 0..conn_id_len {
                            changed_conn_id[i] = state.rand_mut().below(256) as u8;
                        }
                        frame::Frame::NewConnectionId { seq_num, retire_prior_to, conn_id:changed_conn_id, reset_token }
                    }
                    1 => {
                        let reset_token_len = reset_token.len();
                        let mut changed_reset_token = reset_token.clone();
                        for i in 0..reset_token_len {
                            changed_reset_token[i] = state.rand_mut().below(256) as u8;
                        }
                        frame::Frame::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token: changed_reset_token }
                    }
                    _ => unreachable!(),
                }
            },
            frame::Frame::RetireConnectionId { seq_num } => {
                frame::Frame::RetireConnectionId { seq_num }
            },
            frame::Frame::PathChallenge { data } => {
                let mut changed_data = [0u8; 8];
                for i in 0..8 {
                    changed_data[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::PathChallenge { data: changed_data }
            },
            frame::Frame::PathResponse { data } => {
                let mut changed_data = [0u8; 8];
                for i in 0..8 {
                    changed_data[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::PathResponse { data: changed_data }
            },
            frame::Frame::ConnectionClose { error_code, frame_type, reason } => {
                let reason_len = reason.len();
                let mut changed_reason = vec![0u8; reason_len];
                for i in 0..reason_len {
                    changed_reason[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::ConnectionClose { error_code, frame_type, reason: changed_reason }
            },
            frame::Frame::ApplicationClose { error_code, reason } => {
                let reason_len = reason.len();
                let mut changed_reason = vec![0u8; reason_len];
                for i in 0..reason_len {
                    changed_reason[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::ApplicationClose { error_code, reason: changed_reason }
            },
            frame::Frame::HandshakeDone => {
                frame::Frame::HandshakeDone
            },
            frame::Frame::Datagram { data } => {
                let data_len = data.len();
                let mut changed_data = vec![0u8; data_len];
                for i in 0..data_len {
                    changed_data[i] = state.rand_mut().below(256) as u8;
                }
                frame::Frame::Datagram { data: changed_data }
            },
            frame::Frame::DatagramHeader { length } => {
                frame::Frame::DatagramHeader { length }
            },
            frame::Frame::Others { data } => {
                frame::Frame::Others { data }
            },
        };


        quic_corp.frames_cycle[selected_cycle].basic_frames[selected_frame] = frame;
        let changed_bytes = quic_corp.serialize();
        input.resize(changed_bytes.len(), 0);
        unsafe {
            buffer_copy(input.bytes_mut(), changed_bytes.as_slice(),0, 0, changed_bytes.len());
        }
        Ok(MutationResult::Mutated)

    }

}


// pub struct MessageNodeTokenReplaceMutator;

// impl MessageNodeTokenReplaceMutator {
//     pub fn new() -> Self {
//         Self
//     }
// }

// impl Named for MessageNodeTokenReplaceMutator {
//     fn name(&self) -> &Cow<'static, str> {
//         static NAME: Cow<'static, str> = Cow::Borrowed("HTTPMessageNodeTokenReplaceMutator");
//         &NAME
//     }
// }

// impl<I, S> Mutator<I, S> for MessageNodeTokenReplaceMutator
// where
//     S: HasRand + HasMetadata,
//     I: HasMutatorBytes,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//     ) -> Result<MutationResult, Error> {
//         let input = random_input_from_sequence!(state.rand_mut(), input.http_sequence_input_mut());
//         let mut node: &mut _ = unsafe { &mut *input.node };

//         while !node.is_leaf() {
//             let iter = node.iter_node_mut();
//             node = state.rand_mut().choose(iter).unwrap();
//         }

//         let tokens = state.metadata::<TokenMetadata>().unwrap();
//         let length = match node.node_type.label() {
//             NodeLabel::String => tokens.string.len(),
//             NodeLabel::Number => tokens.number.len(),
//             NodeLabel::Symbol => tokens.number.len(),
//         };

//         if length == 0 {
//             return Ok(MutationResult::Skipped);
//         }

//         let idx = state.rand_mut().below(length);
//         let tokens = state.metadata::<TokenMetadata>().unwrap();

//         let token = match node.node_type.label() {
//             NodeLabel::String => &tokens.string[idx],
//             NodeLabel::Number => &tokens.number[idx],
//             NodeLabel::Symbol => &tokens.symbol[idx],
//         };

//         node.value = Vec::from(token.as_bytes());
//         node.update_metadata_up(0);

//         Ok(MutationResult::Mutated)
//     }
// }
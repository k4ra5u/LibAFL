use std::{
    any::Any, env, ffi::{OsStr, OsString}, io::{self, prelude::*, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, time::Duration
};
use std::num::ParseIntError;
use libc::ERA;
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
    executors::{
        Executor, ExitKind, HasObservers
    }, 
    inputs::HasTargetBytes, 
    observers::{
        ObserversTuple, UsesObservers, get_asan_runtime_flags_with_log_path, AsanBacktraceObserver
    }, 
    state::{
        HasExecutions, State, UsesState
    }
};
use libafl_bolts::{
    tuples::{Handle, Handled,MatchName ,MatchNameRef, Prepend, RefIndexable},
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    AsSlice, AsSliceMut, Truncate,
};
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug};

use quiche::{frame::{self, EcnCounts, MAX_STREAM_SIZE}, packet, ranges, stream, Connection, ConnectionId, Error, Header};

fn buf_to_bool(buf: &mut &[u8]) -> Result<bool, Error> {
    if buf.len() < 1 {
        return Err(Error::BufferTooShort);
    }

    let num = buf[0] != 0;
    *buf = &buf[1..];
    Ok(num)
}

fn buf_to_u8(buf: &mut &[u8]) -> Result<u8, Error> {
    if buf.len() < 1 {
        return Err(Error::BufferTooShort);
    }

    let num = buf[0];
    *buf = &buf[1..];
    Ok(num)
}

fn buf_to_u16(buf: &mut &[u8]) -> Result<u16, Error> {
    if buf.len() < 2 {
        return Err(Error::BufferTooShort);
    }

    let num = u16::from_be_bytes([buf[0], buf[1]]);
    *buf = &buf[2..];
    Ok(num)
}

fn buf_to_u32(buf: &mut &[u8]) -> Result<u32, Error> {
    if buf.len() < 4 {
        return Err(Error::BufferTooShort);
    }

    let num = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    *buf = &buf[4..];
    Ok(num)
}

pub fn buf_to_u64(buf: &mut &[u8]) -> Result<u64, Error> {
    if buf.len() < 8 {
        return Err(Error::BufferTooShort);
    }

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[0..8]);

    let num = u64::from_be_bytes(bytes);
    *buf = &buf[8..];
    Ok(num)
}


pub fn padding(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
        
    }
    let frame = frame::Frame::Padding { len: frame_len };
    
    Ok(frame)
}


pub fn ping(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
        
    }
    let mtu_probe = Some(len);
    let frame = frame::Frame::Ping { mtu_probe: mtu_probe };

    Ok(frame)
}


pub fn ack(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
        
    }
    let mut ranges = ranges::RangeSet::default();
    let ranges_num = 10; 
    for i in 0..ranges_num {
        let start = 2*i;
        let end = 2*i+1;
        ranges.insert(start..end);
    }
    let frame = frame::Frame::ACK {
        ack_delay: 0,
        ranges,
        ecn_counts: None,
    };
    Ok(frame)

}


pub fn ack_ecn(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let mut ranges = ranges::RangeSet::default();
    let ranges_num = 10; 
    for i in 0..ranges_num {
        let start = 2*i;
        let end = 2*i+1;
        ranges.insert(start..end);
    }

    let ecn_counts = Some(EcnCounts {
        ect0_count: 10,
        ect1_count: 20,
        ecn_ce_count: 30,
    });

    let frame = frame::Frame::ACK {
        ack_delay: 0,
        ranges,
        ecn_counts,
    };
    Ok(frame)
}


pub fn reset_stream(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::ResetStream {
        stream_id: 10,
        error_code: 100,
        final_size: 100,
    };
    Ok(frame)
}


pub fn stop_sending(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::StopSending {
        stream_id: 10,
        error_code: 100,
    };

    Ok(frame)

}


pub fn crypto(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;  
    }
    let offset = 1000;
    let fin_flag = false;
    let data = buf;
    let frame = frame::Frame::Crypto {

        data: stream::RangeBuf::from(data, offset, fin_flag),
    };

    Ok(frame)
}


pub fn new_token(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len; 
    }
    let frame = frame::Frame::NewToken {
        token: buf.to_vec(),
    };

    Ok(frame)
}


pub fn stream(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
        
    }
    let stream_id = 10;
    let offset = 1000;
    let fin_flag = false;
    let data = buf;

    let frame = frame::Frame::Stream {
        stream_id,
        data: stream::RangeBuf::from(data, offset, fin_flag),
    };

    Ok(frame)
}


pub fn max_data(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
        
    }
    let frame = frame::Frame::MaxData { max: 10000000 };
    Ok(frame)
}


pub fn max_stream_data(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::MaxStreamData {
        stream_id: 10,
        max: 10000000,
    };
    Ok(frame)
}


pub fn max_streams_bidi(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::MaxStreamsBidi { max: 10000000};
    Ok(frame)
}


pub fn max_streams_uni(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::MaxStreamsUni { max: 10000000 };
    Ok(frame)
}


pub fn data_blocked(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::DataBlocked { limit: 10000000};
    Ok(frame)
}


pub fn stream_data_blocked(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::StreamDataBlocked {
        stream_id: 10,
        limit: 10000000,
    };
    Ok(frame)
}


pub fn streams_blocked_bidi(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::StreamsBlockedBidi { limit: 10000000 };
    Ok(frame)
}


pub fn streams_blocked_uni(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::StreamsBlockedUni { limit: 10000000};
    Ok(frame)
}


pub fn new_connection_id(buf: &mut &[u8], len: usize) -> Result<frame::Frame, Error> {
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let seq_num = 10;
    let retire_prior_to = 9;

    let conn_id_len = 20;    
    let conn_id = buf[0..conn_id_len].to_vec();
    *buf = &buf[conn_id_len..];
    let mut reset_token = [0u8; 16];
    reset_token.copy_from_slice(&buf[0..16]);
    *buf = &buf[16..];
    
    let frame = frame::Frame::NewConnectionId {
        seq_num,
        retire_prior_to,
        conn_id,
        reset_token,
    };

    Ok(frame)
}


pub fn retire_connection_id(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::RetireConnectionId { seq_num: 10 };
    Ok(frame)
}


pub fn path_challenge(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(&buf[0..8]);
    let frame = frame::Frame::PathChallenge {
        data,
    };
    Ok(frame)
}


pub fn path_response(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(&buf[0..8]);
    let frame = frame::Frame::PathChallenge {
        data,
    };
    Ok(frame)
}


pub fn connection_close(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let error_code = 100;
    let frame_type = 1000;
    let reason = buf.to_vec();
    // let frame = frame::Frame::ConnectionClose {
    //     error_code,
    //     frame_type,
    //     reason,
    // };
    let frame = frame::Frame::Datagram { data: reason };
    Ok(frame)
}


pub fn application_close(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let error_code = 100;
    let reason = buf.to_vec();
    // let frame = frame::Frame::ApplicationClose {
    //     error_code,
    //     reason,
    // };
    let frame = frame::Frame::Datagram { data: reason };
    Ok(frame)
}


pub fn handshake_done(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let frame = frame::Frame::HandshakeDone;
    Ok(frame)
}


pub fn datagram(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    
    let mut frame_len = buf.len();
    if frame_len > len {
        frame_len = len;
    }
    let data = buf.to_vec();

    let frame = frame::Frame::Datagram { data };
    Ok(frame)
}


pub fn gen_quic_frame(buf: &mut &[u8],len:usize) -> Result<frame::Frame, Error> {
    let selector_frame = buf[0];
    let mut frame_buf = &buf[1..];
    match selector_frame {
        0 => padding(&mut frame_buf,len),
        1 => ping(&mut frame_buf,len),
        2 => ack(&mut frame_buf,len),
        3 => ack_ecn(&mut frame_buf,len),
        4 => reset_stream(&mut frame_buf,len),
        5 => stop_sending(&mut frame_buf,len),
        6 => crypto(&mut frame_buf,len),
        7 => new_token(&mut frame_buf,len),
        8 => stream(&mut frame_buf,len),
        9 => max_data(&mut frame_buf,len),
        10 => max_stream_data(&mut frame_buf,len),
        11 => max_streams_bidi(&mut frame_buf,len),
        12 => max_streams_uni(&mut frame_buf,len),
        13 => data_blocked(&mut frame_buf,len),
        14 => stream_data_blocked(&mut frame_buf,len),
        15 => streams_blocked_bidi(&mut frame_buf,len),
        16 => streams_blocked_uni(&mut frame_buf,len),
        17 => new_connection_id(&mut frame_buf,len),
        18 => retire_connection_id(&mut frame_buf,len),
        19 => path_challenge(&mut frame_buf,len),
        20 => path_response(&mut frame_buf,len),
        21 => connection_close(&mut frame_buf,len),
        22 => application_close(&mut frame_buf,len),
        23 => handshake_done(&mut frame_buf,len),
        24 => datagram(&mut frame_buf,len),
        _ => Err(Error::BufferTooShort),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all() {
        let mut buf = vec![61u8; 1200];
        for i in 0..26 {
            buf[0] = i;
            let mut buf_slice: &[u8] = &buf;
            let frame = gen_quic_frame(&mut buf_slice, 1200).unwrap();
            println!("frame: {:?}", frame);
        }
        assert_eq!(0, 0);
    }
}

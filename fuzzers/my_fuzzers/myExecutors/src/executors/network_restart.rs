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

use quiche::{frame, packet, Connection, ConnectionId, Error, Header};
const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP_REQ_STREAM_ID: u64 = 4;

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub fn encode_pkt(
    conn: &mut Connection, pkt_type: packet::Type, frames: &[frame::Frame],
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut b = octets::OctetsMut::with_slice(buf);

    let epoch = pkt_type.to_epoch()?;

    let space = &mut conn.pkt_num_spaces[epoch];

    let pn = space.next_pkt_num;
    let pn_len = 4;

    let send_path = conn.paths.get_active()?;
    let active_dcid_seq = send_path
        .active_dcid_seq
        .as_ref()
        .ok_or(Error::InvalidState)?;
    let active_scid_seq = send_path
        .active_scid_seq
        .as_ref()
        .ok_or(Error::InvalidState)?;

    let hdr = Header {
        ty: pkt_type,
        version: conn.version,
        dcid: ConnectionId::from_ref(
            conn.ids.get_dcid(*active_dcid_seq)?.cid.as_ref(),
        ),
        scid: ConnectionId::from_ref(
            conn.ids.get_scid(*active_scid_seq)?.cid.as_ref(),
        ),
        pkt_num: pn,
        pkt_num_len: pn_len,
        token: conn.token.clone(),
        versions: None,
        key_phase: conn.key_phase,
    };

    hdr.to_bytes(&mut b)?;

    let payload_len = frames.iter().fold(0, |acc, x| acc + x.wire_len());

    if pkt_type != packet::Type::Short {
        let len = pn_len + payload_len + space.crypto_overhead().unwrap();
        b.put_varint(len as u64)?;
    }

    // Always encode packet number in 4 bytes, to allow encoding packets
    // with empty payloads.
    b.put_u32(pn as u32)?;

    let payload_offset = b.off();

    for frame in frames {
        frame.to_bytes(&mut b)?;
    }

    let aead = match space.crypto_seal {
        Some(ref v) => v,
        None => return Err(Error::InvalidState),
    };

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )?;

    space.next_pkt_num += 1;

    Ok(written)
}

pub fn decode_pkt(
    conn: &mut Connection, buf: &mut [u8],
) -> Result<Vec<frame::Frame>,Error> {
    let mut b = octets::OctetsMut::with_slice(buf);

    let mut hdr = Header::from_bytes(&mut b, conn.source_id().len()).unwrap();

    let epoch = hdr.ty.to_epoch()?;

    let aead = conn.pkt_num_spaces[epoch].crypto_open.as_ref().unwrap();

    let payload_len = b.cap();

    packet::decrypt_hdr(&mut b, &mut hdr, aead).unwrap();

    let pn = packet::decode_pkt_num(
        conn.pkt_num_spaces[epoch].largest_rx_pkt_num,
        hdr.pkt_num,
        hdr.pkt_num_len,
    );

    let mut payload =
        packet::decrypt_pkt(&mut b, pn, hdr.pkt_num_len, payload_len, aead)
            .unwrap();

    let mut frames = Vec::new();

    while payload.cap() > 0 {
        let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;
        frames.push(frame);
    }

    Ok(frames)
}



pub struct QuicStruct {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    socket: mio::net::UdpSocket,
    migrate_socket: mio::net::UdpSocket,
    conn: Option<quiche::Connection>,
    app_proto_selected: bool,
    keylog: Option<std::fs::File>,
    config:  quiche::Config ,
    events: mio::Events,
    poll: mio::Poll,
    send_info: Option<quiche::SendInfo>,
    write: usize,
    req_start: std::time::Instant,
    req_sent: bool,
    server_name: String,
    server_port: u16,
    server_host: String,
    scids: Vec<[u8; quiche::MAX_CONN_ID_LEN]>,
}

impl QuicStruct {

    pub fn new(server_name: String, server_port: u16, server_host: String) -> Self {
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);
    
        // Resolve server address.
        let address = format!("{}:{}", server_host, server_port);
        if address.is_empty() {
            panic!("Invalid server address");
        }
        let peer_addr = address.to_socket_addrs().unwrap().next().unwrap();

    
        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
    
        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let mut socket =
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

        let mut migrate_socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry().register(&mut migrate_socket, mio::Token(1), mio::Interest::READABLE).unwrap();
    
        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    
        // *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);
    
        config
            .set_application_protos(&[
                b"hq-interop",
                b"hq-29",
                b"hq-28",
                b"hq-27",
                b"http/0.9",
                b"h3",
            ])
            .unwrap();
    
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.set_initial_max_stream_data_uni(10_000_000);
        config.set_active_connection_id_limit(2);
        config.set_max_connection_window(25165824);
        config.set_max_stream_window(16777216);
        config.enable_early_data();
        config
        .set_cc_algorithm_name(&"cubic".to_string())
        .unwrap();
        config.enable_dgram(true, 1000, 1000);

        let mut keylog = None;
    
        if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_path)
                .unwrap();
    
            keylog = Some(file);
    
            config.log_keys();
        }

        let mut app_proto_selected = false;

    
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        //let scid = quiche::ConnectionId::from_ref(&scid);
        //SystemRandom::new().fill(&mut scid[..]).unwrap();
        let mut scids : Vec<[u8; quiche::MAX_CONN_ID_LEN]> = Vec::new();
        scids.push(scid);
    
        // Get local address.
        let local_addr = socket.local_addr().unwrap();

        Self{
            local_addr,
            config,
            peer_addr,
            socket,
            conn:None,
            events,
            poll,
            send_info:None,
            write:0,
            req_start: std::time::Instant::now(),
            req_sent: false,
            server_name,
            server_port,
            server_host,
            scids,
            migrate_socket,
            keylog,
            app_proto_selected,
        }

    }
    pub fn connect(&mut self) -> Result<(), String> {
        
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
    
        // Create a QUIC connection and initiate handshake.
        let mut scid = self.scids[0];
        SystemRandom::new().fill(&mut scid[..]).unwrap();
    
        let scid = quiche::ConnectionId::from_ref(&scid);
        let SN_name = Some(self.server_name.as_str());
        let mut conn = quiche::connect(
            SN_name,
            &scid,
            self.local_addr,
            self.peer_addr,
            &mut self.config,
        )
        .unwrap();
    
        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

    
        // 这是啥？
        // if let Some(session_file) = &args.session_file {
        //     if let Ok(session) = std::fs::read(session_file) {
        //         conn.set_session(&session).ok();
        //     }
        // }
    
        println!(
            "connecting to {:} from {:} with scid {:?}",
            self.peer_addr,
            self.socket.local_addr().unwrap(),
            scid,
        );
    
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    
        while let Err(e) = self.socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                println!(
                    "{} -> {}: send() would block",
                    self.socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }
    
            return Err(format!("send() failed: {e:?}"));
        }
    
        println!("written {}", write);
    
        let app_data_start = std::time::Instant::now();
    
        let mut pkt_count = 0;
    
        let mut scid_sent = false;
        let mut new_path_probed = false;
        let mut migrated = false;
        let mut finished = false;
    
        loop {
            if !conn.is_in_early_data() || self.app_proto_selected {
                self.poll.poll(&mut self.events, conn.timeout()).unwrap();
            }
    
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if self.events.is_empty() {
                println!("timed out");
    
                conn.on_timeout();
            }
    
            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            for event in &self.events {
                let socket = match event.token() {
                    mio::Token(0) => &self.socket,
    
                    mio::Token(1) => &self.migrate_socket,
    
                    _ => unreachable!(),
                };
    
                let local_addr = socket.local_addr().unwrap();
                'read: loop {
                    let (len, from) = match socket.recv_from(&mut buf) {
                        Ok(v) => v,
    
                        Err(e) => {
                            // There are no more UDP packets to read on this socket.
                            // Process subsequent events.
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                println!("{}: recv() would block", local_addr);
                                break 'read;
                            }
    
                            return Err(format!(
                                "{local_addr}: recv() failed: {e:?}"
                            ));
                        },
                    };
    
                    println!("{}: got {} bytes", local_addr, len);
    
                    // if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                    //     let path = format!("{target_path}/{pkt_count}.pkt");
    
                    //     if let Ok(f) = std::fs::File::create(path) {
                    //         let mut f = std::io::BufWriter::new(f);
                    //         f.write_all(&buf[..len]).ok();
                    //     }
                    // }
    
                    pkt_count += 1;
    
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
    
                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,
    
                        Err(e) => {
                            println!("{}: recv failed: {:?}", local_addr, e);
                            continue 'read;
                        },
                    };
    
                    println!("{}: processed {} bytes", local_addr, read);
                }
            }
    
            println!("done reading");
    
            if conn.is_closed() {
                println!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
    
                if !conn.is_established() {
                    println!(
                        "connection timed out after {:?}",
                        app_data_start.elapsed(),
                    );
    
                    return Err("HandshakeFail".to_owned());
                }
    
                // if let Some(session_file) = &args.session_file {
                //     if let Some(session) = conn.session() {
                //         std::fs::write(session_file, session).ok();
                //     }
                // }
    
                // if let Some(h_conn) = http_conn {
                //     if h_conn.report_incomplete(&app_data_start) {
                //         return Err(ClientError::HttpFail);
                //     }
                // }
    
                break;
            }
            if (conn.is_established() || conn.is_in_early_data())
            {
                finished = true;
                println!("connection established");

                if let Err(e) = conn.stream_send(0, b"aaaaaaaaaaaaaaaa", false) {        
                    return Err(format!("Failed to send data: {:?}", e));
                }
                //break;
            }
            println!("connection not established yet, but breaked");
    

    
            // // Handle path events.
            while let Some(qe) = conn.path_event_next() {
                match qe {
                    quiche::PathEvent::New(..) => unreachable!(),
    
                    quiche::PathEvent::Validated(local_addr, peer_addr) => {
                        println!(
                            "Path ({}, {}) is now validated",
                            local_addr, peer_addr
                        );
                        conn.migrate(local_addr, peer_addr).unwrap();
                        migrated = true;
                    },
    
                    quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                        println!(
                            "Path ({}, {}) failed validation",
                            local_addr, peer_addr
                        );
                    },
    
                    quiche::PathEvent::Closed(local_addr, peer_addr) => {
                        println!(
                            "Path ({}, {}) is now closed and unusable",
                            local_addr, peer_addr
                        );
                    },
    
                    quiche::PathEvent::ReusedSourceConnectionId(
                        cid_seq,
                        old,
                        new,
                    ) => {
                        println!(
                            "Peer reused cid seq {} (initially {:?}) on {:?}",
                            cid_seq, old, new
                        );
                    },
    
                    quiche::PathEvent::PeerMigrated(..) => unreachable!(),
                }
            }
    
            // // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = conn.retired_scid_next() {
                println!("Retiring source CID {:?}", retired_scid);
            }
    

            if !new_path_probed &&
                scid_sent &&
                conn.available_dcids() > 0
            {
                let additional_local_addr =
                    self.migrate_socket.local_addr().unwrap();
                conn.probe_path(additional_local_addr, self.peer_addr).unwrap();
    
                new_path_probed = true;
            }

            let mut sockets = vec![&self.socket];
            // sockets.push(&self.migrate_socket);
            let mut flag = 0;
    
            for socket in sockets {
                let local_addr = socket.local_addr().unwrap();
    
                for peer_addr in conn.paths_iter(local_addr) {
                    loop {
                        let (write, send_info) = match conn.send_on_path(
                            &mut out,
                            Some(local_addr),
                            Some(peer_addr),
                        ) {
                            Ok(v) => v,
    
                            Err(quiche::Error::Done) => {
                                println!(
                                    "{} -> {}: done writing",
                                    local_addr,
                                    peer_addr
                                );
                                break;
                            },
    
                            Err(e) => {
                                println!(
                                    "{} -> {}: send failed: {:?}",
                                    local_addr, peer_addr, e
                                );
    
                                conn.close(false, 0x1, b"fail").ok();
                                break;
                            },
                        };
                        // println!(
                        //     "{} -> {}: writting {},{:?}",
                        //     local_addr,
                        //     send_info.to,
                        //     write,
                        //     out
                        // );
    
    
                        if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                println!(
                                    "{} -> {}: send() would block",
                                    local_addr,
                                    send_info.to
                                );
                                break;
                            }
    
                            return Err(format!("{} -> {}: send() failed: {:?}",local_addr, send_info.to, e));
                        }
    
                        println!(
                            "{} -> {}: written {}",
                            local_addr,
                            send_info.to,
                            write
                        );
                    }
                }
            } 
            if conn.is_closed() {
                println!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
    
                if !conn.is_established() {
                    println!(
                        "connection timed out after {:?}",
                        app_data_start.elapsed(),
                    );
    
                    return Err("HandshakeFail".to_owned());
                }
    
                // if let Some(session_file) = &args.session_file {
                //     if let Some(session) = conn.session() {
                //         std::fs::write(session_file, session).ok();
                //     }
                // }
    
                // if let Some(h_conn) = http_conn {
                //     if h_conn.report_incomplete(&app_data_start) {
                //         return Err(ClientError::HttpFail);
                //     }
                // }
    
                break;
            }
            if finished {
                break;
            }
        }
    
        self.conn = Some(conn);
        Ok(())
    }
    
    pub fn handle_sending(&mut self) -> Result<(), String> {
        // // Generate outgoing QUIC packets and send them on the UDP socket, until
        // // quiche reports that there are no more packets to be sent.
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let mut sockets = vec![&self.socket];
        // sockets.push(&self.migrate_socket);
        let mut flag = 0;
        let mut conn = self.conn.as_mut().unwrap();

        for socket in sockets {
            let local_addr = socket.local_addr().unwrap();

            for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) = match conn.send_on_path(
                        &mut out,
                        Some(local_addr),
                        Some(peer_addr),
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            println!(
                                "{} -> {}: done writing",
                                local_addr,
                                peer_addr
                            );
                            break;
                        },

                        Err(e) => {
                            println!(
                                "{} -> {}: send failed: {:?}",
                                local_addr, peer_addr, e
                            );

                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };
                    // println!(
                    //     "{} -> {}: writting {},{:?}",
                    //     local_addr,
                    //     send_info.to,
                    //     write,
                    //     out
                    // );


                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!(
                                "{} -> {}: send() would block",
                                local_addr,
                                send_info.to
                            );
                            break;
                        }

                        return Err(format!("{} -> {}: send() failed: {:?}",local_addr, send_info.to, e));
                    }

                    println!(
                        "{} -> {}: written {}",
                        local_addr,
                        send_info.to,
                        write
                    );
                }
            }
        }
        Ok(())
    }

    pub fn handle_recving(&mut self) -> Result<(), String>{
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let mut buf = [0; 65535];

        // sockets.push(&self.migrate_socket);
        let mut conn = self.conn.as_mut().unwrap();

        for event in &self.events {
            let socket = match event.token() {
                mio::Token(0) => &self.socket,

                mio::Token(1) => &self.migrate_socket,

                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("{}: recv() would block", local_addr);
                            break 'read;
                        }

                        return Err(format!(
                            "{local_addr}: recv() failed: {e:?}"
                        ));
                    },
                };

                println!("{}: got {} bytes", local_addr, len);

                // if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                //     let path = format!("{target_path}/{pkt_count}.pkt");

                //     if let Ok(f) = std::fs::File::create(path) {
                //         let mut f = std::io::BufWriter::new(f);
                //         f.write_all(&buf[..len]).ok();
                //     }
                // }


                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        println!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    },
                };

                println!("{}: processed {} bytes", local_addr, read);
            }
        }

        println!("done reading");
        Ok(())
    }

    pub fn send_buf(&mut self,buf: &mut [u8], len: usize,) -> Result<usize,Error> {
        let conn = self.conn.as_mut().unwrap();
        let active_path = conn.paths.get_active()?;
        while let Err(e) = self.socket.send_to(&buf[..len], self.peer_addr) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                println!(
                    "{} -> {}: send() would block",
                    self.socket.local_addr().unwrap(),
                    self.peer_addr
                );
                continue;
            }
            break;
        }
        Ok(len)
        
    }

    pub fn send_pkt_to_server(
        &mut self, pkt_type: packet::Type, frames: &[frame::Frame],
        buf: &mut [u8],
    ) -> Result<usize,Error> {
        println!("sending frames: {:?}", frames);
        let conn = self.conn.as_mut().unwrap();
        match encode_pkt(conn, pkt_type, frames, buf)
        {
            Ok(written) => {
                println!("sending {} bytes to server: {:?}",written, &buf[..written]);
                self.send_buf( buf, written)
            },
            Err(e) => 
            {
                println!("Failed to encode pkt: {:?}", e);
                Err(e)
            }
        }
        //println!("sending pkt to server: {:?}", &buf[..written]);
        //recv_send(conn, buf, written)
    }



    pub fn judge_conn_status(&self) -> bool {
        match &self.conn {
            None => false,
            Some(conn) => {
                if conn.is_closed() || !conn.is_established() || conn.is_timed_out() {
                    return false;
                }
                return true;
            }
        }
    }

}

/// For experiment only, please use `STNyxExecutor` in production.
pub struct NetworkRestartExecutor<OT, S, SP>
where SP: ShMemProvider,
{
    start_command: String,
    judge_command: String,
    envs: Vec<(OsString, OsString)>,
    port: u16,
    timeout: Duration,
    observers: OT,
    phantom: std::marker::PhantomData<S>,
    map: Option<SP::ShMem>,
    map_size: Option<usize>,
    kill_signal: Option<Signal>,
    asan_obs: Option<Handle<AsanBacktraceObserver>>,
    crash_exitcode: Option<i8>,
    shmem_provider: SP,
    pid: i32,
    quic_st: Option<QuicStruct>,
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
                Err(e) => {return 0},
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
    S: State + HasExecutions,
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

        let mut out = [0; MAX_DATAGRAM_SIZE<<1];
        let mut exit_kind = ExitKind::Ok;
        *state.executions_mut() += 1;
        for (key, value) in &self.envs {
            std::env::set_var(key, value);
        }
        let res = self.judge_server_status();
        // 如果服务未启动，则启动服务
        if res == 0 || self.pid == 0 {
            std::process::Command::new("sh").arg("-c").arg(&self.start_command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
            let pid = self.judge_server_status();
            self.pid = pid;
            //self.quic_st.as_mut().unwrap().connect();
        }
        //quic_st 必须存在，检查 quic_st 合法性
        let mut valid_quic_st = false;
        if let Some(quic_st) = self.quic_st.as_ref() {
            valid_quic_st = quic_st.judge_conn_status();
        } 
        if valid_quic_st == false {
            self.rebuild_quic_struct();
        }
        
        let mut quic_st = self.quic_st.as_mut().unwrap();
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
        let binding = input.target_bytes();
        let mut inputs = binding.as_slice();
        // let frames = [
        //     frame::Frame::PathChallenge {
        //         data: [1, 2, 3, 4, 5, 6, 7, 8],
        //     },
        //     frame::Frame::Padding { len: (100) } ,
        // ];
        
        let pkt_type = packet::Type::Short;
        let mut b = octets::Octets::with_slice(inputs);
        match frame::Frame::from_bytes(& mut b, pkt_type){
            Ok(frame) => {
                let frames = [frame];
                println!("sending frame: {:?}", frames);
                //send forged packet
                quic_st.send_pkt_to_server(pkt_type, &frames, &mut out);
            },
            Err(e) => {
                eprintln!("Failed to forge packet: {:?}", e);
                //exit_kind = ExitKind::Crash;
            }
        
        }


        //send forged packet
        // quic_st.send_pkt_to_server(pkt_type, &frames, &mut out);
        
        //clear conn's sending buffer
        match quic_st.handle_sending(){
            Err(e) => {
                eprintln!("Failed to send data: {:?}", e);
                exit_kind = ExitKind::Crash;
            },
            Ok(_) => (),
        }

        //recv&handle conn's received packet 
        match quic_st.handle_recving(){
            Err(e) => {
                eprintln!("Failed to recv data: {:?}", e);
                exit_kind = ExitKind::Crash;
            },
            Ok(_) => (),
        }

        //let mut conn = quic_st.conn.as_mut().unwrap();



        let res = self.judge_server_status();
        if res == 0 {
            exit_kind = ExitKind::Crash;
        }

        Ok(exit_kind)
    }
}

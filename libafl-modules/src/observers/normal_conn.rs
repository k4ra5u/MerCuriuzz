use std::borrow::Cow;
use std::time::Duration;
use std::net::ToSocketAddrs;

use std::io::prelude::*;

use std::rc::Rc;

use std::cell::RefCell;


use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::{Error, Named,tuples::MatchName};
use log::{debug, error, info};
use ring::rand::*;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::misc::*;
use std::thread::sleep;

use super::HasRecordRemote;

const MAX_DATAGRAM_SIZE: usize = 1350;

pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct NormalConnObserver {
    pub name: Cow<'static, str>,
    pub record_remote: bool,
    pub ip: String,
    pub port: u16,
    pub server_name: String,
    pub pre_spend_time: Duration,
    pub post_spend_time: Duration,
    pub unable_to_connect: bool,
}

impl NormalConnObserver {
    /// Creates a new [`NormalConnObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str,ip:String,port:u16,server_name:String) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            ip: ip,
            port: port,
            server_name: server_name,
            pre_spend_time: Duration::new(5,0),
            post_spend_time: Duration::new(0,0),
            unable_to_connect: false,
        }
    }

    pub fn conn_and_calc_time(&mut self) -> Duration {
        // TODO: connect to server and calculate the time
        let start_time = std::time::Instant::now();
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
    
        // Setup the event loop.
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);
    
        // We'll only connect to the first server provided in URL list.
        let address = format!("{}:{}", self.ip, self.port);
        if address.is_empty() {
            panic!("Invalid server address");
        }
        let peer_addr = address.to_socket_addrs().unwrap().next().unwrap();

    
        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
    
    

        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let mut socket =
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

    
        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    

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
        config.set_max_idle_timeout(6000);
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
        config.grease(false);
        config.enable_early_data();
        config.enable_dgram(true, 1000, 1000);

        // let mut http_conn: Option<Box<dyn HttpConn>> = None;
    
        let mut app_proto_selected = false;
    
        // Generate a random source connection ID for the connection.
        let rng = SystemRandom::new();
    
        let scid = {
            let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
            rng.fill(&mut conn_id[..]).unwrap();
    
            conn_id.to_vec()
        }; 
    
        let scid = quiche::ConnectionId::from_ref(&scid);
    
        let local_addr = socket.local_addr().unwrap();
    
        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            Some(self.server_name.as_str()),
            &scid,
            local_addr,
            peer_addr,
            &mut config,
        )
        .unwrap();
    
        if let Some(keylog) = &mut keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }
    
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    
        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                println!(
                    "{} -> {}: send() would block",
                    socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }
    
            self.unable_to_connect = true;
            return Duration::new(0,0);
            // return Err(ClientError::Other(format!("send() failed: {e:?}")));
        }
    
        // println!("written {}", write);
    
        let app_data_start = std::time::Instant::now();
    
        let mut pkt_count = 0;
    
        let mut scid_sent = false;
        let mut new_path_probed = false;
        let mut migrated = false;
    
        loop {
            if !conn.is_in_early_data() || app_proto_selected {
                poll.poll(&mut events, conn.timeout()).unwrap();
            }
    
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                // println!("timed out");
    
                conn.on_timeout();
                break;
            }
    
            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            for event in &events {
                let socket = match event.token() {
                    mio::Token(0) => &socket,
        
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
                                // println!("{}: recv() would block", local_addr);
                                break 'read;
                            }
    
                            self.unable_to_connect = true;
                            return Duration::new(0,0);
                        },
                    };
    
    
                    pkt_count += 1;
    
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
    
                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,
    
                        Err(e) => {
                            error!("{}: recv failed: {:?}", local_addr, e);
                            continue 'read;
                        },
                    };
    
                    // println!("{}: processed {} bytes", local_addr, read);
                }
            }
    
            // println!("done reading");
    
            if conn.is_closed() {
                info!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
    
                if !conn.is_established() {
                    error!(
                        "connection timed out after {:?}",
                        app_data_start.elapsed(),
                    );
    
                    error!("Handshake failed");
                    self.unable_to_connect = true;
                    return Duration::new(0,0);
                    //return Err(ClientError::HandshakeFail);
                }
    
                break;
            }
    

            while let Some(qe) = conn.path_event_next() {
                match qe {
                    quiche::PathEvent::New(..) => unreachable!(),
    
                    quiche::PathEvent::Validated(local_addr, peer_addr) => {
                        info!(
                            "Path ({}, {}) is now validated",
                            local_addr, peer_addr
                        );
                        conn.migrate(local_addr, peer_addr).unwrap();
                        migrated = true;
                    },
    
                    quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                        info!(
                            "Path ({}, {}) failed validation",
                            local_addr, peer_addr
                        );
                    },
    
                    quiche::PathEvent::Closed(local_addr, peer_addr) => {
                        info!(
                            "Path ({}, {}) is now closed and unusable",
                            local_addr, peer_addr
                        );
                    },
    
                    quiche::PathEvent::ReusedSourceConnectionId(
                        cid_seq,
                        old,
                        new,
                    ) => {
                        info!(
                            "Peer reused cid seq {} (initially {:?}) on {:?}",
                            cid_seq, old, new
                        );
                    },
    
                    quiche::PathEvent::PeerMigrated(..) => unreachable!(),
                }
            }
    
            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = conn.retired_scid_next() {
                info!("Retiring source CID {:?}", retired_scid);
            }
    
            // Provides as many CIDs as possible.
            while conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
    
                if conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }
    
                scid_sent = true;
            }
    
    
            // Generate outgoing QUIC packets and send them on the UDP socket, until
            // quiche reports that there are no more packets to be sent.
            let local_addr = socket.local_addr().unwrap();
            debug!("{:?} -> {:?}", local_addr,peer_addr);
            for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) = match conn.send_on_path(
                        &mut out,
                        Some(local_addr),
                        Some(peer_addr),
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            // println!(
                            //     "{} -> {}: done writing",
                            //     local_addr,
                            //     peer_addr
                            // );
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{} -> {}: send failed: {:?}",
                                local_addr, peer_addr, e
                            );

                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // println!(
                            //     "{} -> {}: send() would block",
                            //     local_addr,
                            //     send_info.to
                            // );
                            break;
                        }

                        error!(
                            "{} -> {}: send() failed: {:?}",
                            local_addr, send_info.to, e
                        );
                        self.unable_to_connect = true;
                        return Duration::new(0,0);
                        // return Err(ClientError::Other(format!(
                        //     "{} -> {}: send() failed: {:?}",
                        //     local_addr, send_info.to, e
                        // )));
                    }

                    // println!(
                    //     "{} -> {}: written {}",
                    //     local_addr,
                    //     send_info.to,
                    //     write
                    // );
                }
            }
    
            if conn.is_closed() {
                info!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
    
                if !conn.is_established() {
                    error!(
                        "connection timed out after {:?}",
                        app_data_start.elapsed(),
                    );
    
                    error!("Handshake failed");
                    self.unable_to_connect = true;
                    return Duration::new(0,0);
                    //return Err(ClientError::HandshakeFail);
                }
    
                break;
            }
            break
        }
        let end_time = std::time::Instant::now();
        let spend_time = end_time - start_time;

        self.unable_to_connect = false;
        spend_time
    }

    pub fn calc_pre_spend_time(&mut self) {
        self.pre_spend_time = self.conn_and_calc_time();
    }
    pub fn calc_post_spend_time(&mut self) {
        self.post_spend_time = self.conn_and_calc_time();
    }

    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.calc_pre_spend_time();
            // self.pre_spend_time = Duration::new(5,0);
            self.post_spend_time = Duration::new(0,0);
            self.unable_to_connect = false;
        }

        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            self.calc_post_spend_time();
        }
        info!("{:?}",self);
        // info!("post_exec of NormalConnObserver: {:?}", self);
        Ok(())
    }



}

impl<S> Observer<S> for NormalConnObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.calc_pre_spend_time();
            // self.pre_spend_time = Duration::new(5,0);
            self.post_spend_time = Duration::new(0,0);
            self.unable_to_connect = false;
        }

        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            self.calc_post_spend_time();
        }
        info!("{:?}",self);
        // info!("post_exec of NormalConnObserver: {:?}", self);
        Ok(())
    }
}

impl Named for NormalConnObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

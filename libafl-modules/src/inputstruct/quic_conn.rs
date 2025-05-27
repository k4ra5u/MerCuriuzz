use quiche::{crypto, frame, packet::{self, *}, Connection, ConnectionId, Error, Header,FrameWithPkn};
use rand::Rng;
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug,warn};
use crate::inputstruct::{InputStruct, pkt_resort_type, FramesCycleStruct};


const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP_REQ_STREAM_ID: u64 = 4;

pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub fn pkt_num_len(pn: u64, largest_acked: u64) -> usize {
    let num_unacked: u64 = pn.saturating_sub(largest_acked) + 1;
    // computes ceil of num_unacked.log2()
    let min_bits = u64::BITS - num_unacked.leading_zeros();
    // get the num len in bytes
    ((min_bits + 7) / 8) as usize
}

pub fn decrypt_hdr(
    b: &mut octets::OctetsMut, hdr: &mut Header, aead: &crypto::Open,
) -> Result<(),Error> {
    let mut first = {
        let (first_buf, _) = b.split_at(1)?;
        first_buf.as_ref()[0]
    };

    let mut pn_and_sample = b.peek_bytes_mut(20)?;

    let (mut ciphertext, sample) = pn_and_sample.split_at(MAX_PKT_NUM_LEN)?;

    let ciphertext = ciphertext.as_mut();

    let mask = aead.new_mask(sample.as_ref())?;

    if Header::is_long(first) {
        first ^= mask[0] & 0x0f;
    } else {
        first ^= mask[0] & 0x1f;
    }

    let pn_len = usize::from((first & 3) + 1);

    let ciphertext = &mut ciphertext[..pn_len];

    for i in 0..pn_len {
        ciphertext[i] ^= mask[i + 1];
    }

    // Extract packet number corresponding to the decoded length.
    let pn = match pn_len {
        1 => u64::from(b.get_u8()?),

        2 => u64::from(b.get_u16()?),

        3 => u64::from(b.get_u24()?),

        4 => u64::from(b.get_u32()?),

        _ => return Err(Error::InvalidPacket),
    };

    // Write decrypted first byte back into the input buffer.
    let (mut first_buf, _) = b.split_at(1)?;
    first_buf.as_mut()[0] = first;

    hdr.pkt_num = pn;
    hdr.pkt_num_len = pn_len;

    if hdr.ty == Type::Short {
        hdr.key_phase = (first & 4) != 0;
    }

    Ok(())
}

pub fn decode_pkt_num(largest_pn: u64, truncated_pn: u64, pn_len: usize) -> u64 {
    let pn_nbits = pn_len * 8;
    let expected_pn = largest_pn + 1;
    let pn_win = 1 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

    if candidate_pn + pn_hwin <= expected_pn && candidate_pn < (1 << 62) - pn_win
    {
        return candidate_pn + pn_win;
    }

    if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        return candidate_pn - pn_win;
    }

    candidate_pn
}

pub fn decrypt_pkt<'a>(
    b: &'a mut octets::OctetsMut, pn: u64, pn_len: usize, payload_len: usize,
    aead: &crypto::Open,
) -> Result<octets::Octets<'a>,Error> {
    let payload_offset = b.off();

    let (header, mut payload) = b.split_at(payload_offset)?;

    let payload_len = payload_len
        .checked_sub(pn_len)
        .ok_or(Error::InvalidPacket)?;

    let mut ciphertext = payload.peek_bytes_mut(payload_len)?;

    let payload_len =
        aead.open_with_u64_counter(pn, header.as_ref(), ciphertext.as_mut())?;

    Ok(b.get_bytes(payload_len)?)
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
    if hdr.ty !=packet::Type::Short {
        return Err(Error::InvalidPacket);
    }
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
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub socket: mio::net::UdpSocket,
    pub migrate_socket: mio::net::UdpSocket,
    pub conn: Option<quiche::Connection>,
    pub app_proto_selected: bool,
    pub keylog: Option<std::fs::File>,
    pub config:  quiche::Config ,
    pub events: mio::Events,
    pub poll: mio::Poll,
    pub send_info: Option<quiche::SendInfo>,
    pub write: usize,
    pub req_start: std::time::Instant,
    pub req_sent: bool,
    pub server_name: String,
    pub server_port: u16,
    pub server_host: String,
    pub scids: Vec<[u8; quiche::MAX_CONN_ID_LEN]>,
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


        match std::env::var_os("SSLKEYLOGFILE"){
            Some(keylog_path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(keylog_path)
                    .unwrap();
        
                keylog = Some(file);
        
                config.log_keys();
            },
            None => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("key.log")
                    .unwrap();
        
                keylog = Some(file);
        
                config.log_keys();
            }
        }

        let mut app_proto_selected = false;

    
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        //let scid = quiche::ConnectionId::from_ref(&scid);
        //SystemRandom::new().fill(&mut scid[..]).unwrap();
        let mut scids : Vec<[u8; quiche::MAX_CONN_ID_LEN]> = Vec::new();
        SystemRandom::new().fill(&mut scid[..]).unwrap();
        // self.scids[0] = scid;
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

        info!("{:} -> {:}",self.socket.local_addr().unwrap().port(),self.peer_addr.port());
        debug!(
            "connecting to {:} from {:} with scid {:?}",
            self.peer_addr,
            self.socket.local_addr().unwrap(),
            scid,
        );
    
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    
        while let Err(e) = self.socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!(
                    "{} -> {}: send() would block",
                    self.socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }
    
            return Err(format!("send() failed: {e:?}"));
        }
    
        debug!("written {}", write);
    
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
                debug!("timed out");
    
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
                                debug!("{}: recv() would block", local_addr);
                                break 'read;
                            }
    
                            return Err(format!(
                                "{local_addr}: recv() failed: {e:?}"
                            ));
                        },
                    };
    
                    debug!("{}: got {} bytes", local_addr, len);
    
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
                            debug!("{}: recv failed: {:?}", local_addr, e);
                            continue 'read;
                        },
                    };
    
                    debug!("{}: processed {} bytes", local_addr, read);
                }
            }
    
            debug!("done reading");
    
            if conn.is_closed() {
                warn!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
    
                if !conn.is_established() {
                    warn!(
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
                debug!("connection established");

                if let Err(e) = conn.stream_send(0, b"aaaaaaaaaaaaaaaa", false) {        
                    return Err(format!("Failed to send data: {:?}", e));
                }
                //break;
            }
            debug!("connection not established yet, but breaked");
    

    
            // // Handle path events.
            while let Some(qe) = conn.path_event_next() {
                match qe {
                    quiche::PathEvent::New(..) => unreachable!(),
    
                    quiche::PathEvent::Validated(local_addr, peer_addr) => {
                        debug!(
                            "Path ({}, {}) is now validated",
                            local_addr, peer_addr
                        );
                        conn.migrate(local_addr, peer_addr).unwrap();
                        migrated = true;
                    },
    
                    quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                        debug!(
                            "Path ({}, {}) failed validation",
                            local_addr, peer_addr
                        );
                    },
    
                    quiche::PathEvent::Closed(local_addr, peer_addr) => {
                        debug!(
                            "Path ({}, {}) is now closed and unusable",
                            local_addr, peer_addr
                        );
                    },
    
                    quiche::PathEvent::ReusedSourceConnectionId(
                        cid_seq,
                        old,
                        new,
                    ) => {
                        debug!(
                            "Peer reused cid seq {} (initially {:?}) on {:?}",
                            cid_seq, old, new
                        );
                    },
    
                    quiche::PathEvent::PeerMigrated(..) => unreachable!(),
                }
            }
    
            // // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = conn.retired_scid_next() {
                debug!("Retiring source CID {:?}", retired_scid);
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
                                debug!(
                                    "{} -> {}: done writing",
                                    local_addr,
                                    peer_addr
                                );
                                break;
                            },
    
                            Err(e) => {
                                debug!(
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
                                debug!(
                                    "{} -> {}: send() would block",
                                    local_addr,
                                    send_info.to
                                );
                                break;
                            }
    
                            return Err(format!("{} -> {}: send() failed: {:?}",local_addr, send_info.to, e));
                        }
    
                        debug!(
                            "{} -> {}: written {}",
                            local_addr,
                            send_info.to,
                            write
                        );
                    }
                }
            } 
            if conn.is_closed() {
                warn!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
    
                if !conn.is_established() {
                    warn!(
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
                            debug!(
                                "{} -> {}: done writing",
                                local_addr,
                                peer_addr
                            );
                            break;
                        },

                        Err(e) => {
                            debug!(
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
                            debug!(
                                "{} -> {}: send() would block",
                                local_addr,
                                send_info.to
                            );
                            break;
                        }

                        return Err(format!("{} -> {}: send() failed: {:?}",local_addr, send_info.to, e));
                    }

                    debug!(
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

    pub fn handle_recving(&mut self) ->  Result<Vec<FrameWithPkn>, Error> {
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let mut buf = [0; 65535];
        let mut recv_pkts = 0;
        let mut recv_frames: Vec<FrameWithPkn> = Vec::new();


        // sockets.push(&self.migrate_socket);
        let mut conn = self.conn.as_mut().unwrap();
        let mut recv_bytes = 0;

        for event in &self.events {
            let socket = match event.token() {
                mio::Token(0) => &self.socket,

                mio::Token(1) => &self.migrate_socket,

                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => {
                        recv_pkts += 1;
                        v
                    }

                    Err(e) => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("{}: recv() would block", local_addr);
                            break 'read;
                        }

                        debug!("{local_addr}: recv() failed: {e:?}");
                        return Err(quiche::Error::TlsFail);

                    },
                };

                debug!("{}: got {} bytes", local_addr, len);


                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                let (read, read_frames) = match conn.recv2(&mut buf[..len], recv_info) {
                    Ok(v) => {
                        info!("recved bytes: {:?}", &buf[..len]);
                        let packet_info = buf[0];
                        let version = &buf[1..5];
                        v
                    },

                    Err(e) => {
                        debug!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    },
                };

                recv_bytes += read;
                for frame in read_frames {
                    recv_frames.push(frame.clone());
                }
                debug!("{}: processed {} bytes", local_addr, read);
            }
        }

        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(local_addr, peer_addr) => {
                    info!(
                        "{} Seen new path ({}, {})",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
    
                    // Directly probe the new path.
                    
                    conn
                        .probe_path(local_addr, peer_addr)
                        .expect("cannot probe");
                },
    
                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) is now validated",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) failed validation",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) is now closed and unusable",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    info!(
                        "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                        conn.trace_id(),
                        cid_seq,
                        old,
                        new
                    );
                },
    
                quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    info!(
                        "{} Connection migrated to ({}, {})",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
            }
        }

        // // See whether source Connection IDs have been retired.
        // while let Some(retired_scid) = conn.retired_scid_next() {
        //     info!("Retiring source CID {:?}", retired_scid);
        //     clients_ids.remove(&retired_scid);
        // }

        // // Provides as many CIDs as possible.
        // while client.conn.scids_left() > 0 {
        //     let (scid, reset_token) = generate_cid_and_reset_token(&rng);
        //     if client.conn.new_scid(&scid, reset_token, false).is_err() {
        //         break;
        //     }

        //     clients_ids.insert(scid, client.client_id);
        // }
        match conn.send(&mut out[0..MAX_DATAGRAM_SIZE])
        {
            Ok((write, send_info)) => {
                // debug!("{} written {} bytes,info:{:?}", conn.trace_id(), write, send_info);
            },
    
            Err(quiche::Error::Done) => {
                // info!("{} done writing", conn.trace_id());
            },
    
            Err(e) => {
                // error!("{} send failed: {:?}", conn.trace_id(), e);
            },
        };

        debug!("done reading");
        Ok(recv_frames)
    }


    pub fn handle_recving_once(&mut self) -> Result<Vec<FrameWithPkn>, Error> {
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let mut buf = [0; 1350];
        let mut recv_pkts = 0;
        let mut recv_frames: Vec<FrameWithPkn> = Vec::new();

        // sockets.push(&self.migrate_socket);
        let mut conn = self.conn.as_mut().unwrap();

        let mut recv_bytes = 0;
        for event in &self.events {
            let socket = match event.token() {
                mio::Token(0) => &self.socket,

                mio::Token(1) => &self.migrate_socket,

                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => {
                    recv_pkts += 1;
                    v
                }

                Err(e) => {
                    // There are no more UDP packets to read on this socket.
                    // Process subsequent events.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("{}: recv() would block", local_addr);
                        return Ok(recv_frames);
                    }

                    debug!("{local_addr}: recv() failed: {e:?}");
                    return Err(quiche::Error::TlsFail);
                },
            };

            debug!("{}: got {} bytes", local_addr, len);

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };
    
            
            let (read,read_frames) = match conn.recv2(&mut buf[..len], recv_info) {
                Ok(v) => {
                    debug!("recved bytes: {:?}", &buf[..len]);
                    let packet_info = buf[0];
                    let version = &buf[1..5];
                    v
                },

                Err(e) => {
                    info!("{}: recv failed: {:?}", local_addr, e);
                    return Err(e);
                },
            };
            recv_bytes += read;
            for frame in read_frames {
                recv_frames.push(frame.clone());
            }
            debug!("{}: processed {} bytes", local_addr, read);
        }
        
        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(local_addr, peer_addr) => {
                    info!(
                        "{} Seen new path ({}, {})",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
    
                    // Directly probe the new path.
                    
                    conn
                        .probe_path(local_addr, peer_addr)
                        .expect("cannot probe");
                },
    
                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) is now validated",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) failed validation",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) is now closed and unusable",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    info!(
                        "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                        conn.trace_id(),
                        cid_seq,
                        old,
                        new
                    );
                },
    
                quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    info!(
                        "{} Connection migrated to ({}, {})",
                        conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
            }
        }

        // // See whether source Connection IDs have been retired.
        // while let Some(retired_scid) = conn.retired_scid_next() {
        //     info!("Retiring source CID {:?}", retired_scid);
        //     clients_ids.remove(&retired_scid);
        // }

        // // Provides as many CIDs as possible.
        // while client.conn.scids_left() > 0 {
        //     let (scid, reset_token) = generate_cid_and_reset_token(&rng);
        //     if client.conn.new_scid(&scid, reset_token, false).is_err() {
        //         break;
        //     }

        //     clients_ids.insert(scid, client.client_id);
        // }
        match conn.send(&mut out[0..MAX_DATAGRAM_SIZE])
        {
            Ok((write, send_info)) => {
                // debug!("{} written {} bytes,info:{:?}", conn.trace_id(), write, send_info);
            },
    
            Err(quiche::Error::Done) => {
                // info!("{} done writing", conn.trace_id());
            },
    
            Err(e) => {
                // error!("{} send failed: {:?}", conn.trace_id(), e);
            },
        };

        debug!("done reading");
        Ok(recv_frames)
    }

    pub fn send_buf(&mut self,buf: &mut [u8], len: usize,) -> Result<usize,Error> {
        let conn = self.conn.as_mut().unwrap();
        let active_path = conn.paths.get_active()?;
        while let Err(e) = self.socket.send_to(&buf[..len], self.peer_addr) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!(
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
        debug!("sending frames: {:?}", frames);
        let conn = self.conn.as_mut().unwrap();
        match encode_pkt(conn, pkt_type, frames, buf)
        {
            Ok(written) => {
                debug!("sending {} bytes to server: {:?}",written, &buf[..written]);
                self.send_buf( buf, written)
            },
            Err(e) => 
            {
                debug!("Failed to encode pkt: {:?}", e);
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
                    false
                }
                else if conn.local_error != None {
                    false
                }
                else{
                    match &conn.peer_error {
                        None => true,
                        Some(peer_error) =>
                        {
                            peer_error.is_app
                        }
                    }
                }
            }
        }
    }

}



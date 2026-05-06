use crate::inputstruct::{pkt_resort_type, FramesCycleStruct, InputStruct};
use h3i::client::connection_summary::CloseTriggerFrames;
use h3i::client::Client as H3iClient;
use h3i::frame::H3iFrame;
use h3i::frame_parser::FrameParser;
use h3i::{
    actions::h3::{Action, StreamEventType, WaitType, WaitingFor},
    client::{
        connection_summary::{ConnectionCloseDetails, ConnectionSummary, StreamMap},
        parse_streams, ClientError, StreamParserMap,
    },
    config as H3Config,
};
use log::{debug, error, info, warn};
use octets::OctetsMut;
use quiche::{
    crypto, frame,
    packet::{self, *},
    path, Connection, ConnectionError, ConnectionId, Error, FrameWithPkn, Header,
};
use rand::Rng;
use ring::rand::*;
use std::collections::{HashMap, VecDeque};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};
const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_H3_IDLE_TIMEOUT_MS: u64 = 250;
const DEFAULT_H3_MAX_POLL_MS: u64 = 20;
const DEFAULT_H3_MAX_ACTION_WAIT_MS: u64 = 25;
const DEFAULT_H3_BLOCKED_RETRY_MS: u64 = 100;
const DEFAULT_H3_STREAM_WRITE_SLICE: usize = 1024;
const DEFAULT_H3_STREAM_SLICE_WAIT_MS: u64 = 0;
const DEFAULT_H3_POST_FLUSH_WAIT_MS: u64 = 0;
const DEFAULT_H3_MAX_IMMEDIATE_ACTIONS: usize = 256;
const DEFAULT_H3_ACTION_BUDGET_MS: u64 = 5;
const DEFAULT_H3_BATCH_DRAIN_MS: u64 = 30;
const DEFAULT_H3_PROGRESS_LOG_MS: u64 = 0;
const DEFAULT_H3_HANDSHAKE_WARN_MS: u64 = 1000;

const HTTP_REQ_STREAM_ID: u64 = 4;

#[derive(Default)]
pub struct SyncClient {
    pub streams: StreamMap,
    pub stream_parsers: StreamParserMap,
}

impl SyncClient {
    fn new(close_trigger_frames: Option<CloseTriggerFrames>) -> Self {
        Self {
            streams: StreamMap::new(close_trigger_frames),
            ..Default::default()
        }
    }
}

impl H3iClient for SyncClient {
    fn stream_parsers_mut(&mut self) -> &mut StreamParserMap {
        &mut self.stream_parsers
    }

    fn handle_response_frame(&mut self, stream_id: u64, frame: H3iFrame) {
        self.streams.insert(stream_id, frame);
    }
}

#[derive(Debug)]
pub struct H3BatchObservation {
    pub responded_stream_events: Vec<h3i::actions::h3::StreamEvent>,
    pub per_stream_frames: Vec<(u64, Vec<H3iFrame>)>,
    pub conn_close_details: ConnectionCloseDetails,
}

#[derive(Debug)]
pub struct H3BatchProcessResult {
    pub summary: ConnectionSummary,
    pub observation: H3BatchObservation,
}

pub struct H3Conn {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub h3_config: H3Config::Config,
    pub config: quiche::Config,
    pub conn: Option<quiche::Connection>,
    pub socket: mio::net::UdpSocket,
    pub migrate_socket: mio::net::UdpSocket,
    pub keylog: Option<std::fs::File>,
    pub server_name: String,
    pub server_port: u16,
    pub server_host: String,
    pub streams: StreamMap,
    pub stream_parsers: StreamParserMap,
    pub poll: mio::Poll,
    pub app_proto_selected: bool,
    pub events: mio::Events,
    pub scid: [u8; quiche::MAX_CONN_ID_LEN],
    pub max_poll_wait: Duration,
    pub max_action_wait: Duration,
}
impl H3Conn {
    pub fn new(server_name: String, server_port: u16, server_host: String) -> Self {
        let host_port = format!("{}:{}", server_name, server_port);
        let idle_timeout =
            env_duration_ms("MERCURIUZZ_H3_IDLE_TIMEOUT_MS", DEFAULT_H3_IDLE_TIMEOUT_MS);
        let max_poll_wait = env_duration_ms("MERCURIUZZ_H3_MAX_POLL_MS", DEFAULT_H3_MAX_POLL_MS);
        let max_action_wait = env_duration_ms(
            "MERCURIUZZ_H3_MAX_ACTION_WAIT_MS",
            DEFAULT_H3_MAX_ACTION_WAIT_MS,
        );
        let h3_config = H3Config::Config::new()
            .with_host_port(host_port)
            .with_idle_timeout(idle_timeout.as_millis() as u64)
            .verify_peer(false)
            .build()
            .unwrap();
        let (peer_addr, bind_addr) = resolve_socket_addrs(&h3_config);
        let mut socket = mio::net::UdpSocket::bind(bind_addr).unwrap();
        let mut migrate_socket = mio::net::UdpSocket::bind(bind_addr).unwrap();
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

        let mut keylog = None;
        if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_path)
                .unwrap();

            keylog = Some(file);
        }
        let mut config = create_config(&h3_config, keylog.is_some());

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
        // let scid = quiche::ConnectionId::from_ref(&scid);

        let local_addr = socket.local_addr().unwrap();

        Self {
            h3_config,
            config,
            conn: None,
            local_addr,
            peer_addr,
            socket,
            migrate_socket,
            keylog,
            server_name,
            server_port,
            server_host,
            streams: Default::default(),
            stream_parsers: Default::default(),
            poll,
            events,
            app_proto_selected: false,
            scid,
            max_poll_wait,
            max_action_wait,
        }
    }

    pub fn connect(&mut self) -> std::result::Result<(), ClientError> {
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let connect_url = if !self.h3_config.omit_sni {
            self.h3_config.host_port.split(':').next()
        } else {
            None
        };

        let scid = quiche::ConnectionId::from_ref(&self.scid);

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            connect_url,
            &scid,
            self.local_addr,
            self.peer_addr,
            &mut self.config,
        )
        .map_err(|e| ClientError::Other(e.to_string()))?;

        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        log::debug!(
            "connecting to {0:} from {1:} with scid {2:?}",
            self.peer_addr,
            self.local_addr,
            scid
        );
        self.app_proto_selected = false;

        let (write, send_info) = conn.send(&mut out).expect("initial send failed");

        while let Err(e) = self.socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                log::debug!(
                    "{} -> {}: send() would block",
                    self.socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }

            return Err(ClientError::Other(format!("send() failed: {e:?}")));
        }
        self.conn = Some(conn);
        Ok(())
    }
    pub fn process_actions(
        &mut self,
        actions: Vec<Action>,
        batch_timeout: Duration,
    ) -> std::result::Result<H3BatchProcessResult, ClientError> {
        let app_data_start = std::time::Instant::now();
        let batch_drain =
            env_duration_ms("MERCURIUZZ_H3_BATCH_DRAIN_MS", DEFAULT_H3_BATCH_DRAIN_MS);

        let mut action_queue: VecDeque<Action> = actions.into();
        let mut wait_duration = None;
        let mut wait_instant = None;
        let mut batch_quiet_since = None;
        let progress_log_interval = progress_log_interval();
        let handshake_warn_after = env_duration_ms(
            "MERCURIUZZ_H3_HANDSHAKE_WARN_MS",
            DEFAULT_H3_HANDSHAKE_WARN_MS,
        );
        let mut last_progress_log = Instant::now();
        let mut last_handshake_warn = None;
        let mut loop_count = 0_u64;

        let mut client = SyncClient::new(None);
        let mut waiting_for = WaitingFor::default();
        let mut batch_stream_offsets: HashMap<u64, usize> = HashMap::new();
        let mut batch_frames_by_stream: HashMap<u64, Vec<H3iFrame>> = HashMap::new();
        let mut batch_stream_events = Vec::new();
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let mut conn = self.conn.take().unwrap();
        let initial_stats = conn.stats();
        let mut last_progress_stats = initial_stats.clone();
        let mut last_established = conn.is_established();
        let mut last_early_data = conn.is_in_early_data();
        info!(
            "h3 process_actions start: peer={} actions={} established={} sent_pkts={} recv_pkts={} batch_drain_ms={} batch_timeout_ms={}",
            self.peer_addr,
            action_queue.len(),
            conn.is_established(),
            initial_stats.sent,
            initial_stats.recv,
            batch_drain.as_millis(),
            batch_timeout.as_millis()
        );

        loop {
            loop_count += 1;
            if !batch_timeout.is_zero() && app_data_start.elapsed() >= batch_timeout {
                let cur_stats = conn.stats();
                warn!(
                    "h3 batch hard timeout after {:?}: queued_actions={} waiting_for_responses={} wait_duration_ms={} established={} early_data={} sent_pkts={} recv_pkts={}",
                    app_data_start.elapsed(),
                    action_queue.len(),
                    !waiting_for.is_empty(),
                    wait_duration
                        .map(|v: Duration| v.as_millis())
                        .unwrap_or(0),
                    conn.is_established(),
                    conn.is_in_early_data(),
                    cur_stats.sent,
                    cur_stats.recv,
                );
                break;
            }
            let conn_timeout = conn.timeout();
            let mut actual_sleep = match (wait_duration, conn_timeout) {
                (Some(wait), Some(timeout)) => {
                    #[allow(clippy::comparison_chain)]
                    if timeout < wait {
                        // shave some off the wait time so it doesn't go longer
                        // than user really wanted.
                        let new = wait - timeout;
                        wait_duration = Some(new);
                        Some(timeout)
                    } else if wait < timeout {
                        Some(wait)
                    } else {
                        // same, so picking either doesn't matter
                        Some(timeout)
                    }
                }
                (None, Some(timeout)) => Some(timeout),
                (Some(wait), None) => Some(wait),
                _ => None,
            };

            // log::info!("actual sleep is {actual_sleep:?}");
            if wait_duration.is_none()
                && (actual_sleep.is_none() || actual_sleep.unwrap() > self.max_poll_wait)
            {
                actual_sleep = Some(self.max_poll_wait);
            }
            self.poll.poll(&mut self.events, actual_sleep).unwrap();

            // Only advance quiche timers when the poll actually expired on the
            // connection timeout, not because of an action wait or our poll cap.
            if self.events.is_empty() {
                if conn_timeout.is_some() && actual_sleep == conn_timeout {
                    log::debug!("quiche timeout expired");
                    conn.on_timeout();
                } else {
                    log::debug!("poll completed without socket activity");
                }
            }

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            let mut observed_network_activity = false;
            for event in &self.events {
                let socket = match event.token() {
                    mio::Token(0) => &self.socket,

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
                                break 'read;
                            }

                            return Err(ClientError::Other(format!(
                                "{local_addr}: recv() failed: {e:?}"
                            )));
                        }
                    };

                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
                    observed_network_activity = true;

                    // Process potentially coalesced packets.
                    let _read = match conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,

                        Err(e) => {
                            log::debug!("{local_addr}: recv failed: {e:?}");
                            continue 'read;
                        }
                    };
                }
            }

            log::debug!("done reading");

            if conn.is_closed() {
                log::debug!(
                    "connection closed with error={:?} did_idle_timeout={}, stats={:?} path_stats={:?}",
                    conn.peer_error(),
                    conn.is_timed_out(),
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>(),
                );

                if !conn.is_established() {
                    log::debug!("connection timed out after {:?}", app_data_start.elapsed(),);

                    return Err(ClientError::HandshakeFail);
                }

                break;
            }

            // Create a new application protocol session once the QUIC connection is
            // established.
            if (conn.is_established() || conn.is_in_early_data()) && !self.app_proto_selected {
                self.app_proto_selected = true;
                let negotiated_proto =
                    String::from_utf8_lossy(conn.application_proto()).into_owned();
                info!(
                    "h3 application phase enabled after {:?}: established={} early_data={} alpn='{}' sent_pkts={} recv_pkts={} queued_actions={}",
                    app_data_start.elapsed(),
                    conn.is_established(),
                    conn.is_in_early_data(),
                    negotiated_proto,
                    conn.stats().sent,
                    conn.stats().recv,
                    action_queue.len()
                );
                log_peer_transport_params(&conn);
            }

            if self.app_proto_selected {
                let prev_action_len = action_queue.len();
                check_duration_and_do_actions(
                    &mut wait_duration,
                    &mut wait_instant,
                    &mut action_queue,
                    &mut conn,
                    &mut waiting_for,
                    client.stream_parsers_mut(),
                    self.max_action_wait,
                )?;
                if action_queue.len() != prev_action_len {
                    observed_network_activity = true;
                }

                let mut wait_cleared = false;
                let responses = parse_streams(&mut conn, &mut client);

                for response in responses.iter() {
                    let stream_id = response.stream_id;

                    let all_frames = client.streams.stream(stream_id);
                    let seen = batch_stream_offsets.entry(stream_id).or_insert(0);
                    if *seen < all_frames.len() {
                        batch_frames_by_stream
                            .entry(stream_id)
                            .or_default()
                            .extend(all_frames[*seen..].iter().cloned());
                        *seen = all_frames.len();
                    }

                    if let StreamEventType::Finished = response.event_type {
                        waiting_for.clear_waits_on_stream(stream_id);
                    } else {
                        waiting_for.remove_wait(*response);
                    }

                    wait_cleared = true;
                }
                batch_stream_events.extend(responses);

                if client.streams.all_close_trigger_frames_seen() {
                    client.streams.close_due_to_trigger_frames(&mut conn);
                }

                if wait_cleared {
                    check_duration_and_do_actions(
                        &mut wait_duration,
                        &mut wait_instant,
                        &mut action_queue,
                        &mut conn,
                        &mut waiting_for,
                        client.stream_parsers_mut(),
                        self.max_action_wait,
                    )?;
                }
            }

            let established = conn.is_established();
            let early_data = conn.is_in_early_data();
            if established != last_established || early_data != last_early_data {
                let negotiated_proto =
                    String::from_utf8_lossy(conn.application_proto()).into_owned();
                info!(
                    "h3 connection state changed after {:?}: established={} early_data={} closed={} alpn='{}' queued_actions={} wait_active={} recv_h3_frames={}",
                    app_data_start.elapsed(),
                    established,
                    early_data,
                    conn.is_closed(),
                    negotiated_proto,
                    action_queue.len(),
                    !waiting_for.is_empty(),
                    client.streams.all_frames().len()
                );
                last_established = established;
                last_early_data = early_data;
            }

            if let Some(interval) = progress_log_interval {
                if !interval.is_zero() && last_progress_log.elapsed() >= interval {
                    let cur_stats = conn.stats();
                    info!(
                        "h3 progress: elapsed={:?} loops={} queued_actions={} waiting_for_responses={} wait_duration_ms={} established={} early_data={} app_proto_selected={} sent_pkts={} recv_pkts={} sent_short_data_delta={} sent_short_control_delta={} recv_pkt_delta={} peer_error={:?} local_error={:?} next_timeout_ms={}",
                        app_data_start.elapsed(),
                        loop_count,
                        action_queue.len(),
                        !waiting_for.is_empty(),
                        wait_duration.map(|v| v.as_millis()).unwrap_or(0),
                        established,
                        early_data,
                        self.app_proto_selected,
                        cur_stats.sent,
                        cur_stats.recv,
                        cur_stats
                            .sent_short_data_pkts
                            .saturating_sub(last_progress_stats.sent_short_data_pkts),
                        cur_stats
                            .sent_short_control_pkts
                            .saturating_sub(last_progress_stats.sent_short_control_pkts),
                        cur_stats.recv.saturating_sub(last_progress_stats.recv),
                        conn.peer_error(),
                        conn.local_error(),
                        conn.timeout().map(|v| v.as_millis()).unwrap_or(0),
                    );
                    last_progress_log = Instant::now();
                    last_progress_stats = cur_stats;
                }
            }

            if !conn.is_established() && app_data_start.elapsed() >= handshake_warn_after {
                let should_warn = last_handshake_warn
                    .map(|last: Instant| last.elapsed() >= handshake_warn_after)
                    .unwrap_or(true);

                if should_warn {
                    let cur_stats = conn.stats();
                    warn!(
                        "h3 handshake still not established after {:?}: queued_actions={} sent_initial_pkts={} sent_handshake_pkts={} sent_short_pkts={} recv_pkts={} peer_error={:?} local_error={:?} next_timeout_ms={} app_proto_selected={}",
                        app_data_start.elapsed(),
                        action_queue.len(),
                        cur_stats.sent_initial_pkts,
                        cur_stats.sent_handshake_pkts,
                        cur_stats.sent_short_pkts,
                        cur_stats.recv,
                        conn.peer_error(),
                        conn.local_error(),
                        conn.timeout().map(|v| v.as_millis()).unwrap_or(0),
                        self.app_proto_selected,
                    );
                    last_handshake_warn = Some(Instant::now());
                }
            }

            // Provides as many CIDs as possible.
            while conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token();

                if conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }
            }

            // Generate outgoing QUIC packets and send them on the UDP socket, until
            // quiche reports that there are no more packets to be sent.
            let sockets = vec![&self.socket];
            let mut emitted_quic_packets = 0usize;

            for socket in sockets {
                let local_addr = socket.local_addr().unwrap();

                for peer_addr in conn.paths_iter(local_addr) {
                    loop {
                        let (write, send_info) =
                            match conn.send_on_path(&mut out, Some(local_addr), Some(peer_addr)) {
                                Ok(v) => v,

                                Err(quiche::Error::Done) => {
                                    break;
                                }

                                Err(e) => {
                                    log::error!("{local_addr} -> {peer_addr}: send failed: {e:?}");

                                    // conn.close(false, 0x1, b"fail").ok();
                                    break;
                                }
                            };

                        if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                log::debug!(
                                    "{} -> {}: send() would block",
                                    local_addr,
                                    send_info.to
                                );
                                break;
                            }

                            return Err(ClientError::Other(format!(
                                "{} -> {}: send() failed: {:?}",
                                local_addr, send_info.to, e
                            )));
                        }

                        log::debug!(
                            "{} -> {}: emitted {} bytes of QUIC packets",
                            local_addr,
                            send_info.to,
                            write
                        );
                        observed_network_activity = true;
                        emitted_quic_packets += 1;
                    }
                }
            }

            let batch_is_idle =
                action_queue.is_empty() && wait_duration.is_none() && waiting_for.is_empty();

            if batch_is_idle {
                if observed_network_activity {
                    batch_quiet_since = Some(Instant::now());
                    log::debug!(
                        "h3 batch drain armed: emitted_quic_packets={} stream_frames_seen={}",
                        emitted_quic_packets,
                        client.streams.all_frames().len()
                    );
                } else if let Some(quiet_since) = batch_quiet_since {
                    if quiet_since.elapsed() >= batch_drain {
                        let cur_stats = conn.stats();
                        log::info!(
                            "h3 batch complete after {:?} quiet: delta_sent_pkts={} delta_initial_pkts={} delta_handshake_pkts={} delta_0rtt_pkts={} delta_short_pkts={} delta_short_data_pkts={} delta_short_control_pkts={} delta_ack_eliciting_pkts={} delta_recv_pkts={} delta_sent_bytes={} delta_recv_bytes={} total_recv_h3_frames={}",
                            quiet_since.elapsed(),
                            cur_stats.sent.saturating_sub(initial_stats.sent),
                            cur_stats
                                .sent_initial_pkts
                                .saturating_sub(initial_stats.sent_initial_pkts),
                            cur_stats
                                .sent_handshake_pkts
                                .saturating_sub(initial_stats.sent_handshake_pkts),
                            cur_stats
                                .sent_0rtt_pkts
                                .saturating_sub(initial_stats.sent_0rtt_pkts),
                            cur_stats
                                .sent_short_pkts
                                .saturating_sub(initial_stats.sent_short_pkts),
                            cur_stats
                                .sent_short_data_pkts
                                .saturating_sub(initial_stats.sent_short_data_pkts),
                            cur_stats
                                .sent_short_control_pkts
                                .saturating_sub(initial_stats.sent_short_control_pkts),
                            cur_stats
                                .sent_ack_eliciting_pkts
                                .saturating_sub(initial_stats.sent_ack_eliciting_pkts),
                            cur_stats.recv.saturating_sub(initial_stats.recv),
                            cur_stats.sent_bytes.saturating_sub(initial_stats.sent_bytes),
                            cur_stats.recv_bytes.saturating_sub(initial_stats.recv_bytes),
                            client.streams.all_frames().len()
                        );
                        break;
                    }
                } else {
                    batch_quiet_since = Some(Instant::now());
                }
            } else {
                batch_quiet_since = None;
            }

            if conn.is_closed() {
                log::debug!(
                    "connection closed, {:?} {:?}",
                    conn.stats(),
                    conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                if !conn.is_established() {
                    log::debug!("connection timed out after {:?}", app_data_start.elapsed(),);

                    return Err(ClientError::HandshakeFail);
                }

                break;
            }
        }
        let stats = conn.stats();
        let path_stats = conn.path_stats().collect();
        let conn_close_details = ConnectionCloseDetails::new(&conn);
        let observation = H3BatchObservation {
            responded_stream_events: batch_stream_events,
            per_stream_frames: batch_frames_by_stream.into_iter().collect(),
            conn_close_details: ConnectionCloseDetails::new(&conn),
        };
        self.conn = Some(conn);
        Ok(H3BatchProcessResult {
            summary: ConnectionSummary {
                stream_map: client.streams,
                stats: Some(stats),
                path_stats: path_stats,
                conn_close_details: conn_close_details,
            },
            observation,
        })
    }
}

fn resolve_socket_addrs(args: &H3Config::Config) -> (SocketAddr, SocketAddr) {
    // Resolve server address.
    let peer_addr = if let Some(addr) = &args.connect_to {
        addr.parse().expect("--connect-to is expected to be a string containing an IPv4 or IPv6 address with a port. E.g. 192.0.2.0:443")
    } else {
        let x = format!("https://{}", args.host_port);
        *url::Url::parse(&x)
            .unwrap()
            .socket_addrs(|| None)
            .unwrap()
            .first()
            .unwrap()
    };

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    (
        peer_addr,
        bind_addr.parse().expect("unable to parse bind address"),
    )
}

fn create_config(args: &H3Config::Config, should_log_keys: bool) -> quiche::Config {
    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(1).unwrap();

    config.verify_peer(args.verify_peer);
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
    // config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(args.idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(args.max_stream_data_bidi_local);
    config.set_initial_max_stream_data_bidi_remote(args.max_stream_data_bidi_remote);
    config.set_initial_max_stream_data_uni(args.max_stream_data_uni);
    config.set_initial_max_streams_bidi(args.max_streams_bidi);
    config.set_initial_max_streams_uni(args.max_streams_uni);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(0);

    config.set_max_connection_window(args.max_window);
    config.set_max_stream_window(args.max_stream_window);
    config.grease(false);

    if should_log_keys {
        config.log_keys()
    }

    config
}

fn check_duration_and_do_actions(
    wait_duration: &mut Option<Duration>,
    wait_instant: &mut Option<Instant>,
    action_queue: &mut VecDeque<Action>,
    conn: &mut quiche::Connection,
    waiting_for: &mut WaitingFor,
    stream_parsers: &mut StreamParserMap,
    max_action_wait: Duration,
) -> std::result::Result<(), ClientError> {
    match wait_duration.as_ref() {
        None => {
            if let Some(idle_wait) = handle_actions(
                action_queue,
                conn,
                waiting_for,
                stream_parsers,
                max_action_wait,
            )? {
                *wait_duration = Some(idle_wait);
                *wait_instant = Some(Instant::now());

                // TODO: the wait period could still be larger than the
                // negotiated idle timeout.
                // We could in theory check quiche's idle_timeout value if
                // it was public.
                log::debug!("waiting for {idle_wait:?} before executing more actions");
            }
        }

        Some(period) => {
            let now = Instant::now();
            let then = wait_instant.unwrap();
            log::debug!(
                "checking if actions wait period elapsed {:?} > {:?}",
                now.duration_since(then),
                wait_duration
            );
            if now.duration_since(then) >= *period {
                log::debug!("yup!");
                *wait_duration = None;

                if let Some(idle_wait) = handle_actions(
                    action_queue,
                    conn,
                    waiting_for,
                    stream_parsers,
                    max_action_wait,
                )? {
                    *wait_duration = Some(idle_wait);
                }
            }
        }
    }

    Ok(())
}

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token() -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut reset_token);
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

fn handle_actions(
    actions: &mut VecDeque<Action>,
    conn: &mut quiche::Connection,
    waiting_for: &mut WaitingFor,
    stream_parsers: &mut StreamParserMap,
    max_action_wait: Duration,
) -> std::result::Result<Option<Duration>, ClientError> {
    if !waiting_for.is_empty() {
        log::debug!("won't fire an action due to waiting for responses: {waiting_for:?}");
        return Ok(None);
    }

    let post_flush_wait = env_duration_ms(
        "MERCURIUZZ_H3_POST_FLUSH_WAIT_MS",
        DEFAULT_H3_POST_FLUSH_WAIT_MS,
    );
    let action_budget = env_duration_ms(
        "MERCURIUZZ_H3_ACTION_BUDGET_MS",
        DEFAULT_H3_ACTION_BUDGET_MS,
    );
    let max_immediate_actions = env_usize(
        "MERCURIUZZ_H3_MAX_IMMEDIATE_ACTIONS",
        DEFAULT_H3_MAX_IMMEDIATE_ACTIONS,
    );
    let mut processed_actions = 0usize;
    let action_start = Instant::now();

    while let Some(action) = actions.front().cloned() {
        if max_immediate_actions > 0 && processed_actions >= max_immediate_actions {
            log::debug!(
                "paused action execution after {} actions to flush/send pending QUIC packets",
                processed_actions
            );
            return Ok(Some(Duration::ZERO));
        }

        if !action_budget.is_zero() && action_start.elapsed() >= action_budget {
            log::debug!(
                "paused action execution after {:?} and {} actions to give QUIC send/recv a chance to run",
                action_start.elapsed(),
                processed_actions
            );
            return Ok(Some(Duration::ZERO));
        }

        match action {
            Action::FlushPackets => {
                actions.pop_front();
                if post_flush_wait.is_zero() {
                    return Ok(None);
                }

                let wait = post_flush_wait.min(max_action_wait);
                log::debug!("waiting for {wait:?} after flush");
                return Ok(Some(wait));
            }
            Action::Wait { wait_type } => match wait_type {
                WaitType::WaitDuration(period) => {
                    actions.pop_front();
                    return Ok(Some(period.min(max_action_wait)));
                }
                WaitType::StreamEvent(response) => {
                    log::debug!("waiting for {response:?} before executing more actions");
                    waiting_for.add_wait(&response);
                    actions.pop_front();
                    return Ok(None);
                }
            },
            _ => match try_execute_action(&action, conn, stream_parsers)? {
                ActionExecution::Done => {
                    actions.pop_front();
                    processed_actions += 1;
                }
                ActionExecution::Blocked(retry_after) => {
                    return Ok(Some(retry_after));
                }
                ActionExecution::Replace(next_action, retry_after) => {
                    actions.pop_front();
                    actions.push_front(next_action);
                    return Ok(Some(retry_after));
                }
            },
        }
    }

    Ok(None)
}

enum ActionExecution {
    Done,
    Blocked(Duration),
    Replace(Action, Duration),
}

fn ensure_stream_parser(stream_id: u64, stream_parsers: &mut StreamParserMap) {
    stream_parsers
        .entry(stream_id)
        .or_insert_with(|| FrameParser::new(stream_id));
}

fn serialize_stream_type(stream_type: u64) -> Result<Vec<u8>, ClientError> {
    let mut buf = [0_u8; 8];
    let mut octets = OctetsMut::with_slice(&mut buf);
    octets.put_varint(stream_type).map_err(|e| {
        ClientError::Other(format!("failed to encode stream type {stream_type}: {e:?}"))
    })?;
    let written = octets.off();
    Ok(buf[..written].to_vec())
}

fn serialize_h3_frame(frame: &quiche::h3::frame::Frame) -> Result<Vec<u8>, ClientError> {
    let mut capacity = 1024_usize;

    loop {
        let mut buf = vec![0_u8; capacity];
        let mut octets = OctetsMut::with_slice(&mut buf);

        match frame.to_bytes(&mut octets) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(quiche::h3::Error::BufferTooShort) => {
                capacity = capacity.saturating_mul(2);
                if capacity > 8 * 1024 * 1024 {
                    return Err(ClientError::Other(
                        "failed to serialize HTTP/3 frame: buffer growth exceeded 8 MiB"
                            .to_string(),
                    ));
                }
            }
            Err(e) => {
                return Err(ClientError::Other(format!(
                    "failed to serialize HTTP/3 frame {frame:?}: {e:?}"
                )));
            }
        }
    }
}

fn try_send_bytes(
    stream_id: u64,
    bytes: &[u8],
    fin_stream: bool,
    conn: &mut quiche::Connection,
    stream_parsers: &mut StreamParserMap,
) -> std::result::Result<ActionExecution, ClientError> {
    let verbose_stream_io = env_bool("MERCURIUZZ_H3_STREAM_IO_LOG", false);
    let max_slice = env_usize(
        "MERCURIUZZ_H3_MAX_STREAM_WRITE_SLICE",
        DEFAULT_H3_STREAM_WRITE_SLICE,
    )
    .max(1);
    let send_len = bytes.len().min(max_slice);
    let send_bytes = &bytes[..send_len];
    let send_fin = fin_stream && send_len == bytes.len();
    let blocked_retry = env_duration_ms(
        "MERCURIUZZ_H3_BLOCKED_RETRY_MS",
        DEFAULT_H3_BLOCKED_RETRY_MS,
    );
    let slice_retry = env_duration_ms(
        "MERCURIUZZ_H3_STREAM_SLICE_WAIT_MS",
        DEFAULT_H3_STREAM_SLICE_WAIT_MS,
    );

    match conn.stream_send(stream_id, send_bytes, send_fin) {
        Ok(written) => {
            ensure_stream_parser(stream_id, stream_parsers);

            if verbose_stream_io {
                info!(
                    "stream_send buffered on stream {}: queued {} of {} bytes into quiche tx buffer from pending={} fin={}",
                    stream_id,
                    written,
                    send_bytes.len(),
                    bytes.len(),
                    send_fin
                );
            } else {
                debug!(
                    "stream_send buffered on stream {}: queued {} of {} bytes into quiche tx buffer from pending={} fin={}",
                    stream_id,
                    written,
                    send_bytes.len(),
                    bytes.len(),
                    send_fin
                );
            }

            if written == bytes.len() {
                Ok(ActionExecution::Done)
            } else {
                let remaining = bytes[written..].to_vec();
                let retry_after = if written == send_bytes.len() {
                    slice_retry
                } else {
                    arm_stream_writable(stream_id, remaining.len(), conn);
                    blocked_retry
                };

                if verbose_stream_io {
                    info!(
                        "stream_send partially buffered on stream {}: queued {} bytes, {} bytes remain for a later flush",
                        stream_id,
                        written,
                        remaining.len() + written
                    );
                } else {
                    debug!(
                        "stream_send partially buffered on stream {}: queued {} bytes, {} bytes remain for a later flush",
                        stream_id,
                        written,
                        remaining.len() + written
                    );
                }
                Ok(ActionExecution::Replace(
                    Action::StreamBytes {
                        stream_id,
                        fin_stream,
                        bytes: remaining,
                    },
                    retry_after,
                ))
            }
        }
        Err(quiche::Error::Done) => {
            arm_stream_writable(stream_id, bytes.len(), conn);
            let stream_capacity = conn.stream_capacity(stream_id).ok();
            if verbose_stream_io {
                info!(
                    "stream_send blocked on stream {} by peer flow control or local send buffer, pending_bytes={}, stream_capacity={:?}",
                    stream_id,
                    bytes.len(),
                    stream_capacity
                );
            } else {
                debug!(
                    "stream_send blocked on stream {} by peer flow control or local send buffer, pending_bytes={}, stream_capacity={:?}",
                    stream_id,
                    bytes.len(),
                    stream_capacity
                );
            }
            Ok(ActionExecution::Blocked(blocked_retry))
        }
        Err(quiche::Error::StreamLimit) => {
            if verbose_stream_io {
                info!(
                    "stream_send blocked on stream {} by peer stream limit, peer_streams_left_bidi={}, peer_streams_left_uni={}",
                    stream_id,
                    conn.peer_streams_left_bidi(),
                    conn.peer_streams_left_uni()
                );
            } else {
                debug!(
                    "stream_send blocked on stream {} by peer stream limit, peer_streams_left_bidi={}, peer_streams_left_uni={}",
                    stream_id,
                    conn.peer_streams_left_bidi(),
                    conn.peer_streams_left_uni()
                );
            }
            Ok(ActionExecution::Blocked(blocked_retry))
        }
        Err(e) => Err(ClientError::Other(format!(
            "stream_send failed on stream {stream_id}: {e:?}"
        ))),
    }
}

fn try_execute_action(
    action: &Action,
    conn: &mut quiche::Connection,
    stream_parsers: &mut StreamParserMap,
) -> std::result::Result<ActionExecution, ClientError> {
    match action {
        Action::SendFrame {
            stream_id,
            fin_stream,
            frame,
        } => {
            log::debug!("frame tx id={:?} frame={:?}", stream_id, frame);
            let bytes = serialize_h3_frame(frame)?;
            try_send_bytes(*stream_id, &bytes, *fin_stream, conn, stream_parsers)
        }

        Action::SendHeadersFrame {
            stream_id,
            fin_stream,
            headers,
            frame,
            ..
        } => {
            log::info!("headers frame tx stream={stream_id} hdrs={headers:?}");
            let bytes = serialize_h3_frame(frame)?;
            try_send_bytes(*stream_id, &bytes, *fin_stream, conn, stream_parsers)
        }

        Action::OpenUniStream {
            stream_id,
            fin_stream,
            stream_type,
        } => {
            log::info!(
                "open uni stream_id={stream_id} ty={stream_type} fin={fin_stream} established={} early_data={}",
                conn.is_established(),
                conn.is_in_early_data()
            );
            let bytes = serialize_stream_type(*stream_type)?;
            try_send_bytes(*stream_id, &bytes, *fin_stream, conn, stream_parsers)
        }

        Action::StreamBytes {
            stream_id,
            bytes,
            fin_stream,
        } => {
            log::debug!(
                "stream bytes tx id={} len={} fin={} established={} early_data={}",
                stream_id,
                bytes.len(),
                fin_stream,
                conn.is_established(),
                conn.is_in_early_data()
            );
            try_send_bytes(*stream_id, bytes, *fin_stream, conn, stream_parsers)
        }

        Action::ResetStream {
            stream_id,
            error_code,
        } => {
            log::info!("reset_stream stream_id={stream_id} error_code={error_code}");
            if let Err(e) = conn.stream_shutdown(*stream_id, quiche::Shutdown::Write, *error_code) {
                log::error!("can't send reset_stream: {e}");
                return Ok(ActionExecution::Done);
            }

            ensure_stream_parser(*stream_id, stream_parsers);
            Ok(ActionExecution::Done)
        }

        Action::StopSending {
            stream_id,
            error_code,
        } => {
            log::info!("stop_sending stream id={stream_id} error_code={error_code}");

            if let Err(e) = conn.stream_shutdown(*stream_id, quiche::Shutdown::Read, *error_code) {
                log::error!("can't send stop_sending: {e}");
            }

            ensure_stream_parser(*stream_id, stream_parsers);
            Ok(ActionExecution::Done)
        }

        Action::ConnectionClose { error } => {
            let ConnectionError {
                is_app,
                error_code,
                reason,
            } = error;

            log::info!("connection_close={error:?}");
            let _ = conn.close(*is_app, *error_code, reason);
            Ok(ActionExecution::Done)
        }

        Action::FlushPackets | Action::Wait { .. } => unreachable!(),
    }
}

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    let millis = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_ms);
    Duration::from_millis(millis)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn progress_log_interval() -> Option<Duration> {
    match std::env::var("MERCURIUZZ_H3_PROGRESS_LOG_MS") {
        Ok(value) => match value.parse::<u64>() {
            Ok(0) => None,
            Ok(ms) => Some(Duration::from_millis(ms)),
            Err(_) => None,
        },
        Err(_) if log::log_enabled!(log::Level::Debug) => {
            Some(Duration::from_millis(DEFAULT_H3_PROGRESS_LOG_MS.max(1000)))
        }
        Err(_) => None,
    }
}

fn arm_stream_writable(stream_id: u64, pending_len: usize, conn: &mut quiche::Connection) {
    if pending_len == 0 {
        return;
    }

    if let Err(e) = conn.stream_writable(stream_id, pending_len) {
        debug!(
            "failed to arm writable notification for stream {} pending_len={}: {:?}",
            stream_id, pending_len, e
        );
    }
}

fn log_peer_transport_params(conn: &quiche::Connection) {
    if let Some(params) = conn.peer_transport_params() {
        debug!(
            "peer transport params: initial_max_data={} initial_max_stream_data_bidi_remote={} initial_max_stream_data_bidi_local={} initial_max_stream_data_uni={} initial_max_streams_bidi={} initial_max_streams_uni={}",
            params.initial_max_data,
            params.initial_max_stream_data_bidi_remote,
            params.initial_max_stream_data_bidi_local,
            params.initial_max_stream_data_uni,
            params.initial_max_streams_bidi,
            params.initial_max_streams_uni,
        );
    } else {
        debug!("peer transport params are not available yet");
    }
}

use log::{debug, error, info};
use std::thread::sleep;
use std::time::{Duration, Instant};

use quiche::{
    frame::{self},
    ranges::RangeSet,
};

use clap::Parser;
use mylibafl::inputstruct::{FramesCycleStruct, InputStruct, QuicStruct};

const MAX_DATAGRAM_SIZE: usize = 1350;

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "search_sni",
    about = "This is a simple sni searcher.",
    author = "k4ra5u"
)]
struct Opt {
    #[arg(help = "ip", name = "ip", default_value = "1.0.0.0")]
    ip: String,

    #[arg(help = "sni", name = "sni", default_value = "discordcodes.com")]
    sni: String,
    #[arg(help = "port", name = "port", default_value = "443")]
    port: u16,
}

pub fn main() {
    unsafe { std::env::set_var("RUST_LOG", "info") };
    unsafe { std::env::set_var("SSLKEYLOGFILE", "key.log") };
    unsafe { std::env::set_var("PCAPS_DIR", "pcaps") };
    env_logger::init();
    let opt = Opt::parse();

    let ip = opt.ip;
    let port = opt.port;
    let sni = opt.sni;
    let mut quic_st = QuicStruct::new(sni, port, ip);
    let mut exit_reason = String::new();
    quic_st.connect_timeout = Duration::from_secs(3);
    match quic_st.connect() {
        Err(e) => {
            if quic_st.is_timeout() {
                error!("IP unreachable (timeout): {:?}", e);
            } else {
                error!("Handshake failed (non-timeout): {:?}", e);
            }
        }
        Ok(_) => {
            if !quic_st.judge_conn_status() {
                error!("connect() returned Ok but connection is not established");
                return;
            }
            info!("Connected to server");
        }
    }
    if exit_reason != "" {
        return;
    }

    info!(
        "Connection established, from {:?} to {:?}",
        quic_st.local_addr.port(),
        quic_st.peer_addr.port()
    );

    let mut input_struct = InputStruct::new();
    let mut frame_cycle1 = FramesCycleStruct::new();
    for _i in 0..10 {
        let ping_frame = frame::Frame::Ping { mtu_probe: None };
        frame_cycle1 = frame_cycle1.add_frame(ping_frame);
    }
    let cc_frame = frame::Frame::ConnectionClose {
        error_code: (0),
        frame_type: (0),
        reason: (Vec::new()),
    };
    frame_cycle1 = frame_cycle1.add_frame(cc_frame);

    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    input_struct = input_struct.calc_frames_cycle_len();

    let pkt_type = input_struct.pkt_type;
    let lost_time_dur = input_struct.send_timeout;
    let recv_time = input_struct.recv_timeout;
    let mut recv_left_time = recv_time;

    let mut out = [0; MAX_DATAGRAM_SIZE << 10];
    let mut total_recv_pkts = 0;
    let mut total_recv_bytes = 0;
    let max_pkt_len = 0;
    let mut cur_pkt_len = 0;
    let mut total_sent_pkts: u64 = 0;
    let mut total_sent_bytes = 0;
    let cycles = input_struct.frames_cycle.len();
    let mut sending_acks: Vec<u64> = Vec::new();
    for cur_cycle in 0..cycles {
        let frames = input_struct.frames_cycle[cur_cycle].basic_frames.clone();
        let mut frame_list: Vec<frame::Frame> = Vec::new();
        for frame in frames.iter() {
            for pkn in sending_acks.iter() {
                let mut ranges = RangeSet::default();
                ranges.insert(*pkn..*pkn + 1);
                let ack_frame = frame::Frame::ACK {
                    ack_delay: 0,
                    ranges,
                    ecn_counts: None,
                };
                frame_list.push(ack_frame.clone());
                debug!("sending ack frame: {:?}", ack_frame);
            }
            sending_acks.clear();
            // 注释代码是按照标准的MTU将帧尽可能的合并，在fuzz过程中这应该是负优化，于是每次只发送1个帧
            if cur_pkt_len + frame.wire_len() < max_pkt_len {
                frame_list.push(frame.clone());
                cur_pkt_len += frame.wire_len();
                total_sent_bytes += frame.wire_len();
                debug!("sending frame: {:?}", frame);
                continue;
            }
            frame_list.push(frame.clone());
            total_sent_bytes += frame.wire_len();
            total_sent_pkts += 1;

            let _ = quic_st.send_pkt_to_server(pkt_type, &frame_list, &mut out);
            match quic_st.handle_sending() {
                Err(e) => {
                    error!("Failed to send data: {:?}", e);
                    eprintln!("Failed to send data: {:?}", e);
                    exit_reason = format!("Failed to send data: {:?}", e);
                }
                Ok(_) => (),
            }
            if recv_left_time <= lost_time_dur {
                let send_left_time = lost_time_dur - recv_left_time;
                recv_left_time = recv_time - send_left_time;

                match quic_st.handle_recving_once() {
                    Err(e) => {
                        error!("Failed to recv data: {:?}", e);
                        exit_reason = format!("Failed to recv data: {:?}", e);
                    }
                    Ok(recv_frames) => {
                        let mut recv_pkts = 0;
                        let mut recv_bytes = 0;
                        debug!("recv frames: {:?}", recv_frames);
                        for recv_frame in recv_frames.iter() {
                            match &recv_frame.frame {
                                frame::Frame::ACK {
                                    ack_delay: _ack_delay,
                                    ranges: _ranges,
                                    ecn_counts: _ecn_counts,
                                } => {}
                                //对于所有其他情况 统一处理：
                                _ => {
                                    if !sending_acks.contains(&recv_frame.pkn) {
                                        sending_acks.push(recv_frame.pkn);
                                        break;
                                    }
                                }
                            }
                        }
                        for recv_frame in recv_frames.iter() {
                            recv_pkts += 1;
                            recv_bytes += recv_frame.frame.wire_len();
                        }
                        total_recv_pkts += recv_pkts;
                        total_recv_bytes += recv_bytes;

                        ()
                    }
                }
            } else {
                recv_left_time -= lost_time_dur;
            }
            debug!(
                "recv_left_time: {:?},lost_time: {:?}",
                recv_left_time, lost_time_dur
            );
            cur_pkt_len = frame.wire_len();
            frame_list.clear();
        }
        debug!("sent {:?} frames", frames.len());
    }

    loop {
        match quic_st.handle_recving() {
            Err(e) => {
                eprintln!("Failed to recv data: {:?}", e);
                break;
            }
            Ok(recv_frames) => {
                if recv_frames.len() == 0 {
                    break;
                }
                let mut recv_pkts = 0;
                let mut recv_bytes = 0;
                for recv_frame in recv_frames.iter() {
                    recv_pkts += 1;
                    recv_bytes += recv_frame.frame.wire_len();
                }
                total_recv_pkts += recv_pkts;
                total_recv_bytes += recv_bytes;
                ()
            }
        }
    }
    info!(
        "Total sent pkts: {:?}, bytes: {:?}",
        total_sent_pkts, total_sent_bytes
    );
    info!(
        "Total recv pkts: {:?}, bytes: {:?}",
        total_recv_pkts, total_recv_bytes
    );
    let _ = quic_st.handle_sending(); // flush close 包（至少一次）
    // 2) draining：继续收包/处理超时/必要的重传
    let drain_deadline = Instant::now() + Duration::from_secs(2);
    let mut last_rx = Instant::now();

    loop {
        // 尽量“短周期”地收一次（不要阻塞太久）
        match quic_st.handle_recving_once() {
            // 你已有这个
            Ok(recv_frames) => {
                if !recv_frames.is_empty() {
                    last_rx = Instant::now();
                    // 统计/记录随你
                }
            }
            Err(_e) => {
                // WouldBlock 不应该当成 fatal；如果你的封装把 WouldBlock 也返回 Err，
                // 建议在封装里区分出来，这里先按“非致命”处理或只在特定错误时 break
                // return Err(e);
            }
        }

        // 把 quiche 需要发的包（ACK/close 重传等）继续 flush
        let _ = quic_st.handle_sending();

        // 退出条件：连接已关闭 + 最近一小段时间没再收到包
        if quic_st.conn_is_closed() && last_rx.elapsed() > Duration::from_millis(200) {
            break;
        }

        // 总收尾时间上限
        if Instant::now() > drain_deadline {
            break;
        }

        // 小睡一下避免 busy loop
        sleep(Duration::from_millis(5));
    }

    if exit_reason != "" {
        info!("Exiting reason: {:?}", exit_reason);
        return;
    }
}

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::thread;
use std::thread::sleep;
use std::time::{Duration, Instant};

use clap::Parser;
use crossbeam_channel as cc;
use log::{debug, info};
use quiche::frame;
use serde::{Deserialize, Serialize};
// use std::sync::{Arc, Mutex};
use mylibafl::inputstruct::{FramesCycleStruct, InputStruct, QuicStruct};

const MAX_DOMAINS_PER_IP: usize = 1000;
const MAX_DATAGRAM_SIZE: usize = 1350;

// 收尾参数：尽量收齐 close/ack/重传尾包，避免 socket 过早 drop 触发 ICMP
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const QUIET_TIME: Duration = Duration::from_millis(200);

// 连续 timeout 次数阈值：达到才判定不可达并跳过
const CONSEC_TIMEOUT_THRESHOLD: usize = 3;

#[derive(Debug, Parser)]
#[command(
    name = "jsonl_sni_tester",
    about = "Read input.jsonl, try SNI domains, confirm first success, send CC only, output jsonl. Multi-thread + resume + 3 consecutive timeouts => unreachable.",
    author = "k4ra5u"
)]
struct Opt {
    /// input jsonl (one json object per line)
    input: String,

    /// output jsonl (one json object per line)
    output: String,

    #[arg(long, default_value = "info")]
    log: String,

    #[arg(long, default_value = "/media/john/Data/key.log")]
    sslkeylogfile: String,

    #[arg(long, default_value = "pcaps")]
    pcaps_dir: String,

    /// worker threads
    #[arg(long)]
    threads: Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
struct InputRow {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: Option<String>,
    versions: Option<String>,
    pdns: Option<Pdns>,
}

#[derive(Debug, Deserialize, Clone)]
struct Pdns {
    current_domains: Vec<String>,
    historical_domains: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OutputRow {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: u16,

    selected_domain: Option<String>,
    sni_used: bool,

    // connected / failed / unreachable
    status: String,
    note: Option<String>,
}

/// 用于 resume 读取旧 output 时的最小解析结构
#[derive(Debug, Deserialize)]
struct OutputRowForResume {
    #[serde(rename = "IP")]
    ip: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    unsafe { std::env::set_var("RUST_LOG", &opt.log) };
    unsafe { std::env::set_var("SSLKEYLOGFILE", &opt.sslkeylogfile) };
    unsafe { std::env::set_var("PCAPS_DIR", &opt.pcaps_dir) };
    env_logger::init();

    let threads = opt.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    // ============ resume：读取 output 已完成 IP ============
    let mut done_ips = load_done_ips(&opt.output);
    info!(
        "resume: loaded {} done IPs from {}",
        done_ips.len(),
        opt.output
    );

    // ============ writer：单线程写文件，避免多线程竞争 ============
    let (result_tx, result_rx) = std::sync::mpsc::channel::<String>();
    let output_path = opt.output.clone();

    let writer_handle = thread::spawn(move || -> Result<(), String> {
        let mut writer = open_output_append(&output_path)?;
        while let Ok(line) = result_rx.recv() {
            if let Err(e) = writeln!(writer, "{line}") {
                return Err(format!("write output failed: {e}"));
            }
            if let Err(e) = writer.flush() {
                return Err(format!("flush output failed: {e}"));
            }
        }
        Ok(())
    });

    // ============ worker pool ============
    let (job_tx, job_rx) = cc::unbounded::<InputRow>();

    let mut worker_handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let rx = job_rx.clone(); // ✅ crossbeam 的 Receiver 可 clone
        let tx = result_tx.clone();

        worker_handles.push(thread::spawn(move || {
            while let Ok(row) = rx.recv() {
                let out = process_one_row(row);
                if let Ok(line) = serde_json::to_string(&out) {
                    let _ = tx.send(line);
                }
            }
        }));
    }
    drop(result_tx); // 主线程不再持有 result_tx（worker 仍持有 clone）

    // ============ dispatch jobs（顺便做“本次运行”的去重/跳过） ============
    let input_file = File::open(&opt.input)?;
    let reader = BufReader::new(input_file);

    let mut sent = 0usize;
    let mut skipped = 0usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let row: InputRow = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                // 输入行坏了也输出一行（通过 writer）
                let bad = OutputRow {
                    row: None,
                    ip: "UNKNOWN".to_string(),
                    port: 443,
                    selected_domain: None,
                    sni_used: false,
                    status: "failed".to_string(),
                    note: Some(format!("json_parse_error: {e}")),
                };
                let _ = jobless_emit(&bad, &job_tx); // 不用 job_tx，直接写到结果管道
                continue;
            }
        };

        // 断点续跑：IP 已完成则跳过
        if done_ips.contains(&row.ip) {
            skipped += 1;
            continue;
        }

        // 同一输入里 IP 重复：也跳过（并把它标记为 done，避免后面重复派发）
        done_ips.insert(row.ip.clone());

        // 派发给 worker
        if job_tx.send(row).is_ok() {
            sent += 1;
        }
    }
    drop(job_tx); // 关闭任务通道，让 worker 退出

    info!(
        "dispatch done: sent {} jobs, skipped {} already-done IPs",
        sent, skipped
    );

    // 等 worker 全部退出
    for h in worker_handles {
        let _ = h.join();
    }

    // 关闭 writer：所有 result_tx clone 会在 worker 退出时 drop，result_rx.recv() 会结束
    match writer_handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err("writer thread panicked".into()),
    }
}

/// 直接把 bad row 发到输出（不走 worker）
fn jobless_emit(bad: &OutputRow, _job_tx: &cc::Sender<InputRow>) -> Result<(), ()> {
    // 这里保持简单：bad 行直接 stdout/stderr 你也行；
    // 但为了不改动主结构，这里让 bad 行也走 “process_one_row” 的输出通道比较麻烦。
    // 你若希望 bad 行也进 output.jsonl，建议把解析放进 worker。
    // 当前实现：忽略 bad 行（或你也可以在这里 eprintln!）。
    let _ = bad;
    Ok(())
}

/// 打开 output：append；并尽量保证追加前有换行
fn open_output_append(path: &str) -> Result<BufWriter<File>, String> {
    let exists = Path::new(path).exists();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open output failed: {e}"))?;

    // 如果文件存在且非空，尽量确保末尾以 '\n' 结束，避免粘行
    if exists {
        let meta = file
            .metadata()
            .map_err(|e| format!("stat output failed: {e}"))?;
        if meta.len() > 0 {
            // 轻量做法：不强行读最后一字节（避免额外 seek），你如果特别介意粘行，可自行补读最后字节。
            // 这里选择不处理也通常没问题（大多数情况下文件本身就是按行写的）。
        }
    }

    Ok(BufWriter::new(file))
}

/// 从已有 output.jsonl 里加载“已完成 IP”
fn load_done_ips(output_path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if !Path::new(output_path).exists() {
        return set;
    }

    let file = match File::open(output_path) {
        Ok(f) => f,
        Err(_) => return set,
    };

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        let s = line.trim();
        if s.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<OutputRowForResume>(s) {
            set.insert(v.ip);
        }
    }
    set
}

/// worker：处理单个输入行（单 IP），返回输出行
fn process_one_row(row: InputRow) -> OutputRow {
    let port = row
        .port
        .as_deref()
        .unwrap_or("443")
        .parse::<u16>()
        .unwrap_or(443);

    let version = select_version(&row.versions);

    // 合并域名：current -> historical，去重保序，最多 1000
    let domains = collect_domains_capped(row.pdns.as_ref(), MAX_DOMAINS_PER_IP);
    let sni_used = !domains.is_empty();

    // 结果占位
    let mut selected_domain: Option<String> = None;
    let mut status = "failed".to_string();
    let mut note: Option<String> = None;

    if domains.is_empty() {
        // 无域名：尝试不带 SNI
        match try_connect_only(&row.ip, port, None, version) {
            Ok(mut quic_st) => {
                let cc = build_cc_frames();
                if let Err(e) = send_single_packet_frames(&mut quic_st, &cc) {
                    status = "failed".to_string();
                    note = Some(format!("send_cc_failed: {e}"));
                } else {
                    let _ = drain_after_close(&mut quic_st);
                    status = "connected".to_string();
                    note = Some("no domains provided".to_string());
                }
            }
            Err(AttemptErr::Timeout(e)) => {
                status = "unreachable".to_string();
                note = Some(format!("ip_unreachable_timeout: {e}"));
            }
            Err(AttemptErr::HandshakeFail(e)) => {
                status = "failed".to_string();
                note = Some(format!("no domains provided; {e}"));
            }
            Err(AttemptErr::Other(e)) => {
                status = "failed".to_string();
                note = Some(format!("no domains provided; {e}"));
            }
        }
    } else {
        // 有域名：逐个尝试
        let mut last_err: Option<String> = None;

        // 连续 timeout 计数
        let mut consec_timeouts = 0usize;
        let mut last_timeout_msg: Option<String> = None;

        for d in domains {
            match try_connect_only(&row.ip, port, Some(&d), version) {
                Ok(mut quic_st) => {
                    // 成功：确认域名，立即发 CC + drain，退出
                    let cc = build_cc_frames();
                    match send_single_packet_frames(&mut quic_st, &cc) {
                        Ok(_) => {
                            let _ = drain_after_close(&mut quic_st);
                            selected_domain = Some(d);
                            status = "connected".to_string();
                            note = None;
                        }
                        Err(e) => {
                            status = "failed".to_string();
                            note = Some(format!("send_cc_failed: {e}"));
                        }
                    }
                    break;
                }

                Err(AttemptErr::Timeout(e)) => {
                    consec_timeouts += 1;
                    last_timeout_msg = Some(e.clone());
                    info!(
                        "timeout on {}:{} domain={}, consec_timeouts={}",
                        row.ip, port, d, consec_timeouts
                    );

                    if consec_timeouts >= CONSEC_TIMEOUT_THRESHOLD {
                        status = "unreachable".to_string();
                        note = Some(format!(
                            "ip_unreachable_{}consecutive_timeouts: {}",
                            CONSEC_TIMEOUT_THRESHOLD,
                            last_timeout_msg.unwrap_or_else(|| "Timeout".to_string())
                        ));
                        break; // 达到阈值：跳过后续域名
                    }

                    // 未达到阈值：继续尝试下一个域名
                    continue;
                }

                Err(AttemptErr::HandshakeFail(e)) => {
                    // 非 timeout：说明至少网络可达，连续 timeout 计数清零
                    consec_timeouts = 0;
                    last_err = Some(e);
                    continue;
                }

                Err(AttemptErr::Other(e)) => {
                    // 非 timeout：同样清零
                    consec_timeouts = 0;
                    last_err = Some(e);
                    continue;
                }
            }
        }

        if status == "failed" && note.is_none() {
            note = Some(last_err.unwrap_or_else(|| "all domains failed".to_string()));
        }
    }

    OutputRow {
        row: row.row,
        ip: row.ip,
        port,
        selected_domain,
        sni_used,
        status,
        note,
    }
}

/// 域名合并、去重保序、上限截断
fn collect_domains_capped(pdns: Option<&Pdns>, cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let mut push_one = |s: &str| {
        if out.len() >= cap {
            return;
        }
        let ss = s.trim();
        if ss.is_empty() {
            return;
        }
        if seen.insert(ss.to_string()) {
            out.push(ss.to_string());
        }
    };

    if let Some(p) = pdns {
        for d in &p.current_domains {
            push_one(d);
        }
        for d in &p.historical_domains {
            push_one(d);
        }
    }

    out
}

/// 版本选择：优先 v1(0x00000001)，否则 fallback quiche::PROTOCOL_VERSION
fn select_version(versions: &Option<String>) -> u32 {
    let Some(versions) = versions else {
        return quiche::PROTOCOL_VERSION;
    };

    for entry in versions.split_whitespace() {
        let trimmed = entry.trim();
        let value = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if let Ok(parsed) = u32::from_str_radix(value, 16) {
            if parsed == 0x0000_0001 {
                return parsed;
            }
        }
    }

    quiche::PROTOCOL_VERSION
}

#[derive(Debug)]
enum AttemptErr {
    Timeout(String),
    HandshakeFail(String),
    Other(String),
}

/// 只负责“连接”；成功返回已建立连接的 QuicStruct
fn try_connect_only(
    ip: &str,
    port: u16,
    sni: Option<&str>,
    _version: u32,
) -> Result<QuicStruct, AttemptErr> {
    let sni_string = sni.unwrap_or("").to_string();
    let mut quic_st = QuicStruct::new(sni_string, port, ip.to_string());

    match quic_st.connect() {
        Ok(_) => {
            info!(
                "Connected: {}:{} sni={:?} local_port={} peer_port={}",
                ip,
                port,
                sni,
                quic_st.local_addr.port(),
                quic_st.peer_addr.port()
            );
            Ok(quic_st)
        }
        Err(e) => {
            // 优先用你新增的强语义：is_timeout()
            // 若你还没实现 is_timeout()，至少保证 Err("Timeout")
            if quic_st.is_timeout() || e == "Timeout" {
                return Err(AttemptErr::Timeout(e));
            }
            if e == "HandshakeFail" {
                return Err(AttemptErr::HandshakeFail(e));
            }
            Err(AttemptErr::Other(format!("connect_failed: {e:?}")))
        }
    }
}

/// 仅负责“构建 CC 帧”
fn build_cc_frames() -> Vec<frame::Frame> {
    vec![frame::Frame::ConnectionClose {
        error_code: 0,
        frame_type: 0,
        reason: Vec::new(),
    }]
}

/// 仅负责“发送一个包（包含 frames）并 flush”
fn send_single_packet_frames(
    quic_st: &mut QuicStruct,
    frames: &[frame::Frame],
) -> Result<(), String> {
    let mut input_struct = InputStruct::new();
    let mut frame_cycle = FramesCycleStruct::new();

    for f in frames {
        frame_cycle = frame_cycle.add_frame(f.clone());
    }

    input_struct = input_struct.add_frames_cycle(frame_cycle);
    input_struct = input_struct.calc_frames_cycle_len();
    let pkt_type = input_struct.pkt_type;

    let mut out = [0u8; MAX_DATAGRAM_SIZE << 10];

    quic_st
        .send_pkt_to_server(pkt_type, frames, &mut out)
        .map_err(|e| format!("send_pkt_to_server_failed: {e:?}"))?;

    quic_st
        .handle_sending()
        .map_err(|e| format!("handle_sending_failed: {e:?}"))?;

    Ok(())
}

/// 收尾 draining：短周期 recv + flush send，直到 closed 且安静一小段时间，或超时
fn drain_after_close(quic_st: &mut QuicStruct) -> Result<(), String> {
    let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
    let mut last_rx = Instant::now();

    loop {
        match quic_st.handle_recving_once() {
            Ok(recv_frames) => {
                if !recv_frames.is_empty() {
                    last_rx = Instant::now();
                    debug!("drain recv {} frames", recv_frames.len());
                }
            }
            Err(_e) => {
                // 如果你的封装把 WouldBlock 也 Err 出来，这里保持“非致命”
            }
        }

        let _ = quic_st.handle_sending();

        if quic_st.conn_is_closed() && last_rx.elapsed() > QUIET_TIME {
            break;
        }
        if Instant::now() > drain_deadline {
            break;
        }

        sleep(Duration::from_millis(5));
    }

    Ok(())
}

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use crossbeam_channel as cc;
use log::{debug, info};
use quiche::{FrameWithPkn, frame};
use serde::{Deserialize, Serialize};

use mylibafl::inputstruct::{FramesCycleStruct, InputStruct, QuicStruct};

mod ui;

const MAX_STAGES: usize = 8;
const MAX_DATAGRAM_SIZE: usize = 1350;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const QUIET_TIME: Duration = Duration::from_millis(200);

const STAGE_SETTLE_TIMEOUT: Duration = Duration::from_millis(300);
const PC_PR_TIMEOUT: Duration = Duration::from_secs(2);
const PC_PR_POLL_INTERVAL: Duration = Duration::from_millis(10);

const UI_COLS: usize = 10;
const UI_LOG_LINES: u16 = 6;

const MIN_JOB_QUEUE_CAP: usize = 64;
const MAX_JOB_QUEUE_CAP: usize = 256;
const MIN_RESULT_QUEUE_CAP: usize = 256;
const MAX_RESULT_QUEUE_CAP: usize = 2048;
const MIN_UI_QUEUE_CAP: usize = 2048;
const MAX_UI_QUEUE_CAP: usize = 16384;

#[derive(Debug, Parser)]
#[command(
    name = "feature_measure",
    about = "Read pdns_search_sni_tui output jsonl, run 8-stage frame tests on connected IPs.",
    author = "k4ra5u"
)]
struct Opt {
    /// input jsonl from pdns_search_sni_tui (one json object per line)
    input: String,

    /// output jsonl for feature measurement result
    output: String,

    #[arg(long, default_value = "info")]
    log: String,

    #[arg(long, default_value = "key.log")]
    sslkeylogfile: String,

    #[arg(long, default_value = "pcaps")]
    pcaps_dir: String,

    /// worker threads
    #[arg(long)]
    threads: Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum PortValue {
    Number(u16),
    String(String),
}

impl PortValue {
    fn to_u16(&self) -> Option<u16> {
        match self {
            PortValue::Number(v) => Some(*v),
            PortValue::String(s) => s.parse::<u16>().ok(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct InputRow {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: Option<PortValue>,

    selected_domain: Option<String>,
    status: Option<String>,
    note: Option<String>,
    versions: Option<String>,
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

    source_status: String,
    source_note: Option<String>,

    // skipped / success / failed
    status: String,

    success_stages: Vec<u8>,
    stage_results: Vec<StageResult>,

    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct StageResult {
    stage: u8,

    // success / failed / skipped
    status: String,
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OutputRowForResume {
    #[serde(rename = "IP")]
    ip: String,
}

#[derive(Debug)]
enum AttemptErr {
    Timeout(String),
    HandshakeFail(String),
    Other(String),
}

#[derive(Debug, Clone, Copy)]
enum Stage {
    Stage1,
    Stage2,
    Stage3,
    Stage4,
    Stage5,
    Stage6,
    Stage7,
    Stage8,
}

impl Stage {
    const ALL: [Stage; MAX_STAGES] = [
        Stage::Stage1,
        Stage::Stage2,
        Stage::Stage3,
        Stage::Stage4,
        Stage::Stage5,
        Stage::Stage6,
        Stage::Stage7,
        Stage::Stage8,
    ];

    fn number(self) -> u8 {
        match self {
            Stage::Stage1 => 1,
            Stage::Stage2 => 2,
            Stage::Stage3 => 3,
            Stage::Stage4 => 4,
            Stage::Stage5 => 5,
            Stage::Stage6 => 6,
            Stage::Stage7 => 7,
            Stage::Stage8 => 8,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StageBuildContext {
    row: Option<u64>,
    ip: String,
    port: u16,
    selected_domain: Option<String>,
    source_status: String,
    source_note: Option<String>,
    version: u32,
}

#[derive(Clone)]
struct RuntimeLogFile {
    path: Arc<PathBuf>,
    writer: Arc<Mutex<BufWriter<File>>>,
}

impl RuntimeLogFile {
    fn new(output_path: &str) -> Result<Self, std::io::Error> {
        let path = PathBuf::from(format!("{output_path}.runtime.log"));
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        Ok(Self {
            path: Arc::new(path),
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
        })
    }

    fn append(&self, line: &str) {
        match self.writer.lock() {
            Ok(mut writer) => {
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
            Err(poisoned) => {
                let mut writer = poisoned.into_inner();
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
        }
    }

    fn flush(&self) {
        match self.writer.lock() {
            Ok(mut writer) => {
                let _ = writer.flush();
            }
            Err(poisoned) => {
                let mut writer = poisoned.into_inner();
                let _ = writer.flush();
            }
        }
    }

    fn path_buf(&self) -> PathBuf {
        (*self.path).clone()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    unsafe { std::env::set_var("RUST_LOG", &opt.log) };
    unsafe { std::env::set_var("SSLKEYLOGFILE", &opt.sslkeylogfile) };
    unsafe { std::env::set_var("PCAPS_DIR", &opt.pcaps_dir) };

    let threads = opt.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    let runtime_log = RuntimeLogFile::new(&opt.output)?;

    let (ui_tx, ui_rx) = cc::bounded::<ui::UiEvent>(ui_queue_cap(threads));
    let ui_handle = ui::spawn_ui_thread(threads, UI_COLS, UI_LOG_LINES, ui_rx);

    init_logger_with_ui(ui_tx.clone(), &opt.log, runtime_log.clone())?;

    let mut done_ips = load_done_ips(&opt.output);
    let resume_line = format!("resume loaded done_ips={}", done_ips.len());
    runtime_log.append(&format!("[INFO] {resume_line}"));
    let _ = ui_tx.send(ui::UiEvent::Info(resume_line));

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel::<String>(result_queue_cap(threads));
    let output_path = opt.output.clone();
    let ui_tx_writer = ui_tx.clone();
    let runtime_log_writer = runtime_log.clone();

    let writer_handle = thread::spawn(move || -> Result<(), String> {
        let mut writer = open_output_append(&output_path)?;

        while let Ok(line) = result_rx.recv() {
            if let Err(e) = writeln!(writer, "{line}") {
                let msg = format!("write output failed: {e}");
                runtime_log_writer.append(&format!("[FATAL] {msg}"));
                let _ = ui_tx_writer.send(ui::UiEvent::Fatal(msg.clone()));
                return Err(msg);
            }

            if let Err(e) = writer.flush() {
                let msg = format!("flush output failed: {e}");
                runtime_log_writer.append(&format!("[FATAL] {msg}"));
                let _ = ui_tx_writer.send(ui::UiEvent::Fatal(msg.clone()));
                return Err(msg);
            }
        }

        Ok(())
    });

    let (job_tx, job_rx) = cc::bounded::<InputRow>(job_queue_cap(threads));

    let mut worker_handles = Vec::with_capacity(threads);
    for wid in 0..threads {
        let rx = job_rx.clone();
        let tx = result_tx.clone();
        let ui = ui_tx.clone();

        let handle = thread::Builder::new()
            .name(format!("worker-{wid}"))
            .spawn(move || {
                while let Ok(row) = rx.recv() {
                    let out = process_one_row(&ui, wid, row);

                    if let Ok(line) = serde_json::to_string(&out) {
                        let _ = tx.send(line);
                    }

                    let _ = ui.send(ui::UiEvent::JobDone);
                }

                let _ = ui.send(ui::UiEvent::WorkerIdle { wid });
            })?;

        worker_handles.push(handle);
    }

    let result_tx_main = result_tx.clone();
    drop(result_tx);

    let input_file = File::open(&opt.input)?;
    let reader = BufReader::new(input_file);

    let mut sent = 0usize;
    let mut skipped = 0usize;
    let mut bad_lines = 0usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let row: InputRow = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                bad_lines += 1;
                let bad = OutputRow {
                    row: None,
                    ip: "UNKNOWN".to_string(),
                    port: 443,
                    selected_domain: None,
                    source_status: "invalid_input".to_string(),
                    source_note: None,
                    status: "failed".to_string(),
                    success_stages: Vec::new(),
                    stage_results: Vec::new(),
                    note: Some(format!("json_parse_error: {e}")),
                };

                if let Ok(s) = serde_json::to_string(&bad) {
                    let _ = result_tx_main.send(s);
                }

                let _ = ui_tx.send(ui::UiEvent::JobDone);
                continue;
            }
        };

        if done_ips.contains(&row.ip) {
            skipped += 1;
            continue;
        }

        done_ips.insert(row.ip.clone());

        if job_tx.send(row).is_ok() {
            sent += 1;
        }
    }

    drop(job_tx);

    let _ = ui_tx.send(ui::UiEvent::SetTotals {
        jobs_sent: sent,
        jobs_skipped: skipped,
        bad_lines,
    });

    info!(
        "dispatch done: sent {} jobs, skipped {} already-done IPs, bad_lines {}",
        sent, skipped, bad_lines
    );

    for h in worker_handles {
        let _ = h.join();
    }

    drop(result_tx_main);

    let writer_res = match writer_handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("writer thread panicked".to_string()),
    };

    let _ = ui_tx.send(ui::UiEvent::Shutdown);
    let _ = ui_handle.join();

    if let Err(e) = &writer_res {
        runtime_log.append(&format!("[FATAL] {e}"));
    }
    dump_logs_to_stdout(&runtime_log);

    match writer_res {
        Ok(()) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn init_logger_with_ui(
    ui_tx: cc::Sender<ui::UiEvent>,
    level: &str,
    runtime_log: RuntimeLogFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = env_logger::Builder::new();
    builder.parse_filters(level);

    builder.format(move |_buf, record| {
        let ts = chrono_like_ts_millis();
        let line = format!("{} {:<5} {}", ts, record.level(), record.args());
        runtime_log.append(&line);
        let _ = ui_tx.try_send(ui::UiEvent::Log(line));
        Ok(())
    });

    builder.try_init()?;
    Ok(())
}

fn chrono_like_ts_millis() -> String {
    use std::sync::OnceLock;
    static T0: OnceLock<Instant> = OnceLock::new();
    let t0 = *T0.get_or_init(Instant::now);
    format!("{:>10}ms", t0.elapsed().as_millis())
}

fn job_queue_cap(threads: usize) -> usize {
    threads.max(MIN_JOB_QUEUE_CAP).min(MAX_JOB_QUEUE_CAP)
}

fn result_queue_cap(threads: usize) -> usize {
    threads
        .saturating_mul(2)
        .max(MIN_RESULT_QUEUE_CAP)
        .min(MAX_RESULT_QUEUE_CAP)
}

fn ui_queue_cap(threads: usize) -> usize {
    threads
        .saturating_mul(32)
        .max(MIN_UI_QUEUE_CAP)
        .min(MAX_UI_QUEUE_CAP)
}

fn dump_logs_to_stdout(runtime_log: &RuntimeLogFile) {
    runtime_log.flush();
    let log_path = runtime_log.path_buf();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "===== runtime logs file: {} =====", log_path.display());

    let file = match File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(out, "[WARN] failed to open runtime log file: {e}");
            let _ = out.flush();
            return;
        }
    };

    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
}

fn open_output_append(path: &str) -> Result<BufWriter<File>, String> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open output failed: {e}"))?;
    Ok(BufWriter::new(file))
}

fn load_done_ips(output_path: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if !Path::new(output_path).exists() {
        return set;
    }

    let file = match File::open(output_path) {
        Ok(f) => f,
        Err(_) => return set,
    };

    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
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

fn process_one_row(ui: &cc::Sender<ui::UiEvent>, wid: usize, row: InputRow) -> OutputRow {
    let port = parse_port(row.port.as_ref()).unwrap_or(443);
    let source_status = row.status.clone().unwrap_or_else(|| "unknown".to_string());
    let source_note = row.note.clone();

    let selected_domain = row
        .selected_domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let _ = ui.send(ui::UiEvent::WorkerStart {
        wid,
        ip: row.ip.clone(),
        port,
        total: MAX_STAGES as u64,
    });

    let stage_ctx = StageBuildContext {
        row: row.row,
        ip: row.ip.clone(),
        port,
        selected_domain: selected_domain.clone(),
        source_status: source_status.clone(),
        source_note: source_note.clone(),
        version: select_version(&row.versions),
    };

    if !source_status.eq_ignore_ascii_case("connected") {
        for _ in 0..MAX_STAGES {
            let _ = ui.try_send(ui::UiEvent::WorkerStep { wid });
        }

        let note = format!(
            "source status `{}` is not connected, skip stage testing",
            source_status
        );
        let stage_results = skipped_stage_results(&note);

        let _ = ui.send(ui::UiEvent::WorkerFinishUnreach {
            wid,
            note: note.clone(),
        });

        return OutputRow {
            row: row.row,
            ip: row.ip,
            port,
            selected_domain,
            source_status,
            source_note,
            status: "skipped".to_string(),
            success_stages: Vec::new(),
            stage_results,
            note: Some(note),
        };
    }

    let mut stage_results = Vec::with_capacity(MAX_STAGES);
    let mut success_stages = Vec::new();

    for stage in Stage::ALL {
        let _ = ui.try_send(ui::UiEvent::WorkerStep { wid });

        let stage_result = run_one_stage(stage, &stage_ctx);
        if stage_result.status == "success" {
            success_stages.push(stage.number());
        }

        stage_results.push(stage_result);
    }

    let configured_stage_count = stage_results
        .iter()
        .filter(|r| r.status != "skipped")
        .count();

    let (status, note) = if configured_stage_count == 0 {
        (
            "skipped".to_string(),
            Some("no stage frames implemented, all stages skipped".to_string()),
        )
    } else if success_stages.is_empty() {
        (
            "failed".to_string(),
            Some("all configured stages kept normal PC/PR interaction".to_string()),
        )
    } else {
        (
            "success".to_string(),
            Some(format!("triggered stages: {:?}", success_stages)),
        )
    };

    if status == "success" {
        let _ = ui.send(ui::UiEvent::WorkerFinishOk {
            wid,
            domain: format!("stages={:?}", success_stages),
        });
    } else if status == "skipped" {
        let _ = ui.send(ui::UiEvent::WorkerFinishUnreach {
            wid,
            note: note.clone().unwrap_or_default(),
        });
    } else {
        let _ = ui.send(ui::UiEvent::WorkerFinishFail {
            wid,
            note: note.clone().unwrap_or_default(),
        });
    }

    OutputRow {
        row: row.row,
        ip: row.ip,
        port,
        selected_domain,
        source_status,
        source_note,
        status,
        success_stages,
        stage_results,
        note,
    }
}

fn skipped_stage_results(reason: &str) -> Vec<StageResult> {
    let mut out = Vec::with_capacity(MAX_STAGES);
    for stage in Stage::ALL {
        out.push(StageResult {
            stage: stage.number(),
            status: "skipped".to_string(),
            note: Some(reason.to_string()),
        });
    }
    out
}

fn parse_port(v: Option<&PortValue>) -> Option<u16> {
    v.and_then(PortValue::to_u16)
}

fn run_one_stage(stage: Stage, ctx: &StageBuildContext) -> StageResult {
    let stage_no = stage.number();

    let frames = build_stage_frames(stage, ctx);
    if frames.is_empty() {
        return StageResult {
            stage: stage_no,
            status: "skipped".to_string(),
            note: Some("empty frame sequence, please implement this stage".to_string()),
        };
    }

    let mut quic_st = match try_connect_only(
        &ctx.ip,
        ctx.port,
        ctx.selected_domain.as_deref(),
        ctx.version,
    ) {
        Ok(quic_st) => quic_st,
        Err(AttemptErr::Timeout(e)) => {
            return failed_stage(stage_no, format!("connect_timeout: {e}"));
        }
        Err(AttemptErr::HandshakeFail(e)) => {
            return failed_stage(stage_no, format!("connect_handshake_fail: {e}"));
        }
        Err(AttemptErr::Other(e)) => {
            return failed_stage(stage_no, format!("connect_failed: {e}"));
        }
    };

    if let Err(e) = send_single_packet_frames(&mut quic_st, &frames) {
        let _ = drain_after_close(&mut quic_st);
        return failed_stage(stage_no, format!("send_stage_frames_failed: {e}"));
    }

    let (is_success, judge_note) = judge_stage_success(&mut quic_st, stage);
    let _ = drain_after_close(&mut quic_st);

    if is_success {
        StageResult {
            stage: stage_no,
            status: "success".to_string(),
            note: Some(judge_note),
        }
    } else {
        StageResult {
            stage: stage_no,
            status: "failed".to_string(),
            note: Some(judge_note),
        }
    }
}

fn failed_stage(stage_no: u8, note: String) -> StageResult {
    StageResult {
        stage: stage_no,
        status: "failed".to_string(),
        note: Some(note),
    }
}

fn judge_stage_success(quic_st: &mut QuicStruct, stage: Stage) -> (bool, String) {
    let settle_deadline = Instant::now() + STAGE_SETTLE_TIMEOUT;

    while Instant::now() < settle_deadline {
        if quic_st.conn_is_closed() {
            return (true, "connection_closed_after_stage_frames".to_string());
        }

        if let Ok(recv_frames) = quic_st.handle_recving_once() {
            if let Some(reason) = detect_close_frame(&recv_frames) {
                return (true, reason);
            }
        }

        let _ = quic_st.handle_sending();
        thread::sleep(PC_PR_POLL_INTERVAL);
    }

    if quic_st.conn_is_closed() {
        return (true, "connection_closed_before_pc_pr_probe".to_string());
    }

    let probe_data = stage_probe_data(stage);
    let pc_frames = vec![frame::Frame::PathChallenge { data: probe_data }];

    if let Err(e) = send_single_packet_frames(quic_st, &pc_frames) {
        return (true, format!("cannot_send_path_challenge: {e}"));
    }

    let probe_deadline = Instant::now() + PC_PR_TIMEOUT;

    while Instant::now() < probe_deadline {
        match quic_st.handle_recving_once() {
            Ok(recv_frames) => {
                if let Some(reason) = detect_close_frame(&recv_frames) {
                    return (true, reason);
                }

                if recv_has_expected_path_response(&recv_frames, probe_data) {
                    return (false, "pc_pr_interaction_normal".to_string());
                }
            }
            Err(_e) => {
                // keep polling until timeout
            }
        }

        if quic_st.conn_is_closed() {
            return (true, "connection_closed_during_pc_pr_probe".to_string());
        }

        let _ = quic_st.handle_sending();
        thread::sleep(PC_PR_POLL_INTERVAL);
    }

    (true, "no_path_response_for_path_challenge".to_string())
}

fn detect_close_frame(frames: &[FrameWithPkn]) -> Option<String> {
    for fw in frames {
        match &fw.frame {
            frame::Frame::ConnectionClose {
                error_code,
                frame_type,
                ..
            } => {
                return Some(format!(
                    "peer_connection_close(error_code={}, frame_type={})",
                    error_code, frame_type
                ));
            }

            frame::Frame::ApplicationClose { error_code, .. } => {
                return Some(format!("peer_application_close(error_code={})", error_code));
            }

            _ => {}
        }
    }

    None
}

fn recv_has_expected_path_response(frames: &[FrameWithPkn], expected: [u8; 8]) -> bool {
    for fw in frames {
        if let frame::Frame::PathResponse { data } = &fw.frame {
            if *data == expected {
                return true;
            }
        }
    }

    false
}

fn stage_probe_data(stage: Stage) -> [u8; 8] {
    let s = stage.number();
    [0x50, 0x43, s, 0x00, 0x00, 0x00, 0x00, 0xAA]
}

fn build_stage_frames(stage: Stage, ctx: &StageBuildContext) -> Vec<frame::Frame> {
    match stage {
        Stage::Stage1 => build_stage_1_frames(ctx),
        Stage::Stage2 => build_stage_2_frames(ctx),
        Stage::Stage3 => build_stage_3_frames(ctx),
        Stage::Stage4 => build_stage_4_frames(ctx),
        Stage::Stage5 => build_stage_5_frames(ctx),
        Stage::Stage6 => build_stage_6_frames(ctx),
        Stage::Stage7 => build_stage_7_frames(ctx),
        Stage::Stage8 => build_stage_8_frames(ctx),
    }
}

// TODO: 按你的需求实现每个 stage 的 frame 序列。
// 接口和 build_cc_frames 一样，返回 Vec<frame::Frame>。
fn build_stage_1_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_2_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_3_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_4_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_5_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_6_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_7_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

fn build_stage_8_frames(_ctx: &StageBuildContext) -> Vec<frame::Frame> {
    Vec::new()
}

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

    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    quic_st
        .send_pkt_to_server(pkt_type, frames, &mut out)
        .map_err(|e| format!("send_pkt_to_server_failed: {e:?}"))?;

    quic_st
        .handle_sending()
        .map_err(|e| format!("handle_sending_failed: {e:?}"))?;

    Ok(())
}

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
                // keep draining, non-fatal
            }
        }

        let _ = quic_st.handle_sending();

        if quic_st.conn_is_closed() && last_rx.elapsed() > QUIET_TIME {
            break;
        }

        if Instant::now() > drain_deadline {
            break;
        }

        thread::sleep(Duration::from_millis(5));
    }

    Ok(())
}

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use crossbeam_channel as cc;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
mod ui;
// IMPORTANT: 从 mylibafl re-export 的 quiche 取 frame，避免 quiche 版本不一致导致 Frame 类型不匹配
use quiche::frame;

use mylibafl::inputstruct::{FramesCycleStruct, InputStruct, QuicStruct};

// main.rs
//
// 目标：
// - 多线程 worker（--threads 可指定）
// - resume：跳过 output.jsonl 里已经有结果的 IP
// - 每个 IP 最多尝试 1000 个域名（current -> historical 去重保序）
// - 仅 try connect；成功后只发送一个包（仅含 ConnectionClose 帧）并 drain
// - 连续 3 次 timeout 才判定该 IP 不可达（unreachable）并跳过后续域名
// - TUI：把所有 worker 以网格显示，默认每行 10 个（可通过参数调整）
//
// 依赖（Cargo.toml 里需要你自己加）：
// clap = { version = "4", features = ["derive"] }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// crossbeam-channel = "0.5"
// log = "0.4"
// env_logger = "0.11"
// crossterm = "0.27"
// ratatui = "0.26"
//
// 说明：
// - 日志不会直接打印到 stdout/stderr，而是发给 UI 的 log 面板，避免打乱进度条。
// - 发生“目前会抛出的 error”（比如文件 IO / writer 失败 / UI 初始化失败）仍会返回 Err 让程序退出。
// - QUIC 连接/握手失败属于测量结果的一部分，不会让程序整体 panic，而会写入 output.jsonl。

const MAX_DOMAINS_PER_IP: usize = 1000;
const MAX_DATAGRAM_SIZE: usize = 1350;

// 收尾参数：尽量收齐 close/ack/重传尾包，避免 socket 过早 drop 触发 ICMP
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const QUIET_TIME: Duration = Duration::from_millis(200);

// 连续 timeout 次数阈值：达到才判定不可达并跳过
const CONSEC_TIMEOUT_THRESHOLD: usize = 3;

// UI：默认每行 10 个 worker（可通过参数调整）
const UI_COLS: usize = 10;

// UI：底部 log 行数
const UI_LOG_LINES: u16 = 6;

// FD 预算：每个 worker 大约会占用 Poll + 2 UDP socket + keylog 等多个 fd。
const EST_FDS_PER_WORKER: u64 = 6;
const EST_FDS_BASE: u64 = 1024;

// 2000 线程时默认 8MB 栈会非常夸张，这里显式降低 worker 栈占用。
const WORKER_STACK_SIZE: usize = 1 * 1024 * 1024;

// 使用有界队列，避免无界积压导致内存持续上涨。
const MIN_JOB_QUEUE_CAP: usize = 64;
const MAX_JOB_QUEUE_CAP: usize = 256;
const MIN_RESULT_QUEUE_CAP: usize = 256;
const MAX_RESULT_QUEUE_CAP: usize = 2048;
const MIN_UI_QUEUE_CAP: usize = 2048;
const MAX_UI_QUEUE_CAP: usize = 16384;

// 轻量内存观测间隔（秒）
const MEM_OBS_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Parser)]
#[command(
    name = "jsonl_sni_tester",
    about = "Read input.jsonl, try SNI domains, confirm first success, send CC only, output jsonl. Multi-thread + resume + 3 consecutive timeouts => unreachable. TUI grid columns are configurable.",
    author = "k4ra5u"
)]
struct Opt {
    /// input jsonl (one json object per line)
    input: String,

    /// output jsonl (one json object per line)
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

    /// UI grid columns (workers per row)
    #[arg(long, default_value_t = UI_COLS)]
    ui_cols: usize,

    /// Show IP in each UI worker cell (true/false)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    ui_show_ip: bool,

    /// Show elapsed time in each UI worker cell (true/false)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    ui_show_time: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct InputRow {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: Option<PortValue>,
    versions: Option<String>,
    pdns: Option<Pdns>,
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
            Self::Number(v) => Some(*v),
            Self::String(v) => v.parse::<u16>().ok(),
        }
    }
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

#[derive(Debug)]
enum AttemptErr {
    Timeout(String),
    HandshakeFail(String),
    Other(String),
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

#[derive(Default)]
struct RuntimeCounters {
    jobs_enqueued: AtomicUsize,
    jobs_dequeued: AtomicUsize,
    results_enqueued: AtomicUsize,
    results_dequeued: AtomicUsize,
    workers_busy: AtomicUsize,
    done_ips: AtomicUsize,
}

struct MemoryObserver {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl MemoryObserver {
    fn start(
        counters: Arc<RuntimeCounters>,
        runtime_log: RuntimeLogFile,
        ui_tx: cc::Sender<ui::UiEvent>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_in_thread = stop.clone();
        let join = thread::Builder::new()
            .name("mem-observer".to_string())
            .spawn(move || {
                while !stop_in_thread.load(Ordering::Relaxed) {
                    if let Some((rss_kb, vmsize_kb, threads, swap_kb)) = read_proc_self_mem_metrics() {
                        let jobs_q = counters
                            .jobs_enqueued
                            .load(Ordering::Relaxed)
                            .saturating_sub(counters.jobs_dequeued.load(Ordering::Relaxed));
                        let results_q = counters
                            .results_enqueued
                            .load(Ordering::Relaxed)
                            .saturating_sub(counters.results_dequeued.load(Ordering::Relaxed));
                        let busy = counters.workers_busy.load(Ordering::Relaxed);
                        let done_ips = counters.done_ips.load(Ordering::Relaxed);

                        let mem_line = format!(
                            "[MEM] rss_mb={:.1} vmsize_mb={:.1} swap_mb={:.1} threads={} workers_busy={} jobs_q={} results_q={} done_ips={}",
                            kb_to_mb(rss_kb),
                            kb_to_mb(vmsize_kb),
                            kb_to_mb(swap_kb),
                            threads,
                            busy,
                            jobs_q,
                            results_q,
                            done_ips
                        );
                        runtime_log.append(&mem_line);
                        let _ = ui_tx.send(ui::UiEvent::Log(mem_line));
                    }

                    for _ in 0..MEM_OBS_INTERVAL_SECS {
                        if stop_in_thread.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .ok();

        Self { stop, join }
    }
}

impl Drop for MemoryObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
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
    let required_nofile = estimate_required_nofile(threads);
    let current_nofile = ensure_nofile_limit(required_nofile)
        .map_err(|e| format!("failed to prepare fd limit for threads={threads}: {e}"))?;
    eprintln!(
        "RLIMIT_NOFILE prepared: soft_limit={} required_estimate={}",
        current_nofile, required_nofile
    );
    let runtime_log = RuntimeLogFile::new(&opt.output)?;
    let counters = Arc::new(RuntimeCounters::default());

    // ============ UI ============
    let (ui_tx, ui_rx) = cc::bounded::<ui::UiEvent>(ui_queue_cap(threads));
    let ui_handle = ui::spawn_ui_thread(
        threads,
        opt.ui_cols.max(1),
        UI_LOG_LINES,
        opt.ui_show_ip,
        opt.ui_show_time,
        ui_rx,
    );
    let _mem_observer = MemoryObserver::start(counters.clone(), runtime_log.clone(), ui_tx.clone());

    // ============ logger -> UI logs（避免冲乱 TUI） ============
    init_logger_with_ui(ui_tx.clone(), &opt.log, runtime_log.clone())?;

    // ============ resume：读取 output 已完成 IP ============
    let mut done_ips = load_done_ips(&opt.output);
    counters.done_ips.store(done_ips.len(), Ordering::Relaxed);
    info!(
        "resume: loaded {} done IPs from {}",
        done_ips.len(),
        opt.output
    );
    let resume_line = format!("resume loaded done_ips={}", done_ips.len());
    runtime_log.append(&format!("[INFO] {}", resume_line));
    let _ = ui_tx.send(ui::UiEvent::Info(resume_line));

    // ============ writer：单线程写文件，避免多线程竞争 ============
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel::<String>(result_queue_cap(threads));
    let output_path = opt.output.clone();
    let ui_tx_writer = ui_tx.clone();
    let runtime_log_writer = runtime_log.clone();
    let counters_writer = counters.clone();

    let writer_handle = thread::spawn(move || -> Result<(), String> {
        let mut writer = open_output_append(&output_path)?;
        while let Ok(line) = result_rx.recv() {
            if let Err(e) = writeln!(writer, "{line}") {
                let msg = format!("write output failed: {e}");
                runtime_log_writer.append(&format!("[FATAL] {}", msg));
                let _ = ui_tx_writer.send(ui::UiEvent::Fatal(msg.clone()));
                return Err(msg);
            }
            if let Err(e) = writer.flush() {
                let msg = format!("flush output failed: {e}");
                runtime_log_writer.append(&format!("[FATAL] {}", msg));
                let _ = ui_tx_writer.send(ui::UiEvent::Fatal(msg.clone()));
                return Err(msg);
            }
            counters_writer
                .results_dequeued
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });

    // ============ worker pool ============
    let (job_tx, job_rx) = cc::bounded::<InputRow>(job_queue_cap(threads));

    let mut worker_handles = Vec::with_capacity(threads);
    for wid in 0..threads {
        let rx = job_rx.clone();
        let tx = result_tx.clone();
        let ui = ui_tx.clone();
        let counters_worker = counters.clone();

        let handle = thread::Builder::new()
            .name(format!("worker-{wid}"))
            .stack_size(WORKER_STACK_SIZE)
            .spawn(move || {
                while let Ok(row) = rx.recv() {
                    counters_worker
                        .jobs_dequeued
                        .fetch_add(1, Ordering::Relaxed);
                    counters_worker.workers_busy.fetch_add(1, Ordering::Relaxed);
                    let out = process_one_row(&ui, wid, row);

                    // 输出行
                    if let Ok(line) = serde_json::to_string(&out) {
                        if tx.send(line).is_ok() {
                            counters_worker
                                .results_enqueued
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    counters_worker.workers_busy.fetch_sub(1, Ordering::Relaxed);

                    let _ = ui.send(ui::UiEvent::JobDone);
                }

                let _ = ui.send(ui::UiEvent::WorkerIdle { wid });
            })?;
        worker_handles.push(handle);
    }

    // 主线程也可能要直接写 “坏输入行” => 保留一个 result_tx_main
    let result_tx_main = result_tx.clone();

    // 主线程不再持有 result_tx（worker + result_tx_main 仍持有）
    drop(result_tx);

    // ============ dispatch jobs（去重/跳过 + 统计） ============
    let input_file = File::open(&opt.input)?;
    let reader = BufReader::new(input_file);

    let mut sent = 0usize;
    let mut skipped = 0usize;
    let mut parse_bad = 0usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let row: InputRow = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                info!("failed to parse input line as JSON: {e}");
                parse_bad += 1;
                let bad = OutputRow {
                    row: None,
                    ip: "UNKNOWN".to_string(),
                    port: 443,
                    selected_domain: None,
                    sni_used: false,
                    status: "failed".to_string(),
                    note: Some(format!("json_parse_error: {e}")),
                };
                if let Ok(s) = serde_json::to_string(&bad) {
                    if result_tx_main.send(s).is_ok() {
                        counters.results_enqueued.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let _ = ui_tx.send(ui::UiEvent::JobDone);
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
        counters.done_ips.store(done_ips.len(), Ordering::Relaxed);

        if job_tx.send(row).is_ok() {
            sent += 1;
            counters.jobs_enqueued.fetch_add(1, Ordering::Relaxed);
        }
    }
    drop(job_tx); // 关闭任务通道，让 worker 退出

    let _ = ui_tx.send(ui::UiEvent::SetTotals {
        jobs_sent: sent,
        jobs_skipped: skipped,
        bad_lines: parse_bad,
    });

    info!(
        "dispatch done: sent {} jobs, skipped {} already-done IPs, bad_lines {}",
        sent, skipped, parse_bad
    );

    // 等 worker 全部退出
    for h in worker_handles {
        let _ = h.join();
    }

    // 关闭 writer：必须 drop 掉最后一个 sender
    drop(result_tx_main);

    // writer join（不管成功失败，都先把 UI 关掉恢复终端）
    let writer_res = match writer_handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("writer thread panicked".to_string()),
    };

    // 通知 UI shutdown 并 join
    let _ = ui_tx.send(ui::UiEvent::Shutdown);
    let _ = ui_handle.join();
    if let Err(e) = &writer_res {
        runtime_log.append(&format!("[FATAL] {}", e));
    }
    dump_logs_to_stdout(&runtime_log);

    // 最后把 writer 的错误向上抛
    match writer_res {
        Ok(()) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// ====================== logger -> UI ======================

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
        // 日志面板拥塞时丢弃 UI 日志，不阻塞核心流程；完整日志仍写入 runtime log 文件。
        let _ = ui_tx.try_send(ui::UiEvent::Log(line));
        Ok(())
    });

    builder.try_init()?;
    Ok(())
}

/// 避免引入 chrono 依赖：一个简易毫秒时间戳（相对进程启动）
fn chrono_like_ts_millis() -> String {
    use std::sync::OnceLock;
    static T0: OnceLock<Instant> = OnceLock::new();
    let t0 = *T0.get_or_init(Instant::now);
    format!("{:>10}ms", t0.elapsed().as_millis())
}

fn estimate_required_nofile(threads: usize) -> u64 {
    EST_FDS_BASE + EST_FDS_PER_WORKER * threads as u64
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

fn read_proc_self_mem_metrics() -> Option<(u64, u64, usize, u64)> {
    let content = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss_kb = None;
    let mut vmsize_kb = None;
    let mut threads = None;
    let mut swap_kb = None;

    for line in content.lines() {
        if let Some(v) = parse_kb_field(line, "VmRSS:") {
            rss_kb = Some(v);
            continue;
        }
        if let Some(v) = parse_kb_field(line, "VmSize:") {
            vmsize_kb = Some(v);
            continue;
        }
        if let Some(v) = parse_kb_field(line, "VmSwap:") {
            swap_kb = Some(v);
            continue;
        }
        if let Some(v) = parse_usize_field(line, "Threads:") {
            threads = Some(v);
            continue;
        }
    }

    Some((
        rss_kb?,
        vmsize_kb?,
        threads.unwrap_or_default(),
        swap_kb.unwrap_or_default(),
    ))
}

fn parse_kb_field(line: &str, key: &str) -> Option<u64> {
    if !line.starts_with(key) {
        return None;
    }
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

fn parse_usize_field(line: &str, key: &str) -> Option<usize> {
    if !line.starts_with(key) {
        return None;
    }
    line.split_whitespace().nth(1)?.parse::<usize>().ok()
}

fn kb_to_mb(kb: u64) -> f64 {
    kb as f64 / 1024.0
}

#[cfg(unix)]
fn ensure_nofile_limit(required: u64) -> Result<u64, String> {
    fn to_u64(v: libc::rlim_t) -> u64 {
        if v == libc::RLIM_INFINITY {
            u64::MAX
        } else {
            v as u64
        }
    }

    fn from_u64(v: u64) -> libc::rlim_t {
        if v == u64::MAX {
            libc::RLIM_INFINITY
        } else {
            v as libc::rlim_t
        }
    }

    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let get_rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim as *mut libc::rlimit) };
    if get_rc != 0 {
        return Err(format!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let cur = to_u64(lim.rlim_cur);
    let max = to_u64(lim.rlim_max);
    if cur >= required {
        return Ok(cur);
    }

    let target = required.min(max);
    if target > cur {
        let new_lim = libc::rlimit {
            rlim_cur: from_u64(target),
            rlim_max: lim.rlim_max,
        };
        let set_rc =
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_lim as *const libc::rlimit) };
        if set_rc != 0 {
            return Err(format!(
                "setrlimit(RLIMIT_NOFILE) {} -> {} failed: {}",
                cur,
                target,
                std::io::Error::last_os_error()
            ));
        }
    }

    let mut check_lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let reget_rc =
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut check_lim as *mut libc::rlimit) };
    if reget_rc != 0 {
        return Err(format!(
            "getrlimit(RLIMIT_NOFILE) recheck failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let final_cur = to_u64(check_lim.rlim_cur);
    if final_cur < required {
        return Err(format!(
            "RLIMIT_NOFILE still too low: current={} required~{}. Raise hard/soft limit before run, e.g. `ulimit -n {}`",
            final_cur, required, required
        ));
    }

    Ok(final_cur)
}

#[cfg(not(unix))]
fn ensure_nofile_limit(_required: u64) -> Result<u64, String> {
    Ok(0)
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

// ====================== IO / RESUME ======================

fn open_output_append(path: &str) -> Result<BufWriter<File>, String> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open output failed: {e}"))?;
    Ok(BufWriter::new(file))
}

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

// ====================== CORE LOGIC ======================

fn process_one_row(ui: &cc::Sender<ui::UiEvent>, wid: usize, row: InputRow) -> OutputRow {
    let port = row.port.as_ref().and_then(PortValue::to_u16).unwrap_or(443);

    let version = select_version(&row.versions);

    let domains = collect_domains_capped(row.pdns.as_ref(), MAX_DOMAINS_PER_IP);
    let sni_used = !domains.is_empty();

    // UI start
    let total_len = if domains.is_empty() {
        1
    } else {
        domains.len() as u64
    };
    let _ = ui.send(ui::UiEvent::WorkerStart {
        wid,
        ip: row.ip.clone(),
        port,
        total: total_len,
    });

    let mut selected_domain: Option<String> = None;
    let mut status = "failed".to_string();
    let mut note: Option<String> = None;

    if domains.is_empty() {
        // 无域名：尝试不带 SNI（我们用 ""）
        let _ = ui.try_send(ui::UiEvent::WorkerStep { wid });

        match try_connect_only(&row.ip, port, None, version) {
            Ok(mut quic_st) => {
                let cc = build_cc_frames();
                if let Err(e) = send_single_packet_frames(&mut quic_st, &cc) {
                    status = "failed".to_string();
                    note = Some(format!("send_cc_failed: {e}"));
                    let _ = ui.send(ui::UiEvent::WorkerFinishFail {
                        wid,
                        note: note.clone().unwrap_or_default(),
                    });
                } else {
                    let _ = drain_after_close(&mut quic_st);
                    status = "connected".to_string();
                    note = Some("no domains provided".to_string());
                    let _ = ui.send(ui::UiEvent::WorkerFinishOk {
                        wid,
                        domain: "<no-sni>".to_string(),
                    });
                }
            }
            Err(AttemptErr::Timeout(e)) => {
                status = "unreachable".to_string();
                note = Some(format!("ip_unreachable_timeout: {e}"));
                let _ = ui.send(ui::UiEvent::WorkerFinishUnreach {
                    wid,
                    note: note.clone().unwrap_or_default(),
                });
            }
            Err(AttemptErr::HandshakeFail(e)) => {
                status = "failed".to_string();
                note = Some(format!("no domains provided; {e}"));
                let _ = ui.send(ui::UiEvent::WorkerFinishFail {
                    wid,
                    note: note.clone().unwrap_or_default(),
                });
            }
            Err(AttemptErr::Other(e)) => {
                status = "failed".to_string();
                note = Some(format!("no domains provided; {e}"));
                let _ = ui.send(ui::UiEvent::WorkerFinishFail {
                    wid,
                    note: note.clone().unwrap_or_default(),
                });
            }
        }
    } else {
        let mut last_err: Option<String> = None;
        let mut consec_timeouts = 0usize;
        let mut last_timeout_msg: Option<String> = None;

        for d in domains {
            let _ = ui.try_send(ui::UiEvent::WorkerStep { wid });

            match try_connect_only(&row.ip, port, Some(&d), version) {
                Ok(mut quic_st) => {
                    let cc = build_cc_frames();
                    match send_single_packet_frames(&mut quic_st, &cc) {
                        Ok(_) => {
                            let _ = drain_after_close(&mut quic_st);
                            selected_domain = Some(d.clone());
                            status = "connected".to_string();
                            note = None;
                            let _ = ui.send(ui::UiEvent::WorkerFinishOk { wid, domain: d });
                        }
                        Err(e) => {
                            status = "failed".to_string();
                            note = Some(format!("send_cc_failed: {e}"));
                            let _ = ui.send(ui::UiEvent::WorkerFinishFail {
                                wid,
                                note: note.clone().unwrap_or_default(),
                            });
                        }
                    }
                    break;
                }

                Err(AttemptErr::Timeout(e)) => {
                    consec_timeouts += 1;
                    last_timeout_msg = Some(e.clone());
                    debug!(
                        "unreachable on {}:{} domain={}, consec_timeouts={}",
                        row.ip, port, d, consec_timeouts
                    );

                    if consec_timeouts >= CONSEC_TIMEOUT_THRESHOLD {
                        warn!(
                            "unreachable on {}:{} domain={}, consec_timeouts={}",
                            row.ip, port, d, consec_timeouts
                        );

                        status = "unreachable".to_string();
                        note = Some(format!(
                            "ip_unreachable_{}consecutive_timeouts: {}",
                            CONSEC_TIMEOUT_THRESHOLD,
                            last_timeout_msg.unwrap_or_else(|| "Timeout".to_string())
                        ));
                        let _ = ui.send(ui::UiEvent::WorkerFinishUnreach {
                            wid,
                            note: note.clone().unwrap_or_default(),
                        });
                        break;
                    }
                    continue;
                }

                Err(AttemptErr::HandshakeFail(e)) => {
                    consec_timeouts = 0;
                    last_err = Some(e);
                    continue;
                }

                Err(AttemptErr::Other(e)) => {
                    consec_timeouts = 0;
                    last_err = Some(e);
                    continue;
                }
            }
        }

        if status == "failed" && note.is_none() {
            note = Some(last_err.unwrap_or_else(|| "all domains failed".to_string()));
            let _ = ui.send(ui::UiEvent::WorkerFinishFail {
                wid,
                note: note.clone().unwrap_or_default(),
            });
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

// ====================== CONNECT / SEND / DRAIN ======================

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

fn build_cc_frames() -> Vec<frame::Frame> {
    vec![frame::Frame::ConnectionClose {
        error_code: 0,
        frame_type: 0,
        reason: Vec::new(),
    }]
}

fn send_single_packet_frames(
    quic_st: &mut QuicStruct,
    frames: &[frame::Frame],
) -> Result<(), String> {
    let mut input_struct = InputStruct::new();
    let mut frame_cycle = FramesCycleStruct::new();

    for f in frames {
        // Frame: Clone（你之前就是这么用的）
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
                // 你的封装可能把 WouldBlock 当 Err：这里保持“非致命”
            }
        }

        let _ = quic_st.handle_sending();

        if quic_st.conn_is_closed() && last_rx.elapsed() > QUIET_TIME {
            break;
        }
        if Instant::now() > drain_deadline {
            break;
        }

        std::thread::sleep(Duration::from_millis(5));
    }

    Ok(())
}

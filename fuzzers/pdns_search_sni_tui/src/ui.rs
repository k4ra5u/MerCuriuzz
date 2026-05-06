use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use crossbeam_channel as cc;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};

use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

#[derive(Debug, Clone)]
pub enum UiEvent {
    WorkerStart {
        wid: usize,
        ip: String,
        port: u16,
        total: u64,
    },
    WorkerStep {
        wid: usize,
    },
    WorkerFinishOk {
        wid: usize,
        domain: String,
    },
    WorkerFinishFail {
        wid: usize,
        note: String,
    },
    WorkerFinishUnreach {
        wid: usize,
        note: String,
    },
    WorkerIdle {
        wid: usize,
    },

    JobDone,
    SetTotals {
        jobs_sent: usize,
        jobs_skipped: usize,
        bad_lines: usize,
    },

    Log(String),
    Info(String),
    Fatal(String),

    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WStatus {
    Idle,
    Running,
    Ok,
    Fail,
    Unreach,
}

#[derive(Debug, Clone)]
struct WorkerState {
    prefix: String, // Txx
    target: String, // ip:port
    msg: String,    // running/ok/fail info
    len: u64,
    pos: u64,
    status: WStatus,
    started_at: Option<Instant>,
    finished_at: Option<Instant>,
}

#[derive(Debug)]
struct AppState {
    cols: usize,
    log_lines: u16,
    show_ip: bool,
    show_time: bool,

    workers: Vec<WorkerState>,

    jobs_done: usize,
    jobs_sent: usize,
    jobs_skipped: usize,
    bad_lines: usize,

    logs: VecDeque<String>,
    info: Option<String>,
    fatal: Option<String>,

    scroll_row: usize, // grid 垂直滚动（按行）
}

struct TermGuard;

impl TermGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stderr(), EnterAlternateScreen, cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stderr(), LeaveAlternateScreen, cursor::Show);
    }
}

pub fn spawn_ui_thread(
    threads: usize,
    cols: usize,
    log_lines: u16,
    show_ip: bool,
    show_time: bool,
    rx: cc::Receiver<UiEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = run_ui(threads, cols, log_lines, show_ip, show_time, rx);
    })
}

fn run_ui(
    threads: usize,
    cols: usize,
    log_lines: u16,
    show_ip: bool,
    show_time: bool,
    rx: cc::Receiver<UiEvent>,
) -> io::Result<()> {
    let _guard = TermGuard::enter()?;

    let backend = CrosstermBackend::new(io::stderr());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = AppState {
        cols: cols.max(1),
        log_lines,
        show_ip,
        show_time,

        workers: (0..threads)
            .map(|i| WorkerState {
                prefix: format!("T{:02}", i),
                target: String::new(),
                msg: "idle".to_string(),
                len: 1,
                pos: 0,
                status: WStatus::Idle,
                started_at: None,
                finished_at: None,
            })
            .collect(),

        jobs_done: 0,
        jobs_sent: 0,
        jobs_skipped: 0,
        bad_lines: 0,

        logs: VecDeque::with_capacity(256),
        info: None,
        fatal: None,

        scroll_row: 0,
    };

    let tick = Duration::from_millis(100);

    loop {
        // 1) 消费 UI 事件（尽量多吃）
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, UiEvent::Shutdown) {
                terminal.clear()?;
                return Ok(());
            }
            handle_event(&mut app, ev);
        }

        // 2) 键盘：只做滚动（不影响主流程）
        while event::poll(Duration::from_millis(0))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Up => app.scroll_row = app.scroll_row.saturating_sub(1),
                    KeyCode::Down => app.scroll_row = app.scroll_row.saturating_add(1),
                    KeyCode::PageUp => app.scroll_row = app.scroll_row.saturating_sub(10),
                    KeyCode::PageDown => app.scroll_row = app.scroll_row.saturating_add(10),
                    KeyCode::Home => app.scroll_row = 0,
                    KeyCode::End => {
                        app.scroll_row = total_rows(app.workers.len(), app.cols).saturating_sub(1)
                    }
                    _ => {}
                }
            }
        }

        // 3) draw
        terminal.draw(|f| {
            let size = f.size();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Min(1),
                    Constraint::Length(app.log_lines.max(3)),
                ])
                .split(size);

            // header
            let header = make_header(&app);
            f.render_widget(
                Paragraph::new(Line::from(header)).block(Block::default().borders(Borders::BOTTOM)),
                chunks[0],
            );

            // grid
            draw_grid(f, chunks[1], &mut app);

            // logs
            draw_logs(f, chunks[2], &app);
        })?;

        std::thread::sleep(tick);
    }
}

fn handle_event(app: &mut AppState, ev: UiEvent) {
    match ev {
        UiEvent::WorkerStart {
            wid,
            ip,
            port,
            total,
        } => {
            if let Some(w) = app.workers.get_mut(wid) {
                w.status = WStatus::Running;
                w.pos = 0;
                w.len = total.max(1);
                w.target = format!("{}:{}", ip, port);
                w.msg = "running".to_string();
                w.started_at = Some(Instant::now());
                w.finished_at = None;
            }
        }
        UiEvent::WorkerStep { wid } => {
            if let Some(w) = app.workers.get_mut(wid) {
                if w.status == WStatus::Running {
                    w.pos = (w.pos + 1).min(w.len);
                }
            }
        }
        UiEvent::WorkerFinishOk { wid, domain } => {
            if let Some(w) = app.workers.get_mut(wid) {
                w.status = WStatus::Ok;
                w.pos = w.len;
                w.msg = format!("OK   sni={}", domain);
                w.finished_at = Some(Instant::now());
            }
        }
        UiEvent::WorkerFinishFail { wid, note } => {
            if let Some(w) = app.workers.get_mut(wid) {
                w.status = WStatus::Fail;
                w.pos = w.len;
                w.msg = truncate_for_msg(&format!("FAIL {}", note), 60);
                w.finished_at = Some(Instant::now());
            }
        }
        UiEvent::WorkerFinishUnreach { wid, note } => {
            if let Some(w) = app.workers.get_mut(wid) {
                w.status = WStatus::Unreach;
                w.pos = w.len;
                w.msg = truncate_for_msg(&format!("UNRE {}", note), 60);
                w.finished_at = Some(Instant::now());
            }
        }
        UiEvent::WorkerIdle { wid } => {
            if let Some(w) = app.workers.get_mut(wid) {
                w.status = WStatus::Idle;
                w.pos = 0;
                w.len = 1;
                w.target.clear();
                w.msg = "idle".to_string();
                w.started_at = None;
                w.finished_at = None;
            }
        }
        UiEvent::JobDone => {
            app.jobs_done += 1;
        }
        UiEvent::SetTotals {
            jobs_sent,
            jobs_skipped,
            bad_lines,
        } => {
            app.jobs_sent = jobs_sent;
            app.jobs_skipped = jobs_skipped;
            app.bad_lines = bad_lines;
        }
        UiEvent::Log(line) => push_log(app, line),
        UiEvent::Info(s) => {
            app.info = Some(s.clone());
            push_log(app, format!("[INFO] {}", s));
        }
        UiEvent::Fatal(s) => {
            app.fatal = Some(s.clone());
            push_log(app, format!("[FATAL] {}", s));
        }
        UiEvent::Shutdown => {}
    }
}

fn push_log(app: &mut AppState, line: String) {
    const MAX_LOGS: usize = 300;
    if app.logs.len() >= MAX_LOGS {
        app.logs.pop_front();
    }
    app.logs.push_back(line);
}

fn make_header(app: &AppState) -> String {
    let total_rows = total_rows(app.workers.len(), app.cols);
    let info = app.info.as_deref().unwrap_or("");
    let fatal = app.fatal.as_deref().unwrap_or("");

    format!(
        "ALL  done={} sent={} skipped={} bad={}  grid_rows={}  scroll_row={}  {} {}",
        app.jobs_done,
        app.jobs_sent,
        app.jobs_skipped,
        app.bad_lines,
        total_rows,
        app.scroll_row,
        if !info.is_empty() { info } else { "" },
        if !fatal.is_empty() { fatal } else { "" },
    )
}

fn total_rows(n_workers: usize, cols: usize) -> usize {
    if n_workers == 0 {
        return 0;
    }
    (n_workers + cols - 1) / cols
}

fn draw_grid(f: &mut ratatui::Frame, area: Rect, app: &mut AppState) {
    let cols = app.cols;
    let n = app.workers.len();
    let total_rows = total_rows(n, cols);

    // 可显示的行数（每个 worker 一行）
    let visible_rows = area.height as usize;
    if visible_rows == 0 {
        return;
    }

    // scroll clamp
    if total_rows > visible_rows {
        let max_scroll = total_rows - visible_rows;
        if app.scroll_row > max_scroll {
            app.scroll_row = max_scroll;
        }
    } else {
        app.scroll_row = 0;
    }

    // 每列宽度（尽量均分余数）
    let base_w = area.width / cols as u16;
    let rem = area.width % cols as u16;

    for vr in 0..visible_rows {
        let row_idx = app.scroll_row + vr;
        if row_idx >= total_rows {
            break;
        }

        let y = area.y + vr as u16;

        let mut x = area.x;
        for c in 0..cols {
            let w = base_w + if (c as u16) < rem { 1 } else { 0 };
            if w == 0 {
                continue;
            }

            let idx = row_idx * cols + c;
            let cell_rect = Rect {
                x,
                y,
                width: w,
                height: 1,
            };

            if idx < n {
                let ws = &app.workers[idx];
                let line = format_worker_cell(ws, w as usize, app.show_ip, app.show_time);
                let style = match ws.status {
                    WStatus::Idle => Style::default().fg(Color::DarkGray),
                    WStatus::Running => Style::default().fg(Color::White),
                    WStatus::Ok => Style::default().fg(Color::Green),
                    WStatus::Fail => Style::default().fg(Color::Red),
                    WStatus::Unreach => Style::default().fg(Color::Yellow),
                };

                f.render_widget(Paragraph::new(line).style(style), cell_rect);
            } else {
                // 空白 cell
                f.render_widget(Paragraph::new(""), cell_rect);
            }

            x = x.saturating_add(w);
        }
    }
}

fn draw_logs(f: &mut ratatui::Frame, area: Rect, app: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    // 只展示最后 N 行
    let want = area.height as usize;
    let start = app.logs.len().saturating_sub(want);
    for s in app.logs.iter().skip(start) {
        lines.push(Line::from(s.as_str()));
    }

    let block = Block::default().borders(Borders::TOP).title("logs");
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn format_worker_cell(ws: &WorkerState, width: usize, show_ip: bool, show_time: bool) -> String {
    // 目标格式（与 indicatif 类似）：
    // T36 13.227.227.167:443 [█████░░░]  3/6
    //
    // 但在网格里每个 cell 宽度有限，因此 bar/msg 会自适应截断/缩短。

    if width == 0 {
        return String::new();
    }

    let prefix_w = 4usize; // "T36 " 里 Txx 占 3~4
    // 固定开销：
    // prefix(4) + ' '(1) + msg + ' '(1) + '[' + bar + ']' + ' '(1) + poslen(9)
    // => msg + bar + 18
    let fixed = 18usize;
    let avail = width.saturating_sub(fixed);

    let min_msg = if !show_ip && !show_time {
        4usize
    } else {
        8usize
    };
    let msg_cap = if !show_ip && !show_time {
        16usize
    } else {
        38usize
    };

    let display_msg = build_display_msg(ws, show_ip, show_time);
    let desired_msg_w = count_chars(&display_msg).clamp(min_msg, msg_cap);

    let (msg_w, bar_w) = if avail == 0 {
        (0, 0)
    } else {
        let min_msg_w = min_msg.min(avail);
        let mut msg_w = desired_msg_w.clamp(min_msg_w, avail);

        // 只要还有空间，至少给进度条保留 1 列，避免因 1 列宽差导致样式突变（有的格子有 bar，有的变成 []）。
        if avail > min_msg_w {
            let max_msg_with_bar = avail - 1;
            msg_w = msg_w.min(max_msg_with_bar).max(min_msg_w);
        }

        (msg_w, avail.saturating_sub(msg_w))
    };

    // msg 适配
    let msg = fit_left(&display_msg, msg_w);

    // bar
    let bar = if bar_w == 0 {
        String::new()
    } else {
        let len = ws.len.max(1);
        let pos = ws.pos.min(len);
        let filled = ((pos as u128 * bar_w as u128) / len as u128) as usize;
        let filled = filled.min(bar_w);
        let empty = bar_w.saturating_sub(filled);
        let mut s = String::with_capacity(bar_w);
        s.push_str(&"█".repeat(filled));
        s.push_str(&"░".repeat(empty));
        s
    };

    let pos = ws.pos.min(ws.len.max(1));
    let len = ws.len.max(1);

    let mut line = format!(
        "{:<prefix_w$} {} [{}] {:>4}/{:<4}",
        ws.prefix,
        msg,
        bar,
        pos,
        len,
        prefix_w = prefix_w
    );

    // 填满 cell 宽度，避免残影
    let cur = line.chars().count();
    if cur < width {
        line.push_str(&" ".repeat(width - cur));
    } else if cur > width {
        line = truncate_to_width(&line, width);
    }

    line
}

fn elapsed_secs(ws: &WorkerState) -> Option<f64> {
    let start = ws.started_at?;
    let end = ws.finished_at.unwrap_or_else(Instant::now);
    Some(end.duration_since(start).as_secs_f64())
}

fn build_display_msg(ws: &WorkerState, show_ip: bool, show_time: bool) -> String {
    // 同一位置显示“目标或状态”：
    // - running 且启用 show_ip 时显示 ip:port
    // - 其它情况显示状态文本（idle/OK/FAIL...）
    let mut display_msg = match ws.status {
        WStatus::Running if show_ip && !ws.target.is_empty() => ws.target.clone(),
        _ => ws.msg.clone(),
    };

    if show_time {
        if let Some(elapsed) = elapsed_secs(ws) {
            display_msg.push_str(&format!(" t={elapsed:.1}s"));
        }
    }

    display_msg
}

fn count_chars(s: &str) -> usize {
    s.chars().count()
}

fn fit_left(s: &str, width: usize) -> String {
    let mut out = truncate_to_width(s, width);
    let cur = out.chars().count();
    if cur < width {
        out.push_str(&" ".repeat(width - cur));
    }
    out
}

fn truncate_for_msg(s: &str, max_chars: usize) -> String {
    truncate_to_width(s, max_chars)
}

fn truncate_to_width(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max_chars {
            break;
        }
        out.push(ch);
    }
    out
}

use std::borrow::Cow;
use std::cmp::max;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::Path;

use libafl::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{DifferentialObserver, Observer, ObserversTuple},
};
use libafl_bolts::tuples::{Handle, Handled, MatchNameRef};
use libafl_bolts::{Error, Named};
use log::{info, warn};
use num_traits::abs;
use serde::{Deserialize, Serialize};

use super::HasRecordRemote;

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct MemSnapshot {
    pub primary_bytes: i64,
    pub rw_map_bytes: i64,
    pub vm_rss_kb: i64,
    pub rss_anon_kb: i64,
    pub pss_kb: i64,
    pub private_dirty_kb: i64,
    pub fd_count: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum MemObserverState {
    OK,
    FirMemLeak,
    SecMemLeak,
    BothMemLeak,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemObserver {
    pub name: Cow<'static, str>,
    pub record_remote: bool,
    pub pid: u32,
    pub initial_mem: i64,
    pub before_mem: i64,
    pub after_mem: i64,
    pub allowed_mem: i64,
    pub initial_snapshot: MemSnapshot,
    pub before_snapshot: MemSnapshot,
    pub after_snapshot: MemSnapshot,
}

impl MemObserver {
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            pid: 0,
            initial_mem: 0,
            before_mem: 0,
            after_mem: 0,
            allowed_mem: 0,
            initial_snapshot: MemSnapshot::default(),
            before_snapshot: MemSnapshot::default(),
            after_snapshot: MemSnapshot::default(),
        }
    }

    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }

    pub fn set_init_mem(&mut self, initial_mem: i64) {
        self.initial_mem = initial_mem;
        self.initial_snapshot.primary_bytes = initial_mem;
    }

    pub fn set_before_mem(&mut self, before_mem: i64) {
        self.before_mem = before_mem;
        self.before_snapshot.primary_bytes = before_mem;
    }

    pub fn set_after_mem(&mut self, after_mem: i64) {
        self.after_mem = after_mem;
        self.after_snapshot.primary_bytes = after_mem;
    }

    pub fn sync_from(&mut self, other: &MemObserver) {
        self.initial_mem = other.initial_mem;
        self.before_mem = other.before_mem;
        self.after_mem = other.after_mem;
        self.allowed_mem = other.allowed_mem;
        self.initial_snapshot = other.initial_snapshot.clone();
        self.before_snapshot = other.before_snapshot.clone();
        self.after_snapshot = other.after_snapshot.clone();
    }

    fn parse_kb_field(line: &str, key: &str) -> Option<i64> {
        if !line.starts_with(key) {
            return None;
        }

        line.split_whitespace().nth(1)?.parse::<i64>().ok()
    }

    fn parse_rw_memory_range(line: &str) -> Option<(i64, i64)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let range = parts[0];
        let permissions = parts[1];
        if !permissions.contains('w') {
            return None;
        }

        let range_parts: Vec<&str> = range.split('-').collect();
        if range_parts.len() != 2 {
            return None;
        }

        let start = i64::from_str_radix(range_parts[0], 16).ok()?;
        let end = i64::from_str_radix(range_parts[1], 16).ok()?;
        Some((start, end))
    }

    fn read_rw_map_bytes(pid: u32) -> io::Result<i64> {
        let map_file = format!("/proc/{pid}/maps");
        let file = File::open(map_file)?;
        let reader = io::BufReader::new(file);
        let mut total = 0_i64;

        for cur_line in reader.lines() {
            let line = cur_line?;
            if let Some((start, end)) = Self::parse_rw_memory_range(&line) {
                total += end - start;
            }
        }

        Ok(total)
    }

    fn read_status_fields(pid: u32) -> io::Result<(i64, i64)> {
        let status_file = format!("/proc/{pid}/status");
        let content = fs::read_to_string(status_file)?;
        let mut vm_rss_kb = 0_i64;
        let mut rss_anon_kb = 0_i64;

        for line in content.lines() {
            if let Some(value) = Self::parse_kb_field(line, "VmRSS:") {
                vm_rss_kb = value;
                continue;
            }
            if let Some(value) = Self::parse_kb_field(line, "RssAnon:") {
                rss_anon_kb = value;
            }
        }

        Ok((vm_rss_kb, rss_anon_kb))
    }

    fn read_smaps_rollup_fields(pid: u32) -> (i64, i64) {
        let smaps_rollup = format!("/proc/{pid}/smaps_rollup");
        let content = match fs::read_to_string(smaps_rollup) {
            Ok(content) => content,
            Err(_) => return (0, 0),
        };

        let mut pss_kb = 0_i64;
        let mut private_dirty_kb = 0_i64;

        for line in content.lines() {
            if let Some(value) = Self::parse_kb_field(line, "Pss:") {
                pss_kb = value;
                continue;
            }
            if let Some(value) = Self::parse_kb_field(line, "Private_Dirty:") {
                private_dirty_kb = value;
            }
        }

        (pss_kb, private_dirty_kb)
    }

    fn read_fd_count(pid: u32) -> i64 {
        let fd_dir = format!("/proc/{pid}/fd");
        match fs::read_dir(fd_dir) {
            Ok(entries) => entries.count() as i64,
            Err(_) => 0,
        }
    }

    fn snapshot_for_pid(pid: u32) -> io::Result<MemSnapshot> {
        let rw_map_bytes = Self::read_rw_map_bytes(pid).unwrap_or_default();
        let (vm_rss_kb, rss_anon_kb) = Self::read_status_fields(pid)?;
        let (pss_kb, private_dirty_kb) = Self::read_smaps_rollup_fields(pid);
        let fd_count = Self::read_fd_count(pid);

        let primary_bytes = if vm_rss_kb > 0 {
            vm_rss_kb.saturating_mul(1024)
        } else {
            rw_map_bytes
        };

        Ok(MemSnapshot {
            primary_bytes,
            rw_map_bytes,
            vm_rss_kb,
            rss_anon_kb,
            pss_kb,
            private_dirty_kb,
            fd_count,
        })
    }

    pub fn reset_measurement(&mut self) {
        self.initial_mem = 0;
        self.before_mem = 0;
        self.after_mem = 0;
        self.allowed_mem = 0;
        self.initial_snapshot = MemSnapshot::default();
        self.before_snapshot = MemSnapshot::default();
        self.after_snapshot = MemSnapshot::default();
    }

    fn reset_after_failure(&mut self) {
        self.reset_measurement();
        self.pid = 0;
    }

    fn set_before_snapshot(&mut self, snapshot: MemSnapshot) {
        self.before_mem = snapshot.primary_bytes;
        self.before_snapshot = snapshot.clone();
        if self.initial_mem == 0 {
            self.initial_mem = snapshot.primary_bytes;
            self.initial_snapshot = snapshot;
        }
    }

    fn set_after_snapshot(&mut self, snapshot: MemSnapshot) {
        self.after_mem = snapshot.primary_bytes;
        self.after_snapshot = snapshot;
        if self.allowed_mem == 0 {
            self.allowed_mem = max(self.after_mem - self.initial_mem, 50_000);
        }
    }

    pub fn capture_current_snapshot(&self) -> io::Result<MemSnapshot> {
        if self.pid == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "pid is not set"));
        }

        Self::snapshot_for_pid(self.pid)
    }

    pub fn capture_before_snapshot(&mut self) -> bool {
        match self.capture_current_snapshot() {
            Ok(snapshot) => {
                self.set_before_snapshot(snapshot);
                true
            }
            Err(err) => {
                warn!(
                    "Failed to capture before-memory snapshot for pid {}: {}",
                    self.pid, err
                );
                self.reset_after_failure();
                false
            }
        }
    }

    pub fn capture_after_snapshot(&mut self) -> bool {
        if !self.judge_proc_exist() {
            self.after_mem = self.before_mem;
            self.after_snapshot = self.before_snapshot.clone();
            return true;
        }

        match self.capture_current_snapshot() {
            Ok(snapshot) => {
                self.set_after_snapshot(snapshot);
                true
            }
            Err(err) => {
                warn!(
                    "Failed to capture after-memory snapshot for pid {}: {}",
                    self.pid, err
                );
                self.reset_after_failure();
                false
            }
        }
    }

    pub fn judge_proc_exist(&self) -> bool {
        if self.pid == 0 {
            return false;
        }

        Path::new(&format!("/proc/{}", self.pid)).exists()
    }

    fn bytes_to_mib(bytes: i64) -> f64 {
        bytes as f64 / 1024.0 / 1024.0
    }

    fn kb_to_mib(kb: i64) -> f64 {
        kb as f64 / 1024.0
    }

    pub fn detailed_report(&self, label: &str) -> String {
        let before = &self.before_snapshot;
        let after = &self.after_snapshot;

        format!(
            concat!(
                "{label}: metric=VmRSS before={before_mem:.2} MiB after={after_mem:.2} MiB delta={delta_mem:+.2} MiB",
                " | RssAnon={before_rss_anon:.2}->{after_rss_anon:.2} MiB delta={delta_rss_anon:+.2} MiB",
                " | Pss={before_pss:.2}->{after_pss:.2} MiB delta={delta_pss:+.2} MiB",
                " | Private_Dirty={before_dirty:.2}->{after_dirty:.2} MiB delta={delta_dirty:+.2} MiB",
                " | fd_count={before_fd}->{after_fd} delta={delta_fd:+}",
                " | rw_maps={before_rw:.2}->{after_rw:.2} MiB delta={delta_rw:+.2} MiB"
            ),
            label = label,
            before_mem = Self::bytes_to_mib(self.before_mem),
            after_mem = Self::bytes_to_mib(self.after_mem),
            delta_mem = Self::bytes_to_mib(self.after_mem - self.before_mem),
            before_rss_anon = Self::kb_to_mib(before.rss_anon_kb),
            after_rss_anon = Self::kb_to_mib(after.rss_anon_kb),
            delta_rss_anon = Self::kb_to_mib(after.rss_anon_kb - before.rss_anon_kb),
            before_pss = Self::kb_to_mib(before.pss_kb),
            after_pss = Self::kb_to_mib(after.pss_kb),
            delta_pss = Self::kb_to_mib(after.pss_kb - before.pss_kb),
            before_dirty = Self::kb_to_mib(before.private_dirty_kb),
            after_dirty = Self::kb_to_mib(after.private_dirty_kb),
            delta_dirty =
                Self::kb_to_mib(after.private_dirty_kb - before.private_dirty_kb),
            before_fd = before.fd_count,
            after_fd = after.fd_count,
            delta_fd = after.fd_count - before.fd_count,
            before_rw = Self::bytes_to_mib(before.rw_map_bytes),
            after_rw = Self::bytes_to_mib(after.rw_map_bytes),
            delta_rw = Self::bytes_to_mib(after.rw_map_bytes - before.rw_map_bytes),
        )
    }

    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() && self.pid != 0 {
            let _ = self.capture_before_snapshot();
        }

        Ok(())
    }

    pub fn post_execv(&mut self, _exit_kind: &ExitKind) -> Result<(), Error> {
        if !self.record_remote() && self.pid != 0 {
            let _ = self.capture_after_snapshot();
        }

        Ok(())
    }
}

impl<S> Observer<S> for MemObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() && self.pid != 0 {
            let _ = self.capture_before_snapshot();
        }

        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() && self.pid != 0 {
            let _ = self.capture_after_snapshot();
        }

        Ok(())
    }
}

impl Named for MemObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialMemObserver {
    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<MemObserver>,
    first_observer: MemObserver,
    second_observer: MemObserver,
    second_ob_ref: Handle<MemObserver>,
    name: Cow<'static, str>,
    judge_type: MemObserverState,
}

impl DifferentialMemObserver {
    pub fn new(first: &mut MemObserver, second: &mut MemObserver) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            first_observer: MemObserver::new("fake"),
            second_observer: MemObserver::new("fake"),
            second_ob_ref: second.handle(),
            judge_type: MemObserverState::OK,
        }
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn second_name(&self) -> &str {
        &self.second_name
    }

    pub fn judge_type(&self) -> &MemObserverState {
        &self.judge_type
    }

    pub fn perform_judge(&mut self) {
        let mut first_mem_rev = false;
        let mut second_mem_rev = false;

        if self.first_observer.after_mem > self.first_observer.before_mem {
            let first_mem_diff = self.first_observer.after_mem - self.first_observer.before_mem;
            if first_mem_diff > self.first_observer.allowed_mem * 3 {
                self.judge_type = MemObserverState::FirMemLeak;
            }
        } else {
            first_mem_rev = true;
        }

        if self.second_observer.after_mem > self.second_observer.before_mem {
            let second_mem_diff = self.second_observer.after_mem - self.second_observer.before_mem;
            if second_mem_diff > self.second_observer.allowed_mem * 3 {
                self.judge_type = MemObserverState::SecMemLeak;
            }
        } else {
            second_mem_rev = true;
        }

        if !first_mem_rev && !second_mem_rev {
            let first_mem_diff = self.first_observer.after_mem - self.first_observer.before_mem;
            let second_mem_diff = self.second_observer.after_mem - self.second_observer.before_mem;
            let mem_abs = abs(first_mem_diff - second_mem_diff);
            let allow_mem_diff_abs =
                abs(self.first_observer.allowed_mem - self.second_observer.allowed_mem);

            if first_mem_diff > second_mem_diff
                && (mem_abs > 500_000 || mem_abs > 3 * allow_mem_diff_abs)
            {
                if self.judge_type == MemObserverState::SecMemLeak {
                    self.judge_type = MemObserverState::BothMemLeak;
                } else {
                    self.judge_type = MemObserverState::FirMemLeak;
                }
            }

            if second_mem_diff > first_mem_diff
                && (mem_abs > 500_000 || mem_abs > 3 * allow_mem_diff_abs)
            {
                if self.judge_type == MemObserverState::FirMemLeak {
                    self.judge_type = MemObserverState::BothMemLeak;
                } else {
                    self.judge_type = MemObserverState::SecMemLeak;
                }
            }
        }

        info!("{}", self.first_observer.detailed_report(self.first_name()));
        info!(
            "{}",
            self.second_observer.detailed_report(self.second_name())
        );
        self.first_observer = MemObserver::new("fake");
        self.second_observer = MemObserver::new("fake");
    }
}

impl Named for DifferentialMemObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialMemObserver where S: UsesInput {}

impl<OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for DifferentialMemObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = MemObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = MemObserverState::OK;
        Ok(())
    }

    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        let first_observer = observers.get(&self.first_ob_ref).unwrap();
        self.first_observer = first_observer.clone();
        if self.second_observer.name() != "fake" {
            self.perform_judge();
        }
        Ok(())
    }

    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        let second_observer = observers.get(&self.second_ob_ref).unwrap();
        self.second_observer = second_observer.clone();
        if self.first_observer.name() != "fake" {
            self.perform_judge();
        }
        Ok(())
    }
}

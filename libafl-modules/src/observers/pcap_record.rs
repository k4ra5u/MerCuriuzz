use std::borrow::Cow;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use chrono::{DateTime, FixedOffset, TimeDelta, TimeZone, Utc};
use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::{Handle, Handled};
use libafl_bolts::{Error, Named,tuples::MatchName,tuples::MatchNameRef};
use log::info;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use libafl::{
    observers::{DifferentialObserver, Observer, ObserversTuple},
};
use crate::inputstruct::*;

use super::HasRecordRemote;


pub fn get_time_with_tshark_format() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mili_secs = dur.as_secs() * 1000 + dur.subsec_millis() as u64;
    let dt_utc = Utc.timestamp_millis_opt(mili_secs as i64).single().unwrap();

    // 定义 CST 时区：UTC+8
    let cst = FixedOffset::east(8 * 3600);
    let dt_cst = dt_utc.with_timezone(&cst);

    dt_cst.format("%Y-%m-%dT%H:%M:%S%.3f").to_string()
}

pub fn gen_pcap_path() -> String {
    let rand_str: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let pcaps_dir = env::var("PCAPS_DIR").unwrap();
    format!("{}/{}.pcap", pcaps_dir, rand_str)
}

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct PcapRecord {
    pub start_time: String,
    pub end_time: String,
    pub name: String,
    pub port: u16,
}

impl PcapRecord {
    /// Creates a new [`PcapRecord`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: String::new(),
            end_time: String::new(),
            name: String::new(),
            port: 0,
        }
    }
}

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct PcapObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub port: u16,
    pub new_record: PcapRecord,
}

impl PcapObserver {
    /// Creates a new [`PcapObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            port:0,
            new_record: PcapRecord::new(),
        }
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {

        if !self.record_remote() {
            // self.start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3];
            self.new_record.start_time = get_time_with_tshark_format();
            self.new_record.name = gen_pcap_path();
            self.new_record.port = self.port;

            // let _ = Command::new("sudo")
            // .arg("touch")
            // .arg(&self.new_record.name)
            // .output() // 捕获 `touch` 的输出
            // .expect("Failed to create empty pcap file");
        }


        Ok(())
    }

    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            // info!("post_exec of PcapObserver: {:?}", self);
            self.new_record.end_time = get_time_with_tshark_format();
        }

        Ok(())
    }
}

impl<S> Observer<S> for PcapObserver
where
    S: UsesInput,
{

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {

        if !self.record_remote() {
            // self.start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3];
            self.new_record.start_time = get_time_with_tshark_format();
            self.new_record.name = gen_pcap_path();
            self.new_record.port = self.port;

            // let _ = Command::new("sudo")
            // .arg("touch")
            // .arg(&self.new_record.name)
            // .output() // 捕获 `touch` 的输出
            // .expect("Failed to create empty pcap file");
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
            // info!("post_exec of PcapObserver: {:?}", self);
            self.new_record.end_time = get_time_with_tshark_format();
        }

        Ok(())
    }
}

impl Named for PcapObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}


#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DifferentialPcapObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<PcapObserver>,
    first_observer: PcapObserver,
    second_observer: PcapObserver,
    second_ob_ref: Handle<PcapObserver>,
    name: Cow<'static, str>,
    pub first_pcap_record: PcapRecord,
    pub second_pcap_record: PcapRecord,
}

impl DifferentialPcapObserver {
    /// Create a new `DifferentialPcapObserver`.
    pub fn new (
        first: &mut PcapObserver,
        second: &mut PcapObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            first_observer: PcapObserver::new("fake"),
            second_observer: PcapObserver::new("fake"),
            second_ob_ref: second.handle(),
            first_pcap_record: PcapRecord::new(),
            second_pcap_record: PcapRecord::new(),

        }
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn second_name(&self) -> &str {
        &self.second_name
    }

    pub fn perform_judge (&mut self) {
        self.first_pcap_record = self.first_observer.new_record.clone();
        self.second_pcap_record = self.second_observer.new_record.clone();
        info!("Fir:{:?}", self.first_observer);
        info!("Sec:{:?}", self.second_observer);
        self.first_observer = PcapObserver::new("fake");
        self.second_observer = PcapObserver::new("fake");

    }
}

impl Named for DifferentialPcapObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for DifferentialPcapObserver where S: UsesInput {}

impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialPcapObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
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
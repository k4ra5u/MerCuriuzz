use std::borrow::Cow;
use libafl::inputs::HasMutatorBytes;
use libafl_bolts::ownedref::OwnedMutPtr;
use quiche::frame::Frame;
use quiche::stream::RangeBuf;
use std::{mem};
use num_traits::abs;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, FrameWithPkn, Header};
use crate::inputstruct::*;
use libafl_bolts::tuples::{Handle, Handled};
use libafl_bolts::{Error, Named,tuples::MatchName,tuples::MatchNameRef};
use libafl::{
    observers::{DifferentialObserver, Observer, ObserversTuple},
};

use super::HasRecordRemote;

#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub struct Frame_info {
    pub frame: frame::Frame,
    pub frame_num: usize,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct Ack_range {
    start: u64,
    end: u64,
}

#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub enum CtrlObserverState {
    OK = 0,
    CrtlFrame1TypeMismatch = 1,
    CrtlFrame2TypeMismatch = 1 << 1,
    CtrlFrameTypeNumMismatch = 1 << 2,
    CtrlFrameContentMismatch = 1 << 3,
}
#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub enum DataObserverState {
    OK = 0,
    DataFrame1TypeMismatch = 1,
    DataFrame2TypeMismatch = 1 << 1,
    DataFrameTypeNumMismatch = 1 << 2,
    DataFrameCryptoContentMismatch = 1 << 3,
    DataFrameStreamContentMismatch = 1 << 4,
    DataFrameStreamContentLenMismatch = 1 << 5,
    DataFramePRContentMismatch = 1 << 6,
    DataFrameDgramContentMismatch = 1 << 7,

}
#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub enum ACKObserverState {
    OK = 0,
    ACKRangeMismatch = 1,
}
#[derive(Debug, Serialize, Deserialize,Clone,PartialEq)]
pub enum OtherObserverState {
    OK = 0,
    OtherFrameTypeMismatch = 1 ,
    OtherFrameTypeNumMismatch = 1 << 2,
    OtherFrameContentMismatch = 1 << 3,

}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecvPktNumObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub send_pkts: u64,
    pub recv_pkts: u64,
    pub send_bytes: u64,
    pub recv_bytes: u64,
}
impl RecvPktNumObserver {
    /// Creates a new [`RecvPktNumObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            send_pkts: 0,
            recv_pkts: 0,
            send_bytes: 0,
            recv_bytes: 0,
        }
    }
    pub fn get_send_pkts(&self) -> u64 {
        self.send_pkts
    }
    pub fn get_recv_pkts(&self) -> u64 {
        self.recv_pkts
    }
    pub fn get_send_bytes(&self) -> u64 {
        self.send_bytes
    }
    pub fn get_recv_bytes(&self) -> u64 {
        self.recv_bytes
    }
    pub fn set_send_pkts(&mut self, send_pkts: u64) {
        self.send_pkts = send_pkts;
    }
    pub fn set_recv_pkts(&mut self, recv_pkts: u64) {
        self.recv_pkts = recv_pkts;
    }
    pub fn set_send_bytes(&mut self, send_bytes: u64) {
        self.send_bytes = send_bytes;
    }
    pub fn set_recv_bytes(&mut self, recv_bytes: u64) {
        self.recv_bytes = recv_bytes;
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.send_pkts = 0;
            self.recv_pkts = 0;
            self.send_bytes = 0;
            self.recv_bytes = 0;
        }
        Ok(())
    }
    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        debug!("post_exec of RecvPktNumObserver: {:?}", self);
        Ok(())
    }

}
impl<S> Observer<S> for RecvPktNumObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.send_pkts = 0;
            self.recv_pkts = 0;
            self.send_bytes = 0;
            self.recv_bytes = 0;
        }
        Ok(())
    }
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        debug!("post_exec of RecvPktNumObserver: {:?}", self);
        Ok(())
    }
}
impl Named for RecvPktNumObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct RecvControlFrameObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub ctrl_frames_list: Vec<Frame_info>,
}
impl RecvControlFrameObserver {
    /// Creates a new [`RecvControlFrameObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            ctrl_frames_list: Vec::new(),
        }
    }
    pub fn get_frames_list(&self) -> &Vec<Frame_info> {
        &self.ctrl_frames_list
    }
    pub fn add_frame_list(&mut self, frame: frame::Frame) {
        let mut has_same_frame = false;
        for frame_info in self.ctrl_frames_list.iter_mut() {
            if mem::discriminant(&frame_info.frame) == mem::discriminant(&frame) {
                frame_info.frame_num += 1;
                has_same_frame = true;
                break;
            }
        }
        if !has_same_frame {
            self.ctrl_frames_list.push(Frame_info {
                frame: frame,
                frame_num: 1,
            });
        }
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.ctrl_frames_list.clear();
        }
        Ok(())
    }
    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // info!("post_exec of RecvControlFrameObserver: {:?}", self);
        Ok(())
    }
}
impl<S> Observer<S> for RecvControlFrameObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.ctrl_frames_list.clear();
        }
        Ok(())
    }
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // info!("post_exec of RecvControlFrameObserver: {:?}", self);
        Ok(())
    }
}
impl Named for RecvControlFrameObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct RecvDataFrameObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub crypto_frames_list: Vec<FrameWithPkn>,
    pub stream_frames_list: Vec<FrameWithPkn>,
    pub pr_frames_list: Vec<FrameWithPkn>,
    pub dgram_frames_list: Vec<FrameWithPkn>,
}
impl RecvDataFrameObserver {
    /// Creates a new [`RecvDataFrameObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            crypto_frames_list: Vec::new(),
            stream_frames_list: Vec::new(),
            pr_frames_list: Vec::new(),
            dgram_frames_list: Vec::new(),
        }
    }
    pub fn get_crypto_frames_list(&self) -> &Vec<FrameWithPkn> {
        &self.crypto_frames_list
    }
    pub fn add_crypto_frame_list(&mut self, frame: FrameWithPkn) {
        self.crypto_frames_list.push(frame);
    }
    pub fn get_stream_frames_list(&self) -> &Vec<FrameWithPkn> {
        &self.stream_frames_list
    }
    pub fn add_stream_frame_list(&mut self, frame: FrameWithPkn) {
        self.stream_frames_list.push(frame);
    }
    pub fn get_pr_frames_list(&self) -> &Vec<FrameWithPkn> {
        &self.pr_frames_list
    }
    pub fn add_pr_frame_list(&mut self, frame: FrameWithPkn) {
        self.pr_frames_list.push(frame);
    }
    pub fn get_dgram_frames_list(&self) -> &Vec<FrameWithPkn> {
        &self.dgram_frames_list
    }
    pub fn add_dgram_frame_list(&mut self, frame: FrameWithPkn) {
        self.dgram_frames_list.push(frame);
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.crypto_frames_list.clear();
            self.stream_frames_list.clear();
            self.pr_frames_list.clear();
            self.dgram_frames_list.clear();
        }
        Ok(())
    }
    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        debug!("post_exec of RecvDataFrameObserver: {:?}", self);
        // info!("post_exec of RecvDataFrameObserver: crypto:{:?}, stream:{:?}, pr:{:?}, dgram:{:?}", self.crypto_frames_list.len(), self.stream_frames_list.len(), self.pr_frames_list.len(), self.dgram_frames_list.len());
        Ok(())
    }
}
impl<S> Observer<S> for RecvDataFrameObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.crypto_frames_list.clear();
            self.stream_frames_list.clear();
            self.pr_frames_list.clear();
            self.dgram_frames_list.clear();
        }
        Ok(())
    }
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        debug!("post_exec of RecvDataFrameObserver: {:?}", self);
        // info!("post_exec of RecvDataFrameObserver: crypto:{:?}, stream:{:?}, pr:{:?}, dgram:{:?}", self.crypto_frames_list.len(), self.stream_frames_list.len(), self.pr_frames_list.len(), self.dgram_frames_list.len());
        Ok(())
    }
}

impl Named for RecvDataFrameObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct OtherFrameObserver {
    name: Cow<'static, str>,
    other_frames_list: Vec<Frame_info>,
}
impl OtherFrameObserver {
    /// Creates a new [`OtherFrameObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            other_frames_list: Vec::new(),
        }
    }
    pub fn get_frames_list(&self) -> &Vec<Frame_info> {
        &self.other_frames_list
    }
    pub fn add_frame_list(&mut self, frame: frame::Frame) {
        let mut has_same_frame = false;
        for frame_info in self.other_frames_list.iter_mut() {
            if mem::discriminant(&frame_info.frame) == mem::discriminant(&frame) {
                frame_info.frame_num += 1;
                has_same_frame = true;
                break;
            }
        }
        if !has_same_frame {
            self.other_frames_list.push(Frame_info {
                frame: frame,
                frame_num: 1,
            });
        }
    }
}
impl<S> Observer<S> for OtherFrameObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.other_frames_list.clear();
        Ok(())
    }
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        info!("post_exec of OtherFrameObserver: {:?}", self);
        Ok(())
    }
}
impl Named for OtherFrameObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}



#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct ACKRangeObserver {
    name: Cow<'static, str>,
    pub record_remote: bool,
    pub ack_ranges_nums: usize,
    pub ack_ranges: Vec<Ack_range>,
}
impl ACKRangeObserver {
    /// Creates a new [`ACKRangeObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            record_remote: false,
            ack_ranges_nums: 0,
            ack_ranges: Vec::new(),
        }
    }
    pub fn get_ack_ranges(&self) -> &Vec<Ack_range> {
        &self.ack_ranges
    }
    pub fn add_ACK_range(&mut self, start:u64 ,end:u64) {
        self.ack_ranges_nums += 1;
        self.ack_ranges.push(Ack_range {
            start: start,
            end: end,
        });
    }
    pub fn minimize_ACK_range_mut(&mut self) {
        let mut i = 0;
        while i < self.ack_ranges_nums {
            let mut j = i + 1;
            while j < self.ack_ranges_nums {
                if self.ack_ranges[i].end + 1 >= self.ack_ranges[j].start {
                    if self.ack_ranges[i].end < self.ack_ranges[j].end {
                        self.ack_ranges[i].end = self.ack_ranges[j].end;
                    }
                    self.ack_ranges.remove(j);
                    self.ack_ranges_nums -= 1;
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }
    pub fn minimize_ACK_range(& self) -> Vec<Ack_range> {
        let mut ack_ranges = self.ack_ranges.clone();
        let mut ack_ranges_nums = self.ack_ranges_nums;
        let mut i = 0;
        while i < ack_ranges_nums {
            let mut j = i + 1;
            while j < ack_ranges_nums {
                if ack_ranges[i].end + 1 == ack_ranges[j].start {
                    ack_ranges[i].end = ack_ranges[j].end;
                    ack_ranges.remove(j);
                    ack_ranges_nums -= 1;
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
        ack_ranges
    }
    pub fn pre_execv(&mut self) -> Result<(), Error> {
        if !self.record_remote() {
            self.ack_ranges.clear();
            self.ack_ranges_nums = 0;
        }
        Ok(())
    }
    pub fn post_execv(
        &mut self,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.record_remote() {
            self.minimize_ACK_range_mut();
            // info!("post_exec of ACKRangeObserver: {:?}", self);
        }
        Ok(())
    }
}
impl<S> Observer<S> for ACKRangeObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        if !self.record_remote() {
            self.ack_ranges.clear();
            self.ack_ranges_nums = 0;
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
            self.minimize_ACK_range_mut();
            // info!("post_exec of ACKRangeObserver: {:?}", self);
        }
        Ok(())
    }
}
impl Named for ACKRangeObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}


#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct DifferentialRecvControlFrameObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<RecvControlFrameObserver>,
    second_ob_ref: Handle<RecvControlFrameObserver>,
    first_observer: RecvControlFrameObserver,
    second_observer: RecvControlFrameObserver,
    name: Cow<'static, str>,
    judge_type: CtrlObserverState,
}
impl DifferentialRecvControlFrameObserver {
    /// Create a new `DifferentialRecvControlFrameObserver`.
    pub fn new (
        first: &mut RecvControlFrameObserver,
        second: &mut RecvControlFrameObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            second_ob_ref: second.handle(),
            first_observer: RecvControlFrameObserver::new("fake"),
            second_observer: RecvControlFrameObserver::new("fake"),
            judge_type: CtrlObserverState::OK,
        }
    }
    pub fn first_name(&self) -> &str {
        &self.first_name
    }
    pub fn second_name(&self) -> &str {
        &self.second_name
    }
    pub fn judge_type(&self) -> &CtrlObserverState {
        &self.judge_type
    }
    pub fn get_ctrl_frames(&self) -> Vec<Frame_info> {
        self.first_observer.ctrl_frames_list.clone()
    }
    pub fn perform_judge (&mut self) {
        for frame_info1 in self.first_observer.ctrl_frames_list.iter() {
            let mut frame1_match = false;
            for frame_info2 in self.second_observer.ctrl_frames_list.iter() {
                if  mem::discriminant(&frame_info1.frame) == mem::discriminant(&frame_info2.frame) {
                    frame1_match = true;
                    if abs(frame_info1.frame_num as i64 - frame_info2.frame_num as i64) > 10 {
                        self.judge_type = CtrlObserverState::CtrlFrameTypeNumMismatch;
                    }
                    break;
                }
            }
            if frame1_match == false {
                if frame_info1.frame_num > 10 {
                    self.judge_type = CtrlObserverState::CrtlFrame1TypeMismatch;
                    break;
                }
            }
        }
        for frame_info2 in self.second_observer.ctrl_frames_list.iter() {
            let mut frame2_match = false;
            for frame_info1 in self.first_observer.ctrl_frames_list.iter() {
                if  mem::discriminant(&frame_info1.frame) == mem::discriminant(&frame_info2.frame) {
                    frame2_match = true;
                    break;
                }
            }
            if frame2_match == false {
                if frame_info2.frame_num > 10 {
                    self.judge_type = CtrlObserverState::CrtlFrame2TypeMismatch;
                    break;
                }
            }
        }
        info!("FirControlOb:{:?}", self.first_observer);
        info!("SecControlOb:{:?}", self.second_observer);
        self.first_observer = RecvControlFrameObserver::new("fake");
        self.second_observer = RecvControlFrameObserver::new("fake");
    }
}
impl Named for DifferentialRecvControlFrameObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
impl<S> Observer<S> for DifferentialRecvControlFrameObserver where S: UsesInput {}
impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialRecvControlFrameObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = CtrlObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = CtrlObserverState::OK;
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


#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct DifferentialRecvDataFrameObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<RecvDataFrameObserver>,
    second_ob_ref: Handle<RecvDataFrameObserver>,
    first_observer: RecvDataFrameObserver,
    second_observer: RecvDataFrameObserver,
    name: Cow<'static, str>,
    judge_type: DataObserverState,
}
impl DifferentialRecvDataFrameObserver {
    /// Create a new `DifferentialRecvDataFrameObserver`.
    pub fn new (
        first: &mut RecvDataFrameObserver,
        second: &mut RecvDataFrameObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            second_ob_ref: second.handle(),
            first_observer: RecvDataFrameObserver::new("fake"),
            second_observer: RecvDataFrameObserver::new("fake"),
            judge_type: DataObserverState::OK,
        }
    }
    pub fn first_name(&self) -> &str {
        &self.first_name
    }
    pub fn second_name(&self) -> &str {
        &self.second_name
    }
    pub fn judge_type(&self) -> &DataObserverState {
        &self.judge_type
    }

    pub fn set_initial_observer(&mut self) {
        self.first_observer = RecvDataFrameObserver::new("fake");
        self.second_observer = RecvDataFrameObserver::new("fake");
    }

    pub fn check_data_frame_type_num (&mut self) -> bool {
        if abs(self.first_observer.crypto_frames_list.len() as isize - self.second_observer.crypto_frames_list.len() as isize) >10{
            self.judge_type = DataObserverState::DataFrameTypeNumMismatch;
            return false;
        } else if abs(self.first_observer.stream_frames_list.len() as isize - self.second_observer.stream_frames_list.len() as isize) >10 {
            self.judge_type = DataObserverState::DataFrameTypeNumMismatch;
            return false;
        } else if abs(self.first_observer.pr_frames_list.len() as isize - self.second_observer.pr_frames_list.len() as isize) >10 {
            self.judge_type = DataObserverState::DataFrameTypeNumMismatch;
            return false;
        } else if abs(self.first_observer.dgram_frames_list.len() as isize - self.second_observer.dgram_frames_list.len() as isize) >10 {
            self.judge_type = DataObserverState::DataFrameTypeNumMismatch;
            return false;
        } else {
            return true;
        }
    }

    pub fn check_crypto_frame_content (&mut self) -> bool {
        let mut first_crypto_data_len = 0;
        let mut second_crypto_data_len = 0;
        for crypto_frame in self.first_observer.crypto_frames_list.iter() {
            match &crypto_frame.frame {
                Frame::Crypto { data } => {
                    first_crypto_data_len += data.data.len();
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Crypto frame");
                }
            }
        }
        for crypto_frame in self.second_observer.crypto_frames_list.iter() {
            match &crypto_frame.frame {
                Frame::Crypto { data } => {
                    second_crypto_data_len += data.data.len();
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Crypto frame");
                }
            }
        }
        if abs(first_crypto_data_len as isize - second_crypto_data_len as isize) > 5000 {
            self.judge_type = DataObserverState::DataFrameCryptoContentMismatch;
            return false;
        }
        return true;
    }

    pub fn check_stream_frame_content(&mut self) -> bool {
        let mut first_stream_data_len = 0;
        let mut second_stream_data_len = 0;
        let mut first_stream_data_dismatch_len = 0;
        let mut second_stream_data_dismatch_len = 0;
        for first_stream_frame in self.first_observer.stream_frames_list.iter() {
            match &first_stream_frame.frame {
                Frame::Stream { data, stream_id } => {
                    first_stream_data_len += data.data.len();
                    let val1 = data.data.clone();
                    let start1 = data.off;
                    let mut match_second_stream = false;
                    for second_stream_frame in self.second_observer.stream_frames_list.iter() {
                        match &second_stream_frame.frame {
                            Frame::Stream { data, stream_id } => {
                                let val2 = data.data.clone();
                                let start2 = data.off;
                                if val1 == val2 && start1 == start2 {
                                    match_second_stream = true;
                                    break;
                                }
                            },
                            _ => {
                                // 处理其他类型的frame
                                debug!("Not a Stream frame");
                            }
                        }
                    }
                    if match_second_stream == false {
                        first_stream_data_dismatch_len += val1.len();
                    }
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Stream frame");
                }
            }
        }
        for second_stream_frame in self.second_observer.stream_frames_list.iter() {
            match &second_stream_frame.frame {
                Frame::Stream { data, stream_id } => {
                    second_stream_data_len += data.data.len();
                    let val2 = data.data.clone();
                    let start2 = data.off;
                    let mut match_first_stream = false;
                    for first_stream_frame in self.first_observer.stream_frames_list.iter() {
                        match &first_stream_frame.frame {
                            Frame::Stream { data, stream_id } => {
                                let val1 = data.data.clone();
                                let start1 = data.off;
                                if val1 == val2 && start1 == start2 {
                                    match_first_stream = true;
                                    break;
                                }
                            },
                            _ => {
                                // 处理其他类型的frame
                                debug!("Not a Stream frame");
                            }
                        }
                    }
                    if match_first_stream == false {
                        second_stream_data_dismatch_len += val2.len();
                    }
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Stream frame");
                }
            }
        }
        if first_stream_data_dismatch_len > 5000 || second_stream_data_dismatch_len > 5000 {
            self.judge_type = DataObserverState::DataFrameStreamContentMismatch;
            return false;
        }
        if abs(first_stream_data_len as isize - second_stream_data_len as isize) > 5000 {
            self.judge_type = DataObserverState::DataFrameStreamContentLenMismatch;
            return false;
        }
        return true;

    }

    pub fn check_pr_frame_content(&mut self) -> bool {
        for first_pr_frame in self.first_observer.pr_frames_list.iter() {
            match &first_pr_frame.frame {
                Frame::PathResponse { data } => {
                    let val1 = data.clone();
                    let mut match_second_pr = false;
                    for second_pr_frame in self.second_observer.pr_frames_list.iter() {
                        match &second_pr_frame.frame {
                            Frame::PathResponse { data } => {
                                let val2 = data.clone();
                                if val1 == val2 {
                                    match_second_pr = true;
                                    break;
                                }
                            },
                            _ => {
                                // 处理其他类型的frame
                                debug!("Not a PathResponse frame");
                            }
                        }
                    }
                    if match_second_pr == false {
                        self.judge_type = DataObserverState::DataFramePRContentMismatch;
                        return false;
                    }
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Padding frame");
                }
            }
        }
        for second_pr_frame in self.second_observer.pr_frames_list.iter() {
            match &second_pr_frame.frame {
                Frame::PathResponse { data } => {
                    let val2 = data.clone();
                    let mut match_first_pr = false;
                    for first_pr_frame in self.first_observer.pr_frames_list.iter() {
                        match &first_pr_frame.frame {
                            Frame::PathResponse { data } => {
                                let val1 = data.clone();
                                if val1 == val2 {
                                    match_first_pr = true;
                                    break;
                                }
                            },
                            _ => {
                                // 处理其他类型的frame
                                debug!("Not a PathResponse frame");
                            }
                        }
                    }
                    if match_first_pr == false {
                        self.judge_type = DataObserverState::DataFramePRContentMismatch;
                        return false;
                    }
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Padding frame");
                }
            }
        }
        return true;
    }

    pub fn check_dgram_frame_content(&mut self) -> bool {
        for first_dgram_frame in self.first_observer.dgram_frames_list.iter() {
            match &first_dgram_frame.frame {
                Frame::Datagram { data } => {
                    let val1 = data.clone();
                    let mut match_second_dgram = false;
                    for second_dgram_frame in self.second_observer.dgram_frames_list.iter() {
                        match &second_dgram_frame.frame {
                            Frame::Datagram { data } => {
                                let val2 = data.clone();
                                if val1 == val2 {
                                    match_second_dgram = true;
                                    break;
                                }
                            },
                            _ => {
                                // 处理其他类型的frame
                                debug!("Not a Datagram frame");
                            }
                        }
                    }
                    if match_second_dgram == false {
                        self.judge_type = DataObserverState::DataFrameDgramContentMismatch;
                        return false;
                    }
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Datagram frame");
                }
            }
        }
        for second_dgram_frame in self.second_observer.dgram_frames_list.iter() {
            match &second_dgram_frame.frame {
                Frame::Datagram { data } => {
                    let val2 = data.clone();
                    let mut match_first_dgram = false;
                    for first_dgram_frame in self.first_observer.dgram_frames_list.iter() {
                        match &first_dgram_frame.frame {
                            Frame::Datagram { data } => {
                                let val1 = data.clone();
                                if val1 == val2 {
                                    match_first_dgram = true;
                                    break;
                                }
                            },
                            _ => {
                                // 处理其他类型的frame
                                debug!("Not a Datagram frame");
                            }
                        }
                    }
                    if match_first_dgram == false {
                        self.judge_type = DataObserverState::DataFrameDgramContentMismatch;
                        return false;
                    }
                },
                _ => {
                    // 处理其他类型的frame
                    debug!("Not a Datagram frame");
                }
            }
        }
        return true;
    }

    pub fn perform_judge (&mut self) {

        if self.check_data_frame_type_num() == false {
        } else if self.check_crypto_frame_content() == false {
        } else if self.check_stream_frame_content() == false {
        } else if self.check_pr_frame_content() == false {
        } else if self.check_dgram_frame_content() == false {
        }
        info!("FirDataOb: crypto:{:?}, stream:{:?}, pr:{:?}, dgram:{:?}", self.first_observer.crypto_frames_list.len(), self.first_observer.stream_frames_list.len(), self.first_observer.pr_frames_list.len(), self.first_observer.dgram_frames_list.len());
        info!("SecDataOb: crypto:{:?}, stream:{:?}, pr:{:?}, dgram:{:?}", self.second_observer.crypto_frames_list.len(), self.second_observer.stream_frames_list.len(), self.second_observer.pr_frames_list.len(), self.second_observer.dgram_frames_list.len());
        self.set_initial_observer();

    }
}
impl Named for DifferentialRecvDataFrameObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
impl<S> Observer<S> for DifferentialRecvDataFrameObserver where S: UsesInput {}
impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialRecvDataFrameObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = DataObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = DataObserverState::OK;
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


#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct DifferentialOtherFrameObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<OtherFrameObserver>,
    second_ob_ref: Handle<OtherFrameObserver>,
    first_observer: OtherFrameObserver,
    second_observer: OtherFrameObserver,
    name: Cow<'static, str>,
    judge_type: OtherObserverState,
}
impl DifferentialOtherFrameObserver {
    /// Create a new `DifferentialOtherFrameObserver`.
    pub fn new (
        first: &mut OtherFrameObserver,
        second: &mut OtherFrameObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            second_ob_ref: second.handle(),
            first_observer: OtherFrameObserver::new("fake"),
            second_observer: OtherFrameObserver::new("fake"),
            judge_type: OtherObserverState::OK,
        }
    }
    pub fn first_name(&self) -> &str {
        &self.first_name
    }
    pub fn second_name(&self) -> &str {
        &self.second_name
    }
    pub fn get_judge_type(&self) -> OtherObserverState {
        self.judge_type.clone()
    }
    pub fn perform_judge (&mut self) {
        for frame_info1 in self.first_observer.other_frames_list.iter() {
            let mut frame1_match = false;
            for frame_info2 in self.second_observer.other_frames_list.iter() {
                if  mem::discriminant(&frame_info1.frame) == mem::discriminant(&frame_info2.frame) {
                    frame1_match = true;
                    if frame_info1.frame_num != frame_info2.frame_num {
                        self.judge_type = OtherObserverState::OtherFrameTypeNumMismatch;
                    }
                    break;
                }
            }
            if frame1_match == false {
                self.judge_type = OtherObserverState::OtherFrameTypeMismatch;
                break;
            }
        }
        if self.first_observer.other_frames_list.len() != self.second_observer.other_frames_list.len() {
            self.judge_type = OtherObserverState::OtherFrameTypeMismatch;
        }

        self.first_observer = OtherFrameObserver::new("fake");
        self.second_observer = OtherFrameObserver::new("fake");
    }
}
impl Named for DifferentialOtherFrameObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
impl<S> Observer<S> for DifferentialOtherFrameObserver where S: UsesInput {}
impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialOtherFrameObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = OtherObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = OtherObserverState::OK;
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


#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct DifferentialACKRangeObserver {

    first_name: Cow<'static, str>,
    second_name: Cow<'static, str>,
    first_ob_ref: Handle<ACKRangeObserver>,
    second_ob_ref: Handle<ACKRangeObserver>,
    first_observer: ACKRangeObserver,
    second_observer: ACKRangeObserver,
    name: Cow<'static, str>,
    judge_type: ACKObserverState,
}
impl DifferentialACKRangeObserver {
    /// Create a new `DifferentialACKRangeObserver`.
    pub fn new (
        first: &mut ACKRangeObserver,
        second: &mut ACKRangeObserver,
    ) -> Self {
        Self {
            first_name: first.name().clone(),
            second_name: second.name().clone(),
            name: Cow::from(format!("differential_{}_{}", first.name(), second.name())),
            first_ob_ref: first.handle(),
            second_ob_ref: second.handle(),
            first_observer: ACKRangeObserver::new("fake"),
            second_observer: ACKRangeObserver::new("fake"),
            judge_type: ACKObserverState::OK,
        }
    }
    pub fn first_name(&self) -> &str {
        &self.first_name
    }
    pub fn second_name(&self) -> &str {
        &self.second_name
    }
    pub fn judge_type(&self) -> &ACKObserverState {
        &self.judge_type
    }
    pub fn perform_judge (&mut self) {
        let mut first_list = self.first_observer.minimize_ACK_range();
        let mut second_list = self.second_observer.minimize_ACK_range();

        if first_list.len() != second_list.len() {
            self.judge_type = ACKObserverState::ACKRangeMismatch;
        }
        for first_range in first_list.iter() {
            for second_range in second_list.iter() {
                if abs(first_range.start as i128 - second_range.start as i128) >10 || abs(first_range.end as i128 - second_range.end as i128) > 10 {
                    self.judge_type = ACKObserverState::ACKRangeMismatch;
                    break;
                }
            }
        }
        info!("FirACKOb:{:?}", self.first_observer);
        info!("SecACKOb:{:?}", self.second_observer);
        self.first_observer = ACKRangeObserver::new("fake");
        self.second_observer = ACKRangeObserver::new("fake");
    }
}
impl Named for DifferentialACKRangeObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
impl<S> Observer<S> for DifferentialACKRangeObserver where S: UsesInput {}
impl< OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
    for DifferentialACKRangeObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
        self.judge_type = ACKObserverState::OK;
        Ok(())
    }

    fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
        self.judge_type = ACKObserverState::OK;
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
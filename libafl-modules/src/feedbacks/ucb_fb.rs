use std::borrow::Cow;
use std::cmp::min;

use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::inputs::HasMutatorBytes;
use libafl::observers::ObserversTuple;
use libafl::prelude::ObserverWithHashField;
use libafl::state::HasReward;
use libafl::state::State;
use libafl::HasMetadata;
use libafl_bolts::ownedref::OwnedMutPtr;
use libafl_bolts::tuples::Handle;
use libafl_bolts::tuples::Handled;
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::{Error, Named,tuples::MatchName};
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState, feedbacks::Feedback};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::inputstruct::*;
use crate::observers::*;

/// Nop feedback that annotates execution time in the new testcase, if any
/// for this Feedback, the testcase is never interesting (use with an OR).
/// It decides, if the given [`UCBObserver`] value of a run is interesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UCBFeedback {
    ucb_observer_handle: Handle<UCBObserver>,
    cpu_observer_handle: Handle<CPUUsageObserver>,
    mem_observer_handle: Handle<MemObserver>,
    cc_time_observer_handle: Handle<CCTimesObserver>,
    recv_pkt_num_observer_handle: Handle<RecvPktNumObserver>,
    ack_range_observer_handle: Handle<ACKRangeObserver>,
    control_frame_observer_handle: Handle<RecvControlFrameObserver>,
    data_frame_observer_handle: Handle<RecvDataFrameObserver>,
    reward: f64,


}


impl<S> Feedback<S> for UCBFeedback
where
    S: State + HasReward,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let ucb_ob = _observers.get(&self.ucb_observer_handle).unwrap();
        let cpu_ob = _observers.get(&self.cpu_observer_handle).unwrap();
        let mem_ob = _observers.get(&self.mem_observer_handle).unwrap();
        let cc_time_ob = _observers.get(&self.cc_time_observer_handle).unwrap();
        let recv_pkt_num_ob = _observers.get(&self.recv_pkt_num_observer_handle).unwrap();
        let ack_range_ob = _observers.get(&self.ack_range_observer_handle).unwrap();
        let control_frame_ob = _observers.get(&self.control_frame_observer_handle).unwrap();
        let data_frame_ob = _observers.get(&self.data_frame_observer_handle).unwrap();
        /*
        如果存在CC帧，且时间太快（pkn在20以内），则不认为是有趣的
        如果接收的数据包是发送的数据包的50%以下，则不认为是有趣的 按某种形式统计比例
        如果ack范围过小，则不认为是有趣的（待定）
        控制帧、数据帧暂时不考虑
        CPU占用率的百分比记为record 按某种形式统计比例
        内存占用的百分比记为record 按某种形式统计比例
        加权平均值更新record
        */
        let mut record = 0.0;
        let mut recv_pkt_record = 0.0;
        let mut cpu_record = 0.0;
        let mut mem_record = 0.0;
        if cc_time_ob.pkn > 0 && cc_time_ob.pkn < 20 {
            warn!("Received CC Too fast, pkn: {}", cc_time_ob.pkn);
            return Ok(false);
        }
        // if recv_pkt_num_ob.recv_pkts < recv_pkt_num_ob.send_pkts / 2 {
        //     warn!("Received packets are less than half of sent packets, recv: {}, sent: {}", recv_pkt_num_ob.recv_pkts, recv_pkt_num_ob.send_pkts);
        //     return Ok(false);
        // }
        recv_pkt_record = (recv_pkt_num_ob.recv_pkts as f64 / (recv_pkt_num_ob.send_pkts * 5) as f64).min(1.0);
        cpu_record = (cpu_ob.final_based_cpu_usage - cpu_ob.based_cpu_usage) as f64 / 100.0;
        mem_record = ((mem_ob.after_mem - mem_ob.before_mem) as f64 / (mem_ob.allowed_mem) as f64).min(1.0);
        self.reward = recv_pkt_record.max(cpu_record).max(mem_record);
        _state.set_reward(self.reward);

        Ok(true)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        // let observer = observers.get(&self.observer_handle).unwrap();
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Named for UCBFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.ucb_observer_handle.name()
    }
}

impl UCBFeedback {
    /// Creates a new [`UCBFeedback`], deciding if the given [`UCBObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(ucb_observer: &UCBObserver, cpu_observer: &CPUUsageObserver, mem_observer: &MemObserver, cc_time_observer: &CCTimesObserver, recv_pkt_num_observer: &RecvPktNumObserver, ack_range_observer: &ACKRangeObserver, control_frame_observer: &RecvControlFrameObserver, data_frame_observer: &RecvDataFrameObserver) -> Self {
        Self {
            ucb_observer_handle: ucb_observer.handle(),
            cpu_observer_handle: cpu_observer.handle(),
            mem_observer_handle: mem_observer.handle(),
            cc_time_observer_handle: cc_time_observer.handle(),
            recv_pkt_num_observer_handle: recv_pkt_num_observer.handle(),
            ack_range_observer_handle: ack_range_observer.handle(),
            control_frame_observer_handle: control_frame_observer.handle(),
            data_frame_observer_handle: data_frame_observer.handle(),
            reward: 0.0,
        }
    }
}


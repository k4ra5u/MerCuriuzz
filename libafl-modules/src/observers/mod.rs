pub mod cc_time;
pub mod cpu_usage;
pub mod mem_usage;
pub mod normal_conn;
pub mod recv_pkt_num;
pub mod ucb_ob;
pub mod misc_ob;
pub mod pcap_record;
pub mod shmem_io;

use libafl::prelude::ExitKind;
pub use recv_pkt_num::*;
pub use cc_time::*;
pub use cpu_usage::*;
pub use mem_usage::*;
pub use normal_conn::*;
use serde::{Deserialize, Serialize};
pub use ucb_ob::*;
pub use misc_ob::*;
pub use pcap_record::*;
pub use shmem_io::*;

pub trait HasRecordRemote {
    fn record_remote(&self) -> bool;
    fn set_record_remote(&mut self, record_remote: bool);
}

impl HasRecordRemote for NormalConnObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for CCTimesObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for MiscObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for RecvPktNumObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for ACKRangeObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for RecvControlFrameObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for RecvDataFrameObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for CPUUsageObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for MemObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for PcapObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}
impl HasRecordRemote for UCBObserver {
    fn record_remote(&self) -> bool {
        self.record_remote
    }
    fn set_record_remote(&mut self, record_remote: bool) {
        self.record_remote = record_remote;
    }
}

#[derive( Serialize, Deserialize,Debug, Clone)]
pub struct RemoteObsData {
    pub exit_kind: ExitKind,
    pub normal_conn_ob: NormalConnObserver,
    pub cc_time_ob: CCTimesObserver,
    pub misc_ob: MiscObserver,
    pub recv_pkt_num_ob: RecvPktNumObserver,
    pub ack_range_ob: ACKRangeObserver,
    pub control_frame_ob: RecvControlFrameObserver,
    pub data_frame_ob: RecvDataFrameObserver,
    pub cpu_usage_ob: CPUUsageObserver,
    pub mem_usage_ob: MemObserver,
    pub pcap_record_ob: PcapObserver,
    pub ucb_ob: UCBObserver,
    
}

impl RemoteObsData {
    pub fn new(
        normal_conn_ob: NormalConnObserver,
        cc_time_ob: CCTimesObserver,
        misc_ob: MiscObserver,
        recv_pkt_num_ob: RecvPktNumObserver,
        ack_range_ob: ACKRangeObserver,
        control_frame_ob: RecvControlFrameObserver,
        data_frame_ob: RecvDataFrameObserver,
        cpu_usage_ob: CPUUsageObserver,
        mem_usage_ob: MemObserver,
        pcap_record_ob: PcapObserver,
        ucb_ob: UCBObserver
    ) -> Self {
        RemoteObsData {
            exit_kind: ExitKind::Ok,
            normal_conn_ob,
            cc_time_ob,
            misc_ob,
            recv_pkt_num_ob,
            ack_range_ob,
            control_frame_ob,
            data_frame_ob,
            cpu_usage_ob,
            mem_usage_ob,
            pcap_record_ob,
            ucb_ob,
    
        }
    }
}
use std::{
    any::Any, env, ffi::{OsStr, OsString}, io::{self, prelude::*, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, time::Duration, vec
};
use quiche::{frame, packet, Connection, ConnectionId, Error, Header};
use log::{error, info,debug,warn};
// use rand::Rng;
use std::net::{SocketAddr, ToSocketAddrs};
// use ring::rand::*;
use libc::{srand, rand};
#[derive(Debug)]
pub struct FramesCycleStruct {
    pub repeat_num: usize,
    pub basic_frames: Vec<frame::Frame>,
}

impl FramesCycleStruct {

    pub fn new() ->Self {
        Self {
            repeat_num: 0,
            basic_frames: Vec::new(),
        }
    }

    pub fn set_repeat_num(mut self, repeat_num: usize) -> Self {
        self.repeat_num = repeat_num;
        self
    }

    pub fn add_frame(mut self, frame: frame::Frame) -> Self {
        self.basic_frames.push(frame);
        self
    }

    pub fn new_with_input(pkt_type: packet::Type, input: &[u8]) -> Self {
        let repeat_num = u64::from_le_bytes(input[0..8].try_into().unwrap()) as usize;
        let input = &input[8..];
        let mut left = input.len();
        let mut basic_frames = Vec::new();
        let mut octets_input = octets::Octets::with_slice(input);
        while left > 0 {
            match  frame::Frame::from_bytes(&mut octets_input, pkt_type) {
                Ok(frame) => {
                    left = octets_input.cap();
                    // debug!("frame: {:?}", frame);
                    basic_frames.push(frame);
                },
                Err(_) => {
                    break;
                },
            }
        }
        Self {
            repeat_num,
            basic_frames,
        }
    }
}
#[derive(Debug)]
pub enum pkt_resort_type {
    None,
    Random,
    Reverse,
    Odd_even,
}
#[derive(Debug)]
pub struct InputStruct {
    pub pkt_type: packet::Type,
    pub send_timeout: u64,
    pub recv_timeout: u64,
    pub packet_resort_type: pkt_resort_type,
    pub number_of_cycles: usize,
    pub cycles_len: Vec<usize>,
    pub frames_cycle: Vec<FramesCycleStruct>,
}
impl InputStruct {
    pub fn new() -> Self {
        Self {
            pkt_type: packet::Type::Short,
            send_timeout: 50,
            recv_timeout: 50,
            packet_resort_type: pkt_resort_type::None,
            number_of_cycles: 0,
            cycles_len: Vec::new(),
            frames_cycle: Vec::new(),
        }
    }
    pub fn set_pkt_type(mut self,pkt_type: packet::Type ) -> Self {
        self.pkt_type = pkt_type;
        self
    }
    pub fn set_send_timeout(mut self, send_timeout: u64) -> Self {
        // self.send_timeout = Duration::from_millis(send_timeout);
        self.send_timeout = send_timeout;
        self
    }
    pub fn set_recv_timeout(mut self, recv_timeout:u64  ) -> Self {
        // self.recv_timeout = Duration::from_millis(recv_timeout);
        self.recv_timeout = recv_timeout;
        self
    }
    pub fn set_packet_resort_type(mut self, packet_resort_type: pkt_resort_type) -> Self {
        self.packet_resort_type = packet_resort_type;
        self
    }

    pub fn add_frames_cycle(mut self, frames_cycle: FramesCycleStruct) -> Self {
        self.frames_cycle.push(frames_cycle);
        self
    }
    pub fn calc_frames_cycle_len(mut self) -> Self {
        self.number_of_cycles = self.frames_cycle.len();

        let mut frames_cycle_bytes = Vec::new();
        self.cycles_len = Vec::new();
        let mut current_framses_len:u64 =0;
        for frame_cycle in self.frames_cycle.iter(){
            frames_cycle_bytes.extend_from_slice(&(frame_cycle.repeat_num as u64).to_le_bytes());
            for frame in &frame_cycle.basic_frames {
                let mut d = Vec::new();
                let mut b = octets::OctetsMut::with_slice(&mut d);
                frame.to_bytes(& mut b);
                frames_cycle_bytes.extend_from_slice(&d);
            }
            self.cycles_len.push(frames_cycle_bytes.len() - current_framses_len as usize);
            current_framses_len = frames_cycle_bytes.len() as u64;
        }
        self
    }

    pub fn deserialize(mut self,input: &[u8]) -> Self {
        let pkt_type = match (input[0]%6){
            0 => packet::Type::Initial,
            1 => packet::Type::Retry,
            2 => packet::Type::Handshake,
            3 => packet::Type::ZeroRTT,
            4 => packet::Type::VersionNegotiation,
            5 => packet::Type::Short,
            _ => packet::Type::Short,
        };
        let send_mili_secs = u64::from_le_bytes(input[1..9].try_into().unwrap());
        let recv_mili_secs = u64::from_le_bytes(input[9..17].try_into().unwrap());
        let packet_resort_type = match input[17] {
            0 => pkt_resort_type::None,
            1 => pkt_resort_type::Random,
            2 => pkt_resort_type::Reverse,
            3 => pkt_resort_type::Odd_even,
            _ => pkt_resort_type::None,
        };
        let number_of_cycles = u64::from_le_bytes(input[17..25].try_into().unwrap()) as usize;
        let mut cycles_len = Vec::new();
        for i in 0..number_of_cycles {
            let cycle_len = u64::from_le_bytes(input[25+i*8..33+i*8].try_into().unwrap()) as usize;
            cycles_len.push(cycle_len);
        }
        let mut input = &input[25+number_of_cycles*8..];
        let mut frames_cycle = Vec::new();
        for i in 0..number_of_cycles{
            let cycle_len = cycles_len[i];
            let frame_cycle = FramesCycleStruct::new_with_input(pkt_type, &input[0..cycle_len]);
            input = &input[cycle_len..];
            frames_cycle.push(frame_cycle);
        }

        Self {
            pkt_type,
            send_timeout: send_mili_secs,
            recv_timeout: recv_mili_secs,
            packet_resort_type,
            number_of_cycles,
            cycles_len,
            frames_cycle,
        }
    }
    
    pub fn gen_frames(&self,start:u64, end:u64,cur_cycle:usize) -> Vec<frame::Frame> {
        let mut frames = Vec::new();
        let frames_cycle = &self.frames_cycle[cur_cycle];
        
        for i in start..end +1 {
            for frame in &frames_cycle.basic_frames {
                //default: 由于上层已经打乱了次序，这里每个cycle只有一个frame，方便对frame进行操作
                //对于每种frame设计不同的操作
                match frame {
                    frame::Frame::Padding {
                        len,
                    } => {
                        frames.push(frame::Frame::Padding {
                            len: *len,
                            });
                    },
                    frame::Frame::Ping {
                        mtu_probe: mtu_probe,
                    }  => {
                        match *mtu_probe {
                            Some(mtu_probe) => {
                                let mut mutated_mtu_probe = mtu_probe ;
                                // let mut rng = rand::thread_rng();
                                // mutated_mtu_probe = rng.gen_range(0..=1500);
                                mutated_mtu_probe = unsafe { rand() as usize }%1500 ;
                                frames.push(frame::Frame::Ping {
                                    mtu_probe: Some(mutated_mtu_probe),
                                });
                            },
                            None => {
                                frames.push(frame::Frame::Ping {
                                    mtu_probe: None,
                                })
                            },
                        }

                    },
                    frame::Frame::ACK {
                        ack_delay,
                        ranges,
                        ecn_counts,
                    } => {

                        let mut mutated_ack_delay = ack_delay;
                        let mut mutated_ranges = ranges.clone();
                        let mut mutated_ecn_counts = ecn_counts.clone();
                        mutated_ack_delay = ack_delay;
                        mutated_ranges = ranges.clone();
                        mutated_ecn_counts = ecn_counts.clone();
                        frames.push(frame::Frame::ACK {
                            ack_delay: *mutated_ack_delay,
                            ranges: mutated_ranges,
                            ecn_counts: mutated_ecn_counts,
                        });
                    },
                    frame::Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        let mut mutated_stream_id = *stream_id;
                        let mut mutated_error_code = *error_code;
                        let mut mutated_final_size = *final_size;
                        mutated_stream_id = *stream_id ;
                        mutated_error_code = *error_code + 1;
                        mutated_final_size = *final_size + 1;
                        frames.push(frame::Frame::ResetStream {
                            stream_id: mutated_stream_id,
                            error_code: mutated_error_code,
                            final_size: mutated_final_size,
                        });
                    },
                    frame::Frame::StopSending {
                        stream_id,
                        error_code,
                    } => {
                        let mut mutated_stream_id = *stream_id;
                        let mut mutated_error_code = *error_code;
                        mutated_stream_id = *stream_id ;
                        mutated_error_code = *error_code + 1;
                        frames.push(frame::Frame::StopSending {
                            stream_id: mutated_stream_id,
                            error_code: mutated_error_code,
                        });
                    },
                    frame::Frame::Crypto {
                        data,
                    } => {
                        let mut mutated_data = data.clone();
                        mutated_data = data.clone();
                        frames.push(frame::Frame::Crypto {
                            data: mutated_data,
                        });
                    },
                    frame::Frame::CryptoHeader { 
                        offset, 
                        length 
                    } => {
                        let mut mutated_offset = *offset;
                        let mut mutated_length = *length;
                        mutated_offset = *offset + 1;
                        mutated_length = *length + 1;
                        frames.push(frame::Frame::CryptoHeader {
                            offset: mutated_offset,
                            length: mutated_length,
                        });
                    },
                    frame::Frame::NewToken {
                        token,
                    } => {
                        let mut mutated_token = token.clone();
                        mutated_token = token.clone();
                        frames.push(frame::Frame::NewToken {
                            token: mutated_token,
                        });
                    },
                    frame::Frame::Stream {
                        stream_id,
                        data,
                    } => {
                        let mut mutated_stream_id = *stream_id;
                        let mut mutated_data = data.clone();
                        mutated_stream_id = *stream_id;
                        mutated_data = data.clone();
                        frames.push(frame::Frame::Stream {
                            stream_id: mutated_stream_id,
                            data: mutated_data,
                        });
                    },
                    frame::Frame::StreamHeader { 
                        stream_id, 
                        offset, 
                        length ,
                        fin,
                    } => {
                        let mut mutated_stream_id = *stream_id;
                        let mut mutated_offset = *offset;
                        let mut mutated_length = *length;
                        let mut mutated_fin = *fin;
                        mutated_stream_id = *stream_id ;
                        mutated_offset = *offset + 1000*i as u64;
                        mutated_length = *length ;
                        mutated_fin = *fin;
                        frames.push(frame::Frame::StreamHeader {
                            stream_id: mutated_stream_id,
                            offset: mutated_offset,
                            length: mutated_length,
                            fin: mutated_fin,
                        });
                    },
                    frame::Frame::MaxData {
                        max,
                    } => {
                        let mut mutated_max = *max;
                        mutated_max = *max + 1;
                        frames.push(frame::Frame::MaxData {
                            max: mutated_max,
                        });
                    },
                    frame::Frame::MaxStreamData {
                        stream_id,
                        max,
                    } => {
                        let mut mutated_stream_id = *stream_id;
                        let mut mutated_max = *max;
                        mutated_stream_id = *stream_id + 1;
                        mutated_max = *max + 1;
                        frames.push(frame::Frame::MaxStreamData {
                            stream_id: mutated_stream_id,
                            max: mutated_max,
                        });
                    },
                    frame::Frame::MaxStreamsBidi {
                        max,
                    } => {
                        let mut mutated_max = *max;
                        mutated_max = *max + i as u64;
                        frames.push(frame::Frame::MaxStreamsBidi {
                            max: mutated_max,
                        });
                    },
                    frame::Frame::MaxStreamsUni {
                        max,
                    } => {
                        let mut mutated_max = *max;
                        mutated_max = *max + i as u64;
                        frames.push(frame::Frame::MaxStreamsUni {
                            max: mutated_max,
                        });
                    },
                    frame::Frame::DataBlocked {
                        limit,
                    } => {
                        let mut mutated_limit = *limit;
                        mutated_limit = *limit + i as u64;
                        frames.push(frame::Frame::DataBlocked {
                            limit: mutated_limit,
                        });
                    },
                    frame::Frame::StreamDataBlocked {
                        stream_id,
                        limit,
                    } => {
                        let mut mutated_stream_id = *stream_id;
                        let mut mutated_limit = *limit;
                        mutated_stream_id = *stream_id;
                        mutated_limit = *limit + i as u64;
                        frames.push(frame::Frame::StreamDataBlocked {
                            stream_id: mutated_stream_id,
                            limit: mutated_limit,
                        });
                    },
                    frame::Frame::StreamsBlockedBidi { 
                        limit 
                    } => {
                    let mut mutated_limit = *limit;
                        mutated_limit = *limit + i as u64;
                        frames.push(frame::Frame::StreamsBlockedBidi {
                            limit: mutated_limit,
                        });
                    },
                    frame::Frame::StreamsBlockedUni { 
                        limit 
                    } => {
                        let mut mutated_limit = *limit;
                        mutated_limit = *limit + i as u64;
                        frames.push(frame::Frame::StreamsBlockedUni {
                            limit: mutated_limit,
                        });
                    },

                    frame::Frame::NewConnectionId {
                        seq_num,
                        retire_prior_to,
                        conn_id ,
                        reset_token,
                    } => {
                        let mut mutated_seq = *seq_num + i as u64;
                        let mut mutated_retire_prior_to = *retire_prior_to + i as u64;
                        let mut mutated_cid = [0 as u8;quiche::MAX_CONN_ID_LEN];
                        let mut mutated_reset_token = reset_token.clone();
                        mutated_seq = *seq_num + i as u64;
                        mutated_retire_prior_to = *retire_prior_to+ i as u64;
                        for i in (0..quiche::MAX_CONN_ID_LEN){
                            mutated_cid[i] = unsafe{rand() as u8};

                        }
                        for i in (0..16){
                            mutated_reset_token[i] = unsafe{rand() as u8};
                        }
                        debug!("mutated_cid: {:?}", mutated_cid);

                        
                        // SystemRandom::new().fill( & mut mutated_cid[..]).unwrap();
                        // SystemRandom::new().fill( & mut mutated_reset_token[..]).unwrap();

                        // mutated_reset_token = reset_token.clone();
                        frames.push(frame::Frame::NewConnectionId {
                            seq_num: mutated_seq,
                            retire_prior_to: mutated_retire_prior_to,
                            conn_id: mutated_cid.to_vec(),
                            reset_token: mutated_reset_token,
                        });
                    },
                    frame::Frame::RetireConnectionId {
                        seq_num,
                    } => {
                        let mut mutated_seq = *seq_num;
                        mutated_seq = *seq_num + i as u64;
                        frames.push(frame::Frame::RetireConnectionId {
                            seq_num: mutated_seq,
                        });
                    },
                    frame::Frame::PathChallenge {
                        data,
                    } => {
                        let mut mutated_data = data.clone();
                        mutated_data = data.clone();
                        for i in (0..8) {
                            mutated_data[i] = unsafe{rand() as u8};
                        }
                        // SystemRandom::new().fill( & mut mutated_data[..]).unwrap();
                        frames.push(frame::Frame::PathChallenge {
                            data: mutated_data,
                        });
                    },
                    frame::Frame::PathResponse {
                        data,
                    } => {
                        let mut mutated_data = data.clone();
                        mutated_data = data.clone();
                        for i in (0..8) {
                            mutated_data[i] = unsafe{rand() as u8};
                        }
                        // SystemRandom::new().fill( & mut mutated_data[..]).unwrap();
                        frames.push(frame::Frame::PathResponse {
                            data: mutated_data,
                        });
                    },
                    frame::Frame::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    } => {
                        let mut mutated_error_code = *error_code;
                        let mut mutated_frame_type = *frame_type;
                        let mut mutated_reason = reason.clone();
                        mutated_error_code = *error_code + i as u64;
                        mutated_frame_type = *frame_type + i as u64;
                        mutated_reason = reason.clone();
                        frames.push(frame::Frame::ConnectionClose {
                            error_code: mutated_error_code,
                            frame_type: mutated_frame_type,
                            reason: mutated_reason,
                        });
                    },
                    frame::Frame::ApplicationClose { 
                        error_code,
                        reason,
                    } => {
                        let mut mutated_err_code = *error_code;
                        let mut mutated_reason = reason.clone();
                        mutated_err_code = *error_code  + i as u64;
                        mutated_reason = reason.clone();
                        frames.push(frame::Frame::ApplicationClose { 
                            error_code: mutated_err_code,
                            reason: mutated_reason 
                        });
                    }
                    frame::Frame::HandshakeDone => {
                        frames.push(frame.clone());
                    },
                    frame::Frame::Datagram {
                        data,
                    } => {
                        let mut mutated_data = data.clone();
                        mutated_data = data.clone();
                        frames.push(frame::Frame::Datagram {
                            data: mutated_data,
                        });
                    },
                    frame::Frame::DatagramHeader { 
                        length 
                    } => {
                        let mut mutated_length = *length;
                        mutated_length = *length + i as usize;
                        frames.push(frame::Frame::DatagramHeader {
                            length: mutated_length,
                        });
                    },
                    frame::Frame::Others { data } => {
                        let mut mutated_data = data.clone();
                        mutated_data = data.clone();
                        frames.push(frame::Frame::Others {
                            data: mutated_data,
                        });
                    },
                }
            }
    
        }

        match self.packet_resort_type {
            pkt_resort_type::None => {
            },
            pkt_resort_type::Random => {
                // let mut rng = rand::thread_rng();
                let mut i = frames.len();
                while i > 1 {
                    i -= 1;
                    // let j = rng.gen_range(0..i+1);
                    let j = unsafe{rand() as usize}%(i+1);
                    frames.swap(i, j);
                }
            },
            pkt_resort_type::Reverse => {
                frames.reverse();
            },
            pkt_resort_type::Odd_even => {
                for i in (0..frames.len()).rev() {
                    if i%2 == 1 {
                        frames.remove(i);
                    }
                }
            },
        }
        frames
    }
    // 反向parse_struct_from_input序列化InputStruct结构体
    /*
    input{
    pkt_type: u8
    send_mili_secs: u64
    recv_mili_secs: u64
    packet_resort_type: u8
    number_of_cycles: u64
    cycles_len: [u64,number_of_cycles]
    frames : [FramesCycleStruct, number_of_cycles]
    FramesCycleStruct: {
        repeat_num: u64,
        basic_frames: [frame::Frame]
    }
     */
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::new();
        let pkt_type:u8 = match self.pkt_type {
            packet::Type::Initial => 0,
            packet::Type::Retry => 1,
            packet::Type::Handshake => 2,
            packet::Type::ZeroRTT => 3,
            packet::Type::VersionNegotiation => 4,
            packet::Type::Short => 5,
        };
        res.extend_from_slice(&pkt_type.to_le_bytes());
        // res.extend_from_slice(&(self.send_timeout.as_millis() as u64).to_le_bytes());
        // res.extend_from_slice(&(self.recv_timeout.as_millis() as u64).to_le_bytes());
        res.extend_from_slice(&self.send_timeout.to_le_bytes());
        res.extend_from_slice(&self.recv_timeout.to_le_bytes());
        let packet_resort_type:u8 = match self.packet_resort_type {
            pkt_resort_type::None => 0,
            pkt_resort_type::Random => 1,
            pkt_resort_type::Reverse => 2,
            pkt_resort_type::Odd_even => 3,
        };
        res.extend_from_slice(&packet_resort_type.to_le_bytes());
        let num_of_cycles = self.frames_cycle.len() as u64;
        res.extend_from_slice(&num_of_cycles.to_le_bytes());
        let mut frames_cycle_bytes = Vec::new();
        let mut current_framses_len:u64 =0;
        for frame_cycle in self.frames_cycle.iter(){
            frames_cycle_bytes.extend_from_slice(&(frame_cycle.repeat_num as u64).to_le_bytes());
            for frame in frame_cycle.basic_frames.clone()  {
                let mut d = [0; 153000];
                let mut b = octets::OctetsMut::with_slice(&mut d);
                let frame_len = match  frame.to_bytes(& mut b) {
                    Ok(frame_len) => {
                        frame_len
                    },
                    Err(_) => {
                        warn!("frame to bytes error: {:?}", frame);
                        continue;
                    },
                };
                frames_cycle_bytes.extend_from_slice(d[0..frame_len].to_vec().as_slice());
            }
            res.extend_from_slice(&(frames_cycle_bytes.len() as u64 - current_framses_len).to_le_bytes());
            current_framses_len = frames_cycle_bytes.len() as u64;
        }
        res.extend_from_slice(&frames_cycle_bytes);
        res
    }
}

pub fn InputStruct_deserialize(input: &[u8]) -> InputStruct {
    let pkt_type = match (input[0]%6){
        0 => packet::Type::Initial,
        1 => packet::Type::Retry,
        2 => packet::Type::Handshake,
        3 => packet::Type::ZeroRTT,
        4 => packet::Type::VersionNegotiation,
        5 => packet::Type::Short,
        _ => packet::Type::Short,
    };
    let send_mili_secs = u64::from_le_bytes(input[1..9].try_into().unwrap());
    let recv_mili_secs = u64::from_le_bytes(input[9..17].try_into().unwrap());
    let packet_resort_type = match input[17] {
        0 => pkt_resort_type::None,
        1 => pkt_resort_type::Random,
        2 => pkt_resort_type::Reverse,
        3 => pkt_resort_type::Odd_even,
        _ => pkt_resort_type::None,
    };
    let number_of_cycles = u64::from_le_bytes(input[18..26].try_into().unwrap()) as usize;
    let mut cycles_len = Vec::new();
    for i in 0..number_of_cycles {
        let cycle_len = u64::from_le_bytes(input[26+i*8..34+i*8].try_into().unwrap()) as usize;
        cycles_len.push(cycle_len);
    }
    let mut input = &input[26+number_of_cycles*8..];
    let mut frames_cycle = Vec::new();
    for i in 0..number_of_cycles{
        let cycle_len = cycles_len[i];
        let frame_cycle = FramesCycleStruct::new_with_input(pkt_type, &input[0..cycle_len]);
        input = &input[cycle_len..];
        if frame_cycle.basic_frames.len() !=0 {
            frames_cycle.push(frame_cycle);
        }
    }

    InputStruct {
        pkt_type,
        // send_timeout: Duration::from_millis(send_mili_secs),
        // recv_timeout: Duration::from_millis(recv_mili_secs),
        send_timeout: send_mili_secs,
        recv_timeout: recv_mili_secs,
        packet_resort_type,
        number_of_cycles,
        cycles_len,
        frames_cycle,
    }
}


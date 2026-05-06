use h3i::actions::h3::{Action, StreamEvent, StreamEventType, WaitType};
use h3i::{
    HTTP3_CONTROL_STREAM_TYPE_ID, QPACK_DECODER_STREAM_TYPE_ID, QPACK_ENCODER_STREAM_TYPE_ID,
};
use log::{debug, error, info, warn};
use quiche::h3::frame::Frame as QFrame;
use quiche::h3::qpack::{
    encode_int, encode_str, INDEXED, INDEXED_WITH_POST_BASE, LITERAL, LITERAL_WITH_NAME_REF,
};
use quiche::h3::Header as QHeader;
use quiche::h3::NameValue;
use quiche::{frame, h3, packet, Connection, ConnectionId, Error, Header};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    env,
    ffi::{OsStr, OsString},
    io::{self, prelude::*, ErrorKind, Read, Write},
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Output, Stdio},
    str,
    thread::sleep,
    time::Duration,
    vec,
};
// use rand::Rng;
use std::net::{SocketAddr, ToSocketAddrs};
// use ring::rand::*;
use crate::inputstruct::pkt_resort_type;
use libc::{rand, srand};
use octets::OctetsMut;

const MAX_H3_FRAME_ACTIONS: usize = 20;
const MAX_DATA_BLOCKS: usize = 8;
const MAX_CONTROL_BLOCKS: usize = 8;
const DEFAULT_H3_MAX_GENERATED_ACTIONS: usize = 8192;

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

pub fn encode_header_block(headers: &[QHeader]) -> std::result::Result<Vec<u8>, String> {
    let mut encoder = quiche::h3::qpack::Encoder::new();

    let headers_len = headers.iter().fold(0, |acc, h: &QHeader| {
        acc + h.value().len() + h.name().len() + 32
    });

    let mut header_block = vec![0; headers_len];
    let len = encoder
        .encode(headers, &mut header_block)
        .map_err(|_| "Internal Error")?;

    header_block.truncate(len);

    Ok(header_block)
}

pub fn encode_varint(value: u64) -> Vec<u8> {
    match value {
        0..=63 => vec![value as u8],
        64..=16_383 => ((value as u16) | 0x4000).to_be_bytes().to_vec(),
        16_384..=1_073_741_823 => ((value as u32) | 0x8000_0000).to_be_bytes().to_vec(),
        _ => (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
    }
}

pub fn raw_h3_frame_bytes(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = encode_varint(frame_type);
    frame.extend(encode_varint(payload.len() as u64));
    frame.extend_from_slice(payload);
    frame
}

pub fn raw_headers_frame_bytes(payload: &[u8]) -> Vec<u8> {
    raw_h3_frame_bytes(0x1, payload)
}

pub fn blocked_qpack_payload() -> Vec<u8> {
    let padding_headers = vec![
        QHeader::new(b"x-pad-a", b"aaaaaaaaaaaaaaaa"),
        QHeader::new(b"x-pad-b", b"bbbbbbbbbbbbbbbb"),
    ];
    let mut tail = encode_header_block(&padding_headers).unwrap_or_default();
    tail = tail.get(2..).unwrap_or_default().to_vec();

    let mut payload = vec![0x02, 0x00, 0x80];
    payload.extend(tail);
    payload
}

pub fn blocked_qpack_payload_with_padding(total_len: usize) -> Vec<u8> {
    let mut payload = blocked_qpack_payload();
    if total_len > payload.len() {
        payload.extend(std::iter::repeat(b'A').take(total_len - payload.len()));
    }
    payload
}

pub fn split_bytes(bytes: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    bytes
        .chunks(chunk_size.max(1))
        .map(|chunk| chunk.to_vec())
        .collect()
}

pub fn wait_duration_action(ms: u64) -> Action {
    Action::Wait {
        wait_type: WaitType::WaitDuration(Duration::from_millis(ms)),
    }
}

pub fn append_stream_bytes_script(
    actions: &mut Vec<Action>,
    stream_id: u64,
    bytes: &[u8],
    chunk_size: usize,
    _inter_chunk_wait_ms: u64,
) {
    let chunks = split_bytes(bytes, chunk_size);

    for chunk in chunks.iter() {
        actions.push(Action::StreamBytes {
            stream_id,
            fin_stream: false,
            bytes: chunk.clone(),
        });
        actions.push(Action::FlushPackets);
    }
}

pub fn append_raw_headers_stream_script(
    actions: &mut Vec<Action>,
    stream_id: u64,
    qpack_payload: &[u8],
    chunk_size: usize,
    inter_chunk_wait_ms: u64,
) {
    let frame_bytes = raw_headers_frame_bytes(qpack_payload);
    append_stream_bytes_script(
        actions,
        stream_id,
        &frame_bytes,
        chunk_size,
        inter_chunk_wait_ms,
    );
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteSendPlan {
    pub chunk_size: usize,
    pub flush_each_chunk: bool,
}

impl Default for ByteSendPlan {
    fn default() -> Self {
        Self {
            chunk_size: 1024,
            flush_each_chunk: true,
        }
    }
}

impl ByteSendPlan {
    pub fn normalized(&self) -> Self {
        Self {
            chunk_size: self.chunk_size.max(1),
            flush_each_chunk: self.flush_each_chunk,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct H3QpackPlan {
    pub steps: Vec<H3QpackStep>,
}

impl H3QpackPlan {
    pub fn to_actions(&self) -> Vec<Action> {
        let mut actions = Vec::new();

        for step in &self.steps {
            step.append_actions(&mut actions);
        }

        actions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum H3QpackStep {
    OpenEncoderStream {
        stream_id: u64,
        fin_stream: bool,
    },
    OpenDecoderStream {
        stream_id: u64,
        fin_stream: bool,
    },
    EncoderInstructions {
        stream_id: u64,
        send: ByteSendPlan,
        instructions: Vec<QpackEncoderInstruction>,
    },
    DecoderInstructions {
        stream_id: u64,
        send: ByteSendPlan,
        instructions: Vec<QpackDecoderInstruction>,
    },
    RequestHeaderBlock {
        stream_id: u64,
        fin_stream: bool,
        send: ByteSendPlan,
        block: QpackHeaderBlock,
    },
    Flush,
    WaitMs {
        ms: u64,
    },
}

impl H3QpackStep {
    pub fn append_actions(&self, actions: &mut Vec<Action>) {
        match self {
            Self::OpenEncoderStream {
                stream_id,
                fin_stream,
            } => actions.push(Action::OpenUniStream {
                stream_id: *stream_id,
                fin_stream: *fin_stream,
                stream_type: QPACK_ENCODER_STREAM_TYPE_ID,
            }),
            Self::OpenDecoderStream {
                stream_id,
                fin_stream,
            } => actions.push(Action::OpenUniStream {
                stream_id: *stream_id,
                fin_stream: *fin_stream,
                stream_type: QPACK_DECODER_STREAM_TYPE_ID,
            }),
            Self::EncoderInstructions {
                stream_id,
                send,
                instructions,
            } => {
                let payload =
                    serialize_qpack_encoder_instructions(instructions).unwrap_or_default();
                append_stream_bytes_with_plan(
                    actions,
                    *stream_id,
                    &payload,
                    false,
                    &send.normalized(),
                );
            }
            Self::DecoderInstructions {
                stream_id,
                send,
                instructions,
            } => {
                let payload =
                    serialize_qpack_decoder_instructions(instructions).unwrap_or_default();
                append_stream_bytes_with_plan(
                    actions,
                    *stream_id,
                    &payload,
                    false,
                    &send.normalized(),
                );
            }
            Self::RequestHeaderBlock {
                stream_id,
                fin_stream,
                send,
                block,
            } => {
                let payload = serialize_qpack_header_block(block).unwrap_or_default();
                let frame_bytes = raw_headers_frame_bytes(&payload);
                append_stream_bytes_with_plan(
                    actions,
                    *stream_id,
                    &frame_bytes,
                    *fin_stream,
                    &send.normalized(),
                );
            }
            Self::Flush => actions.push(Action::FlushPackets),
            Self::WaitMs { ms } => actions.push(Action::Wait {
                wait_type: WaitType::WaitDuration(Duration::from_millis(*ms)),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QpackEncoderInstruction {
    SetDynamicTableCapacity {
        capacity: u64,
    },
    InsertWithNameRef {
        is_static: bool,
        name_index: u64,
        value: Vec<u8>,
    },
    InsertWithoutNameRef {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    Duplicate {
        index: u64,
    },
    RawBytes {
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QpackDecoderInstruction {
    HeaderAck { stream_id: u64 },
    StreamCancellation { stream_id: u64 },
    InsertCountIncrement { increment: u64 },
    RawBytes { bytes: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QpackHeaderBlock {
    pub required_insert_count: u64,
    pub base: u64,
    pub fields: Vec<QpackFieldRep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QpackFieldRep {
    Indexed {
        is_static: bool,
        index: u64,
    },
    IndexedPostBase {
        index: u64,
    },
    LiteralWithNameRef {
        is_static: bool,
        name_index: u64,
        value: Vec<u8>,
    },
    LiteralWithPostBaseNameRef {
        index: u64,
        value: Vec<u8>,
    },
    Literal {
        name: Vec<u8>,
        value: Vec<u8>,
        lowercase_name: bool,
    },
}

fn estimate_qpack_encoder_size(instructions: &[QpackEncoderInstruction]) -> usize {
    let mut estimate = 16usize;

    for instruction in instructions {
        estimate += match instruction {
            QpackEncoderInstruction::SetDynamicTableCapacity { .. } => 16,
            QpackEncoderInstruction::InsertWithNameRef { value, .. } => value.len() + 16,
            QpackEncoderInstruction::InsertWithoutNameRef { name, value } => {
                name.len() + value.len() + 24
            }
            QpackEncoderInstruction::Duplicate { .. } => 16,
            QpackEncoderInstruction::RawBytes { bytes } => bytes.len(),
        };
    }

    estimate.max(16)
}

fn estimate_qpack_decoder_size(instructions: &[QpackDecoderInstruction]) -> usize {
    let mut estimate = 16usize;

    for instruction in instructions {
        estimate += match instruction {
            QpackDecoderInstruction::HeaderAck { .. }
            | QpackDecoderInstruction::StreamCancellation { .. }
            | QpackDecoderInstruction::InsertCountIncrement { .. } => 16,
            QpackDecoderInstruction::RawBytes { bytes } => bytes.len(),
        };
    }

    estimate.max(16)
}

fn estimate_qpack_header_block_size(block: &QpackHeaderBlock) -> usize {
    let mut estimate = 16usize;

    for field in &block.fields {
        estimate += match field {
            QpackFieldRep::Indexed { .. } | QpackFieldRep::IndexedPostBase { .. } => 16,
            QpackFieldRep::LiteralWithNameRef { value, .. }
            | QpackFieldRep::LiteralWithPostBaseNameRef { value, .. } => value.len() + 16,
            QpackFieldRep::Literal { name, value, .. } => name.len() + value.len() + 24,
        };
    }

    estimate.max(16)
}

fn encode_qpack_name<const LOWERCASE: bool>(
    name: &[u8],
    first: u8,
    prefix: usize,
    octets: &mut OctetsMut,
) -> std::result::Result<(), String> {
    encode_str::<LOWERCASE>(name, first, prefix, octets).map_err(|e| format!("{e:?}"))
}

fn encode_qpack_value(
    value: &[u8],
    first: u8,
    prefix: usize,
    octets: &mut OctetsMut,
) -> std::result::Result<(), String> {
    encode_str::<false>(value, first, prefix, octets).map_err(|e| format!("{e:?}"))
}

pub fn serialize_qpack_encoder_instructions(
    instructions: &[QpackEncoderInstruction],
) -> std::result::Result<Vec<u8>, String> {
    let mut buf = vec![0_u8; estimate_qpack_encoder_size(instructions)];
    let mut octets = OctetsMut::with_slice(&mut buf);

    for instruction in instructions {
        match instruction {
            QpackEncoderInstruction::SetDynamicTableCapacity { capacity } => {
                encode_int(*capacity, 0x20, 5, &mut octets).map_err(|e| format!("{e:?}"))?;
            }
            QpackEncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
            } => {
                let first = 0x80 | if *is_static { 0x40 } else { 0 };
                encode_int(*name_index, first, 6, &mut octets).map_err(|e| format!("{e:?}"))?;
                encode_qpack_value(value, 0, 7, &mut octets)?;
            }
            QpackEncoderInstruction::InsertWithoutNameRef { name, value } => {
                encode_qpack_name::<true>(name, 0x40, 6, &mut octets)?;
                encode_qpack_value(value, 0, 7, &mut octets)?;
            }
            QpackEncoderInstruction::Duplicate { index } => {
                encode_int(*index, 0x00, 5, &mut octets).map_err(|e| format!("{e:?}"))?;
            }
            QpackEncoderInstruction::RawBytes { bytes } => {
                octets.put_bytes(bytes).map_err(|e| format!("{e:?}"))?;
            }
        }
    }

    let written = octets.off();
    buf.truncate(written);
    Ok(buf)
}

pub fn serialize_qpack_decoder_instructions(
    instructions: &[QpackDecoderInstruction],
) -> std::result::Result<Vec<u8>, String> {
    let mut buf = vec![0_u8; estimate_qpack_decoder_size(instructions)];
    let mut octets = OctetsMut::with_slice(&mut buf);

    for instruction in instructions {
        match instruction {
            QpackDecoderInstruction::HeaderAck { stream_id } => {
                encode_int(*stream_id, 0x80, 7, &mut octets).map_err(|e| format!("{e:?}"))?;
            }
            QpackDecoderInstruction::StreamCancellation { stream_id } => {
                encode_int(*stream_id, 0x40, 6, &mut octets).map_err(|e| format!("{e:?}"))?;
            }
            QpackDecoderInstruction::InsertCountIncrement { increment } => {
                encode_int(*increment, 0x00, 6, &mut octets).map_err(|e| format!("{e:?}"))?;
            }
            QpackDecoderInstruction::RawBytes { bytes } => {
                octets.put_bytes(bytes).map_err(|e| format!("{e:?}"))?;
            }
        }
    }

    let written = octets.off();
    buf.truncate(written);
    Ok(buf)
}

pub fn serialize_qpack_header_block(
    block: &QpackHeaderBlock,
) -> std::result::Result<Vec<u8>, String> {
    let mut buf = vec![0_u8; estimate_qpack_header_block_size(block)];
    let mut octets = OctetsMut::with_slice(&mut buf);

    encode_int(block.required_insert_count, 0, 8, &mut octets).map_err(|e| format!("{e:?}"))?;

    let (sign_first, delta_base) = if block.base >= block.required_insert_count {
        (0_u8, block.base - block.required_insert_count)
    } else {
        (
            0x80_u8,
            block
                .required_insert_count
                .saturating_sub(block.base)
                .saturating_sub(1),
        )
    };
    encode_int(delta_base, sign_first, 7, &mut octets).map_err(|e| format!("{e:?}"))?;

    for field in &block.fields {
        match field {
            QpackFieldRep::Indexed { is_static, index } => {
                let first = INDEXED | if *is_static { 0x40 } else { 0 };
                encode_int(*index, first, 6, &mut octets).map_err(|e| format!("{e:?}"))?;
            }
            QpackFieldRep::IndexedPostBase { index } => {
                encode_int(*index, INDEXED_WITH_POST_BASE, 4, &mut octets)
                    .map_err(|e| format!("{e:?}"))?;
            }
            QpackFieldRep::LiteralWithNameRef {
                is_static,
                name_index,
                value,
            } => {
                let first = LITERAL_WITH_NAME_REF | if *is_static { 0x10 } else { 0 };
                encode_int(*name_index, first, 4, &mut octets).map_err(|e| format!("{e:?}"))?;
                encode_qpack_value(value, 0, 7, &mut octets)?;
            }
            QpackFieldRep::LiteralWithPostBaseNameRef { index, value } => {
                encode_int(*index, 0x00, 4, &mut octets).map_err(|e| format!("{e:?}"))?;
                encode_qpack_value(value, 0, 7, &mut octets)?;
            }
            QpackFieldRep::Literal {
                name,
                value,
                lowercase_name,
            } => {
                if *lowercase_name {
                    encode_qpack_name::<true>(name, LITERAL, 3, &mut octets)?;
                } else {
                    encode_qpack_name::<false>(name, LITERAL, 3, &mut octets)?;
                }
                encode_qpack_value(value, 0, 7, &mut octets)?;
            }
        }
    }

    let written = octets.off();
    buf.truncate(written);
    Ok(buf)
}

fn append_stream_bytes_with_plan(
    actions: &mut Vec<Action>,
    stream_id: u64,
    bytes: &[u8],
    fin_stream: bool,
    send: &ByteSendPlan,
) {
    let send = send.normalized();
    let chunks = split_bytes(bytes, send.chunk_size);

    if chunks.is_empty() {
        actions.push(Action::StreamBytes {
            stream_id,
            fin_stream,
            bytes: Vec::new(),
        });
        if send.flush_each_chunk {
            actions.push(Action::FlushPackets);
        }
        return;
    }

    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = idx + 1 == chunks.len();
        actions.push(Action::StreamBytes {
            stream_id,
            fin_stream: fin_stream && is_last,
            bytes: chunk.clone(),
        });
        if send.flush_each_chunk {
            actions.push(Action::FlushPackets);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H3DataBlock {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub content_length: usize,
    pub header_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    pub header_patterns: Vec<String>,
}

impl H3DataBlock {
    pub fn new() -> Self {
        Self {
            method: "".to_string(),
            path: "".to_string(),
            body: Vec::new(),
            content_length: 0,
            header_pairs: Vec::new(),
            header_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H3ControlBlock {
    pub basic_frame: QFrame,
    pub repeat_num: usize,
}

impl H3ControlBlock {
    pub fn new() -> Self {
        Self {
            basic_frame: QFrame::Unknown {
                raw_type: 0,
                payload: Vec::new(),
            },
            repeat_num: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H3Struct {
    pub send_timeout: u64,
    pub recv_timeout: u64,
    pub packet_resort_type: pkt_resort_type,
    pub data_blocks: Vec<H3DataBlock>,
    pub normal_headers: Vec<String>,
    pub control_blocks: Vec<H3ControlBlock>,
    pub data_actions: Vec<Action>,
    pub control_actions: Vec<Action>,
    #[serde(default)]
    pub qpack_plan: H3QpackPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyH3StructV0 {
    send_timeout: u64,
    recv_timeout: u64,
    packet_resort_type: pkt_resort_type,
    data_blocks: Vec<H3DataBlock>,
    normal_headers: Vec<String>,
    control_blocks: Vec<H3ControlBlock>,
    data_actions: Vec<Action>,
    control_actions: Vec<Action>,
}

impl From<LegacyH3StructV0> for H3Struct {
    fn from(value: LegacyH3StructV0) -> Self {
        Self {
            send_timeout: value.send_timeout,
            recv_timeout: value.recv_timeout,
            packet_resort_type: value.packet_resort_type,
            data_blocks: value.data_blocks,
            normal_headers: value.normal_headers,
            control_blocks: value.control_blocks,
            data_actions: value.data_actions,
            control_actions: value.control_actions,
            qpack_plan: H3QpackPlan::default(),
        }
    }
}

pub fn deserialize_h3_struct(bytes: &[u8]) -> Result<H3Struct, Box<bincode::ErrorKind>> {
    bincode::deserialize(bytes)
        .or_else(|_| bincode::deserialize::<LegacyH3StructV0>(bytes).map(Into::into))
}

impl H3Struct {
    pub fn new() -> Self {
        let headers: Vec<String> = vec![
            "user-agent".to_string(),
            "accept".to_string(),
            "accept-encoding".to_string(),
            "accept-language".to_string(),
            "cache-control".to_string(),
            "connection".to_string(),
            "content-type".to_string(),
            "cookie".to_string(),
            "authorization".to_string(),
            "origin".to_string(),
            "referer".to_string(),
            "if-none-match".to_string(),
            "if-match".to_string(),
            "range".to_string(),
            "te".to_string(),
            "transfer-encoding".to_string(),
            "upgrade".to_string(),
            "keep-alive".to_string(),
            "proxy-connection".to_string(),
            "x-forwarded-for".to_string(),
            "x-http-method-override".to_string(),
        ];
        Self {
            send_timeout: 0,
            recv_timeout: 0,
            packet_resort_type: pkt_resort_type::None,
            data_blocks: Vec::new(),
            normal_headers: headers,
            control_blocks: Vec::new(),
            data_actions: Vec::new(),
            control_actions: Vec::new(),
            qpack_plan: H3QpackPlan::default(),
        }
    }

    fn block_has_pattern(block: &H3DataBlock, pattern: &str) -> bool {
        block
            .header_patterns
            .iter()
            .any(|item| item.eq_ignore_ascii_case(pattern))
    }

    fn header_list_for_block(block: &H3DataBlock) -> Vec<QHeader> {
        let omit_method = Self::block_has_pattern(block, "omit_method");
        let omit_scheme = Self::block_has_pattern(block, "omit_scheme");
        let omit_authority = Self::block_has_pattern(block, "omit_authority");
        let omit_path = Self::block_has_pattern(block, "omit_path");
        let omit_content_length = Self::block_has_pattern(block, "omit_content_length");
        let extras_first = Self::block_has_pattern(block, "extras_first");
        let duplicate_content_length = Self::block_has_pattern(block, "duplicate_content_length");

        let mut default_headers = Vec::new();
        if !omit_method {
            default_headers.push(QHeader::new(b":method", block.method.as_bytes()));
        }
        if !omit_scheme {
            default_headers.push(QHeader::new(b":scheme", b"https"));
        }
        if !omit_authority {
            default_headers.push(QHeader::new(b":authority", b"myserver.xx"));
        }
        if !omit_path {
            default_headers.push(QHeader::new(b":path", block.path.as_bytes()));
        }
        if !omit_content_length {
            default_headers.push(QHeader::new(
                b"content-length",
                block.content_length.to_string().as_bytes(),
            ));
        }

        let extra_headers = block
            .header_pairs
            .iter()
            .map(|(name, value)| QHeader::new(name.as_slice(), value.as_slice()))
            .collect::<Vec<_>>();

        let mut headers = if extras_first {
            let mut merged = extra_headers;
            merged.extend(default_headers);
            merged
        } else {
            let mut merged = default_headers;
            merged.extend(extra_headers);
            merged
        };

        if duplicate_content_length {
            headers.push(QHeader::new(
                b"content-length",
                block
                    .content_length
                    .saturating_add(1)
                    .to_string()
                    .as_bytes(),
            ));
        }

        headers
    }

    fn trailer_header_block() -> Vec<u8> {
        let trailer_headers = vec![QHeader::new(b"x-fuzz-trailer", b"done")];
        encode_header_block(&trailer_headers).unwrap_or_default()
    }

    fn split_body(body: &[u8], parts: usize) -> Vec<Vec<u8>> {
        if body.is_empty() || parts <= 1 {
            return vec![body.to_vec()];
        }

        let bytes = body;
        let chunk_size = ((bytes.len() + parts - 1) / parts).max(1);
        bytes
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>()
    }

    fn wait_action_for_block(block: &H3DataBlock, stream_id: u64) -> Option<Action> {
        if Self::block_has_pattern(block, "wait_headers") {
            return Some(Action::Wait {
                wait_type: WaitType::StreamEvent(StreamEvent {
                    stream_id,
                    event_type: StreamEventType::Headers,
                }),
            });
        }
        if Self::block_has_pattern(block, "wait_data") {
            return Some(Action::Wait {
                wait_type: WaitType::StreamEvent(StreamEvent {
                    stream_id,
                    event_type: StreamEventType::Data,
                }),
            });
        }
        if Self::block_has_pattern(block, "wait_finished") {
            return Some(Action::Wait {
                wait_type: WaitType::StreamEvent(StreamEvent {
                    stream_id,
                    event_type: StreamEventType::Finished,
                }),
            });
        }
        None
    }

    fn trim_actions_to_frame_budget(actions: Vec<Action>) -> Vec<Action> {
        let mut trimmed = Vec::with_capacity(actions.len().min(MAX_H3_FRAME_ACTIONS * 2));
        let mut sent_frames = 0usize;

        for action in actions {
            let counts_as_frame = matches!(
                action,
                Action::SendFrame { .. } | Action::SendHeadersFrame { .. }
            );
            if counts_as_frame && sent_frames >= MAX_H3_FRAME_ACTIONS {
                continue;
            }
            if counts_as_frame {
                sent_frames += 1;
            }
            trimmed.push(action);
        }

        trimmed
    }

    fn cap_action_plan(mut actions: Vec<Action>) -> Vec<Action> {
        let limit = env_usize(
            "MERCURIUZZ_H3_MAX_GENERATED_ACTIONS",
            DEFAULT_H3_MAX_GENERATED_ACTIONS,
        );

        if limit == 0 || actions.len() <= limit {
            return actions;
        }

        warn!(
            "h3 action plan truncated: actions={} limit={}",
            actions.len(),
            limit
        );
        actions.truncate(limit);

        if !matches!(
            actions.last(),
            Some(Action::FlushPackets | Action::Wait { .. } | Action::ConnectionClose { .. })
        ) {
            actions.push(Action::FlushPackets);
        }

        actions
    }

    fn apply_resort(actions: &mut Vec<Action>, resort_type: pkt_resort_type) {
        match resort_type {
            pkt_resort_type::None => {}
            pkt_resort_type::Random => {
                let mut i = actions.len();
                while i > 1 {
                    let j = unsafe { rand() as usize } % i;
                    i -= 1;
                    actions.swap(i, j);
                }
            }
            pkt_resort_type::Reverse => {
                actions.reverse();
            }
            pkt_resort_type::Odd_even => {
                if actions.len() >= 2 {
                    let mut cur_pos = actions.len() as isize - 2;
                    while cur_pos >= 0 {
                        let del_pos = (unsafe { rand() as usize } % 2) + cur_pos as usize;
                        if del_pos >= actions.len() {
                            break;
                        }
                        actions.remove(del_pos);
                        cur_pos -= 2;
                    }
                }
            }
        }
    }

    pub fn gen_frames(self) -> Vec<Action> {
        const CLIENT_CONTROL_STREAM_ID: u64 = 2;
        let mut cur_stream_id = 0;
        let mut basic_data_actions: Vec<Action> = Vec::new();
        let mut basic_control_actions: Vec<Action> = Vec::new();
        for (block_idx, block) in self.data_blocks.iter().take(MAX_DATA_BLOCKS).enumerate() {
            if block_idx > 0 && self.send_timeout > 0 {
                basic_data_actions.push(Action::Wait {
                    wait_type: WaitType::WaitDuration(Duration::from_millis(self.send_timeout)),
                });
            }

            let headers = Self::header_list_for_block(block);
            let header_block = encode_header_block(&headers).unwrap_or_default();
            let has_trailers = Self::block_has_pattern(block, "trailers");
            let split_body = Self::block_has_pattern(block, "split_body");
            let data_before_headers = Self::block_has_pattern(block, "data_before_headers");
            let force_empty_data = Self::block_has_pattern(block, "empty_data");
            let body_chunks = if force_empty_data {
                vec![Vec::new()]
            } else if split_body {
                Self::split_body(&block.body, 2)
            } else {
                vec![block.body.clone()]
            };

            let mut per_stream_actions = Vec::new();

            if data_before_headers {
                for (chunk_idx, payload) in body_chunks.iter().enumerate() {
                    let is_last_chunk = chunk_idx + 1 == body_chunks.len();
                    per_stream_actions.push(Action::SendFrame {
                        stream_id: cur_stream_id,
                        fin_stream: is_last_chunk && !has_trailers,
                        frame: QFrame::Data {
                            payload: payload.clone(),
                        },
                    });
                }
                per_stream_actions.push(Action::SendFrame {
                    stream_id: cur_stream_id,
                    fin_stream: !has_trailers,
                    frame: QFrame::Headers { header_block },
                });
            } else {
                let fin_on_headers = body_chunks.is_empty() && !has_trailers;
                per_stream_actions.push(Action::SendFrame {
                    stream_id: cur_stream_id,
                    fin_stream: fin_on_headers,
                    frame: QFrame::Headers { header_block },
                });
                for (chunk_idx, payload) in body_chunks.iter().enumerate() {
                    let is_last_chunk = chunk_idx + 1 == body_chunks.len();
                    per_stream_actions.push(Action::SendFrame {
                        stream_id: cur_stream_id,
                        fin_stream: is_last_chunk && !has_trailers,
                        frame: QFrame::Data {
                            payload: payload.clone(),
                        },
                    });
                }
            }

            if has_trailers {
                per_stream_actions.push(Action::SendFrame {
                    stream_id: cur_stream_id,
                    fin_stream: true,
                    frame: QFrame::Headers {
                        header_block: Self::trailer_header_block(),
                    },
                });
            }

            if let Some(wait_action) = Self::wait_action_for_block(block, cur_stream_id) {
                per_stream_actions.push(wait_action);
            }

            basic_data_actions.extend(per_stream_actions);
            cur_stream_id += 4;
        }
        for (block_idx, block) in self
            .control_blocks
            .iter()
            .take(MAX_CONTROL_BLOCKS)
            .enumerate()
        {
            if basic_control_actions.is_empty() {
                basic_control_actions.push(Action::OpenUniStream {
                    stream_id: CLIENT_CONTROL_STREAM_ID,
                    fin_stream: false,
                    stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
                });
            }
            for i in 0..block.repeat_num.min(MAX_H3_FRAME_ACTIONS) {
                match &block.basic_frame {
                    QFrame::Data { payload } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::Data {
                                payload: payload.clone(),
                            },
                        });
                    }
                    QFrame::Headers { header_block } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::Headers {
                                header_block: header_block.clone(),
                            },
                        });
                    }
                    QFrame::CancelPush { push_id } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::CancelPush {
                                push_id: push_id + i as u64,
                            },
                        });
                    }
                    QFrame::Settings {
                        max_field_section_size,
                        qpack_max_table_capacity,
                        qpack_blocked_streams,
                        connect_protocol_enabled,
                        h3_datagram,
                        grease,
                        additional_settings,
                        raw,
                    } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::Settings {
                                max_field_section_size: *max_field_section_size,
                                qpack_max_table_capacity: *qpack_max_table_capacity,
                                qpack_blocked_streams: *qpack_blocked_streams,
                                connect_protocol_enabled: *connect_protocol_enabled,
                                h3_datagram: *h3_datagram,
                                grease: *grease,
                                additional_settings: additional_settings.clone(),
                                raw: raw.clone(),
                            },
                        });
                    }
                    QFrame::PushPromise {
                        push_id,
                        header_block,
                    } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::PushPromise {
                                push_id: push_id + i as u64,
                                header_block: header_block.clone(),
                            },
                        });
                    }
                    QFrame::GoAway { id } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::GoAway { id: id + i as u64 },
                        });
                    }
                    QFrame::MaxPushId { push_id } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::MaxPushId {
                                push_id: push_id + i as u64,
                            },
                        });
                    }
                    QFrame::PriorityUpdateRequest {
                        prioritized_element_id,
                        priority_field_value,
                    } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::PriorityUpdateRequest {
                                prioritized_element_id: prioritized_element_id + i as u64,
                                priority_field_value: priority_field_value.clone(),
                            },
                        });
                    }
                    QFrame::PriorityUpdatePush {
                        prioritized_element_id,
                        priority_field_value,
                    } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::PriorityUpdatePush {
                                prioritized_element_id: prioritized_element_id + i as u64,
                                priority_field_value: priority_field_value.clone(),
                            },
                        });
                    }
                    QFrame::Unknown { raw_type, payload } => {
                        basic_control_actions.push(Action::SendFrame {
                            stream_id: CLIENT_CONTROL_STREAM_ID,
                            fin_stream: false,
                            frame: QFrame::Unknown {
                                raw_type: raw_type + i as u64,
                                payload: payload.clone(),
                            },
                        });
                    }
                }
            }
            if block_idx + 1 != self.control_blocks.len() && self.send_timeout > 0 {
                basic_control_actions.push(Action::Wait {
                    wait_type: WaitType::WaitDuration(Duration::from_millis(self.send_timeout)),
                });
            }
        }

        let mut actions = Vec::new();
        actions.extend(self.control_actions.clone());
        actions.extend(self.qpack_plan.to_actions());
        actions.extend(basic_control_actions.clone());
        actions.extend(self.data_actions.clone());
        actions.extend(basic_data_actions.clone());

        if self.recv_timeout > 0 {
            actions.push(Action::Wait {
                wait_type: WaitType::WaitDuration(Duration::from_millis(self.recv_timeout)),
            });
        }

        let mut actions = Self::trim_actions_to_frame_budget(actions);
        actions = Self::cap_action_plan(actions);
        Self::apply_resort(&mut actions, self.packet_resort_type);
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_qpack_encoder_instruction_vectors() {
        let encoded = serialize_qpack_encoder_instructions(&[
            QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 32 },
            QpackEncoderInstruction::InsertWithoutNameRef {
                name: b"x".to_vec(),
                value: b"y".to_vec(),
            },
        ])
        .unwrap();

        assert_eq!(encoded, vec![0x3f, 0x01, 0x41, 0xf3, 0x81, 0xf5]);
    }

    #[test]
    fn serialize_qpack_decoder_instruction_vectors() {
        let encoded = serialize_qpack_decoder_instructions(&[
            QpackDecoderInstruction::HeaderAck { stream_id: 3 },
            QpackDecoderInstruction::StreamCancellation { stream_id: 4 },
            QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
        ])
        .unwrap();

        assert_eq!(encoded, vec![0x83, 0x44, 0x01]);
    }

    #[test]
    fn serialize_qpack_header_block_vectors() {
        let encoded = serialize_qpack_header_block(&QpackHeaderBlock {
            required_insert_count: 0,
            base: 0,
            fields: vec![QpackFieldRep::Literal {
                name: b"a".to_vec(),
                value: b"b".to_vec(),
                lowercase_name: true,
            }],
        })
        .unwrap();

        assert_eq!(encoded, vec![0x00, 0x00, 0x29, 0x1f, 0x81, 0x8f]);
    }

    #[test]
    fn qpack_plan_to_actions_preserves_order_and_chunking() {
        let block = QpackHeaderBlock {
            required_insert_count: 0,
            base: 0,
            fields: vec![QpackFieldRep::Literal {
                name: b"a".to_vec(),
                value: b"b".to_vec(),
                lowercase_name: true,
            }],
        };
        let expected_header_bytes =
            raw_headers_frame_bytes(&serialize_qpack_header_block(&block).unwrap());
        let actions = H3QpackPlan {
            steps: vec![
                H3QpackStep::OpenEncoderStream {
                    stream_id: 6,
                    fin_stream: false,
                },
                H3QpackStep::EncoderInstructions {
                    stream_id: 6,
                    send: ByteSendPlan {
                        chunk_size: 2,
                        flush_each_chunk: true,
                    },
                    instructions: vec![QpackEncoderInstruction::SetDynamicTableCapacity {
                        capacity: 32,
                    }],
                },
                H3QpackStep::RequestHeaderBlock {
                    stream_id: 0,
                    fin_stream: true,
                    send: ByteSendPlan {
                        chunk_size: 2,
                        flush_each_chunk: false,
                    },
                    block,
                },
                H3QpackStep::Flush,
                H3QpackStep::WaitMs { ms: 5 },
            ],
        }
        .to_actions();

        assert_eq!(
            actions[0],
            Action::OpenUniStream {
                stream_id: 6,
                fin_stream: false,
                stream_type: QPACK_ENCODER_STREAM_TYPE_ID,
            }
        );
        assert_eq!(
            actions[1],
            Action::StreamBytes {
                stream_id: 6,
                fin_stream: false,
                bytes: vec![0x3f, 0x01],
            }
        );
        assert_eq!(actions[2], Action::FlushPackets);
        assert_eq!(
            actions[3],
            Action::StreamBytes {
                stream_id: 0,
                fin_stream: false,
                bytes: expected_header_bytes[0..2].to_vec(),
            }
        );
        assert_eq!(
            actions[4],
            Action::StreamBytes {
                stream_id: 0,
                fin_stream: false,
                bytes: expected_header_bytes[2..4].to_vec(),
            }
        );
        assert_eq!(
            actions[5],
            Action::StreamBytes {
                stream_id: 0,
                fin_stream: false,
                bytes: expected_header_bytes[4..6].to_vec(),
            }
        );
        assert_eq!(
            actions[6],
            Action::StreamBytes {
                stream_id: 0,
                fin_stream: true,
                bytes: expected_header_bytes[6..8].to_vec(),
            }
        );
        assert_eq!(actions[7], Action::FlushPackets);
        assert_eq!(
            actions[8],
            Action::Wait {
                wait_type: WaitType::WaitDuration(Duration::from_millis(5)),
            }
        );
    }

    #[test]
    fn legacy_h3_struct_deserializes_with_default_qpack_plan() {
        let legacy = LegacyH3StructV0 {
            send_timeout: 1,
            recv_timeout: 2,
            packet_resort_type: pkt_resort_type::None,
            data_blocks: vec![H3DataBlock::new()],
            normal_headers: vec!["user-agent".to_string()],
            control_blocks: Vec::new(),
            data_actions: vec![Action::FlushPackets],
            control_actions: Vec::new(),
        };

        let bytes = bincode::serialize(&legacy).unwrap();
        let decoded = deserialize_h3_struct(&bytes).unwrap();

        assert_eq!(decoded.send_timeout, 1);
        assert_eq!(decoded.recv_timeout, 2);
        assert_eq!(decoded.data_blocks.len(), 1);
        assert_eq!(decoded.data_actions, vec![Action::FlushPackets]);
        assert!(decoded.qpack_plan.steps.is_empty());
    }
}

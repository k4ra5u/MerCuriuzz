use core::{
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use std::{
    cmp::{max, min},
    env,
    sync::Arc,
};

use libafl_bolts::alloc::{borrow::Cow, vec::Vec};
use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type, Merge, NamedTuple},
    Named,
};

use log::{debug, error, info, warn};
use nix::sys::select;
use quiche::{
    frame,
    h3::{self, NameValue},
    packet,
    range_buf::{DefaultBufFactory, RangeBuf},
    stream, BufFactory, Connection, ConnectionId, Header,
};
use ring::aead::quic;
use serde::{
    de::{value::BytesDeserializer, IntoDeserializer},
    Deserialize, Serialize,
};

use crate::inputstruct::{
    h3_input::{
        append_raw_headers_stream_script, blocked_qpack_payload,
        blocked_qpack_payload_with_padding, deserialize_h3_struct, raw_headers_frame_bytes,
        serialize_qpack_decoder_instructions, serialize_qpack_encoder_instructions,
        serialize_qpack_header_block, split_bytes, ByteSendPlan, H3ControlBlock, H3DataBlock,
        H3QpackPlan, H3QpackStep, H3Struct, QpackDecoderInstruction, QpackEncoderInstruction,
        QpackFieldRep, QpackHeaderBlock,
    },
    *,
};
use h3i::actions::h3::{Action, WaitType};
use h3i::{
    HTTP3_CONTROL_STREAM_TYPE_ID, HTTP3_PUSH_STREAM_TYPE_ID, QPACK_DECODER_STREAM_TYPE_ID,
    QPACK_ENCODER_STREAM_TYPE_ID,
};
use libafl::mutators::MutationId;
use libafl::prelude::buffer_copy;
use libafl::{
    corpus::{Corpus, CorpusId},
    inputs::HasMutatorBytes,
    mutators::{
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
            ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
            BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator,
            BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator,
            CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator,
            DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
        },
        token_mutations::{TokenInsert, TokenReplace},
        MutationResult, Mutator, MutatorsTuple,
    },
    state::{HasCorpus, HasRand},
    Error, HasMetadata,
};
use quiche::h3::frame::Frame as QFrame;

const MAX_FRAME_BYTES: u64 = 4096;
const CLIENT_CONTROL_STREAM_ID: u64 = 2;
const MAX_H3_FRAME_ACTIONS: usize = 64;
const MAX_DATA_BLOCKS: usize = 8;
const MAX_CONTROL_BLOCKS: usize = 8;
const MAX_ACTION_LIST_LEN: usize = 32;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HEADER_VALUE_LEN: usize = 2048;
const MAX_CONTENT_LENGTH_FIELD: usize = 1 << 20;
const MAX_ACTION_BYTES: usize = 4096;
const MAX_METHOD_LEN: usize = 32;
const MAX_PATH_LEN: usize = 256;
const MAX_HEADER_PAIR_COUNT: usize = 16;
const MAX_HEADER_PATTERN_COUNT: usize = 8;
const MAX_ACTION_REASON_BYTES: usize = 256;
const MAX_CONTROL_REPEAT_NUM: usize = 64;
const MAX_MUTATED_TIMEOUT_MS: u64 = 1000;
const MAX_TESTCASE_BYTES: usize = 4 * 1024 * 1024;
const MAX_QPACK_BLOCKED_PAYLOAD: usize = 16 * 1024;
const MAX_QPACK_PLAN_STEPS: usize = 32;
const MAX_QPACK_INSTRUCTION_COUNT: usize = 16;
const MAX_QPACK_FIELD_COUNT: usize = 16;
const RFC_VARINT_MAX: u64 = (1u64 << 62) - 1;
const QPACK_BLOCKED_PAYLOAD_BUCKETS: &[usize] = &[0, 16, 64, 256, 1024, 4096, 8 * 1024, 16 * 1024];
const QPACK_CHUNK_BUCKETS: &[usize] = &[256, 1024, 2048, 4096];
const QPACK_STREAM_REPEAT_BUCKETS: &[usize] = &[1, 1, 2, 2];
const QPACK_CONTROL_STREAM_BYTES: &[u8] = &[0x3f, 0xe1, 0xff, 0x00, 0x01, 0x02];
const QPACK_DECODER_STREAM_BYTES: &[u8] = &[0x80, 0x00, 0xff];
const HEADER_PATTERNS: &[&str] = &[
    "omit_method",
    "omit_scheme",
    "omit_authority",
    "omit_path",
    "omit_content_length",
    "extras_first",
    "duplicate_content_length",
    "trailers",
    "data_before_headers",
    "split_body",
    "empty_data",
];
const VARINT_EDGE_VALUES: &[u64] = &[
    0,
    1,
    2,
    3,
    4,
    7,
    8,
    15,
    16,
    31,
    32,
    63,
    64,
    127,
    128,
    255,
    256,
    1023,
    1024,
    4095,
    4096,
    16383,
    16384,
    65535,
    65536,
    1_048_575,
    1_048_576,
    1_073_741_823,
    1_073_741_824,
    2_147_483_647,
    2_147_483_648,
    4_294_967_295,
    4_294_967_296,
    1_099_511_627_775,
    1_099_511_627_776,
    281_474_976_710_655,
    281_474_976_710_656,
    1_152_921_504_606_846_975,
    2_305_843_009_213_693_951,
    4_611_686_018_427_387_902,
    4_611_686_018_427_387_903,
];

fn random_u62<S>(state: &mut S) -> u64
where
    S: HasRand,
{
    let top = state.rand_mut().below(4) as u64;
    let mid = state.rand_mut().below(1 << 30) as u64;
    let low = state.rand_mut().below(1 << 30) as u64;
    ((top << 60) | (mid << 30) | low).min(RFC_VARINT_MAX)
}

fn random_varint_edge<S>(state: &mut S) -> u64
where
    S: HasRand,
{
    let idx = state.rand_mut().below(VARINT_EDGE_VALUES.len()) as usize;
    let edge = VARINT_EDGE_VALUES[idx];

    match state.rand_mut().below(4) {
        0 => edge,
        1 => {
            let delta = state.rand_mut().below(1 << 16) as u64;
            if state.rand_mut().below(2) == 0 {
                edge.saturating_sub(delta)
            } else {
                edge.saturating_add(delta).min(RFC_VARINT_MAX)
            }
        }
        2 => random_u62(state),
        _ => {
            let hi = state.rand_mut().below(1 << 30) as u64;
            let lo = state.rand_mut().below(1 << 30) as u64;
            ((hi << 30) | lo).min(RFC_VARINT_MAX)
        }
    }
}

fn random_bytes<S>(state: &mut S, max_len: usize) -> Vec<u8>
where
    S: HasRand,
{
    let len = 1 + state.rand_mut().below(max_len.max(1)) as usize;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(state.rand_mut().below(256) as u8);
    }
    bytes
}

fn choose_from_slice<S, T>(state: &mut S, choices: &[T]) -> T
where
    S: HasRand,
    T: Copy,
{
    choices[state.rand_mut().below(choices.len()) as usize]
}

fn is_request_stream_id(stream_id: u64) -> bool {
    stream_id & 0x3 == 0
}

fn is_control_uni_stream_id(stream_id: u64) -> bool {
    stream_id & 0x3 == 2
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn push_unique_u64(values: &mut Vec<u64>, value: u64) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn truncate_bytes(bytes: &mut Vec<u8>, limit: usize) {
    if bytes.len() > limit {
        bytes.truncate(limit);
    }
}

fn sanitize_qframe(frame: &mut QFrame) {
    match frame {
        QFrame::Data { payload }
        | QFrame::Headers {
            header_block: payload,
        }
        | QFrame::Unknown {
            raw_type: _,
            payload,
        } => truncate_bytes(payload, MAX_ACTION_BYTES),
        QFrame::PushPromise {
            push_id: _,
            header_block,
        } => {
            truncate_bytes(header_block, MAX_ACTION_BYTES);
        }
        QFrame::PriorityUpdateRequest {
            prioritized_element_id: _,
            priority_field_value,
        }
        | QFrame::PriorityUpdatePush {
            prioritized_element_id: _,
            priority_field_value,
        } => truncate_bytes(priority_field_value, MAX_ACTION_BYTES),
        QFrame::Settings {
            additional_settings,
            raw,
            ..
        } => {
            if let Some(settings) = additional_settings {
                settings.truncate(8);
            }
            if let Some(settings) = raw {
                settings.truncate(8);
            }
        }
        _ => {}
    }
}

fn sanitize_action(action: &mut Action) {
    match action {
        Action::SendFrame { frame, .. } | Action::SendHeadersFrame { frame, .. } => {
            sanitize_qframe(frame);
        }
        Action::StreamBytes { bytes, .. } => truncate_bytes(bytes, MAX_ACTION_BYTES),
        Action::ConnectionClose { error } => {
            truncate_bytes(&mut error.reason, MAX_ACTION_REASON_BYTES)
        }
        Action::OpenUniStream { .. }
        | Action::ResetStream { .. }
        | Action::StopSending { .. }
        | Action::FlushPackets
        | Action::Wait { .. } => {}
    }
}

fn sanitize_action_list(actions: &mut Vec<Action>) {
    if actions.len() > MAX_ACTION_LIST_LEN {
        actions.truncate(MAX_ACTION_LIST_LEN);
    }

    for action in actions.iter_mut() {
        sanitize_action(action);
    }
}

fn sanitize_data_block(block: &mut H3DataBlock) {
    if block.method.len() > MAX_METHOD_LEN {
        block.method.truncate(MAX_METHOD_LEN);
    }
    if block.path.len() > MAX_PATH_LEN {
        block.path.truncate(MAX_PATH_LEN);
    }
    truncate_bytes(&mut block.body, MAX_FRAME_BYTES as usize);
    block.content_length = block.content_length.min(MAX_CONTENT_LENGTH_FIELD);
    if block.header_pairs.len() > MAX_HEADER_PAIR_COUNT {
        block.header_pairs.truncate(MAX_HEADER_PAIR_COUNT);
    }
    for (name, value) in block.header_pairs.iter_mut() {
        truncate_bytes(name, MAX_HEADER_NAME_LEN);
        truncate_bytes(value, MAX_HEADER_VALUE_LEN);
    }
    block.header_patterns.retain(|pattern| {
        HEADER_PATTERNS.contains(&pattern.as_str()) || is_wait_header_pattern(pattern)
    });
    block.header_patterns.sort();
    block.header_patterns.dedup();
    if block.header_patterns.len() > MAX_HEADER_PATTERN_COUNT {
        block.header_patterns.truncate(MAX_HEADER_PATTERN_COUNT);
    }
}

fn sanitize_control_block(block: &mut H3ControlBlock) {
    block.repeat_num = block.repeat_num.min(MAX_CONTROL_REPEAT_NUM);
    sanitize_qframe(&mut block.basic_frame);
}

fn sanitize_send_plan(send: &mut ByteSendPlan) {
    send.chunk_size = send.chunk_size.clamp(1, MAX_ACTION_BYTES);
}

fn sanitize_qpack_encoder_instruction(instruction: &mut QpackEncoderInstruction) {
    match instruction {
        QpackEncoderInstruction::SetDynamicTableCapacity { capacity }
        | QpackEncoderInstruction::Duplicate { index: capacity } => {
            *capacity = (*capacity).min(RFC_VARINT_MAX);
        }
        QpackEncoderInstruction::InsertWithNameRef {
            name_index, value, ..
        } => {
            *name_index = (*name_index).min(RFC_VARINT_MAX);
            truncate_bytes(value, MAX_HEADER_VALUE_LEN);
        }
        QpackEncoderInstruction::InsertWithoutNameRef { name, value } => {
            truncate_bytes(name, MAX_HEADER_NAME_LEN);
            truncate_bytes(value, MAX_HEADER_VALUE_LEN);
        }
        QpackEncoderInstruction::RawBytes { bytes } => {
            truncate_bytes(bytes, MAX_ACTION_BYTES);
        }
    }
}

fn sanitize_qpack_decoder_instruction(instruction: &mut QpackDecoderInstruction) {
    match instruction {
        QpackDecoderInstruction::HeaderAck { stream_id }
        | QpackDecoderInstruction::StreamCancellation { stream_id }
        | QpackDecoderInstruction::InsertCountIncrement {
            increment: stream_id,
        } => {
            *stream_id = (*stream_id).min(RFC_VARINT_MAX);
        }
        QpackDecoderInstruction::RawBytes { bytes } => {
            truncate_bytes(bytes, MAX_ACTION_BYTES);
        }
    }
}

fn sanitize_qpack_field_rep(field: &mut QpackFieldRep) {
    match field {
        QpackFieldRep::Indexed { index, .. }
        | QpackFieldRep::IndexedPostBase { index }
        | QpackFieldRep::LiteralWithNameRef {
            name_index: index, ..
        }
        | QpackFieldRep::LiteralWithPostBaseNameRef { index, .. } => {
            *index = (*index).min(RFC_VARINT_MAX);
        }
        QpackFieldRep::Literal { name, value, .. } => {
            truncate_bytes(name, MAX_HEADER_NAME_LEN);
            truncate_bytes(value, MAX_HEADER_VALUE_LEN);
        }
    }

    match field {
        QpackFieldRep::LiteralWithNameRef { value, .. }
        | QpackFieldRep::LiteralWithPostBaseNameRef { value, .. } => {
            truncate_bytes(value, MAX_HEADER_VALUE_LEN);
        }
        _ => {}
    }
}

fn sanitize_qpack_header_block(block: &mut QpackHeaderBlock) {
    block.required_insert_count = block.required_insert_count.min(RFC_VARINT_MAX);
    block.base = block.base.min(RFC_VARINT_MAX);
    if block.fields.len() > MAX_QPACK_FIELD_COUNT {
        block.fields.truncate(MAX_QPACK_FIELD_COUNT);
    }
    for field in block.fields.iter_mut() {
        sanitize_qpack_field_rep(field);
    }

    if serialize_qpack_header_block(block)
        .map(|bytes| bytes.len() > MAX_QPACK_BLOCKED_PAYLOAD)
        .unwrap_or(false)
    {
        while block.fields.len() > 1 {
            block.fields.pop();
            if serialize_qpack_header_block(block)
                .map(|bytes| bytes.len() <= MAX_QPACK_BLOCKED_PAYLOAD)
                .unwrap_or(false)
            {
                break;
            }
        }
    }
}

fn sanitize_qpack_step(step: &mut H3QpackStep) {
    match step {
        H3QpackStep::OpenEncoderStream { .. }
        | H3QpackStep::OpenDecoderStream { .. }
        | H3QpackStep::Flush => {}
        H3QpackStep::WaitMs { ms } => {
            *ms = (*ms).min(MAX_MUTATED_TIMEOUT_MS);
        }
        H3QpackStep::EncoderInstructions {
            send, instructions, ..
        } => {
            sanitize_send_plan(send);
            if instructions.len() > MAX_QPACK_INSTRUCTION_COUNT {
                instructions.truncate(MAX_QPACK_INSTRUCTION_COUNT);
            }
            for instruction in instructions.iter_mut() {
                sanitize_qpack_encoder_instruction(instruction);
            }
            if serialize_qpack_encoder_instructions(instructions)
                .map(|bytes| bytes.len() > MAX_QPACK_BLOCKED_PAYLOAD)
                .unwrap_or(false)
            {
                while instructions.len() > 1 {
                    instructions.pop();
                    if serialize_qpack_encoder_instructions(instructions)
                        .map(|bytes| bytes.len() <= MAX_QPACK_BLOCKED_PAYLOAD)
                        .unwrap_or(false)
                    {
                        break;
                    }
                }
            }
        }
        H3QpackStep::DecoderInstructions {
            send, instructions, ..
        } => {
            sanitize_send_plan(send);
            if instructions.len() > MAX_QPACK_INSTRUCTION_COUNT {
                instructions.truncate(MAX_QPACK_INSTRUCTION_COUNT);
            }
            for instruction in instructions.iter_mut() {
                sanitize_qpack_decoder_instruction(instruction);
            }
            if serialize_qpack_decoder_instructions(instructions)
                .map(|bytes| bytes.len() > MAX_QPACK_BLOCKED_PAYLOAD)
                .unwrap_or(false)
            {
                while instructions.len() > 1 {
                    instructions.pop();
                    if serialize_qpack_decoder_instructions(instructions)
                        .map(|bytes| bytes.len() <= MAX_QPACK_BLOCKED_PAYLOAD)
                        .unwrap_or(false)
                    {
                        break;
                    }
                }
            }
        }
        H3QpackStep::RequestHeaderBlock { send, block, .. } => {
            sanitize_send_plan(send);
            sanitize_qpack_header_block(block);
        }
    }
}

fn sanitize_qpack_plan(plan: &mut H3QpackPlan) {
    if plan.steps.len() > MAX_QPACK_PLAN_STEPS {
        plan.steps.truncate(MAX_QPACK_PLAN_STEPS);
    }
    for step in plan.steps.iter_mut() {
        sanitize_qpack_step(step);
    }
}

fn sanitize_h3_corp(h3_corp: &mut H3Struct) {
    h3_corp.send_timeout = h3_corp.send_timeout.min(MAX_MUTATED_TIMEOUT_MS);
    h3_corp.recv_timeout = h3_corp.recv_timeout.min(MAX_MUTATED_TIMEOUT_MS);
    if h3_corp.data_blocks.len() > MAX_DATA_BLOCKS {
        h3_corp.data_blocks.truncate(MAX_DATA_BLOCKS);
    }
    if h3_corp.control_blocks.len() > MAX_CONTROL_BLOCKS {
        h3_corp.control_blocks.truncate(MAX_CONTROL_BLOCKS);
    }
    for block in h3_corp.data_blocks.iter_mut() {
        sanitize_data_block(block);
    }
    for block in h3_corp.control_blocks.iter_mut() {
        sanitize_control_block(block);
    }
    sanitize_action_list(&mut h3_corp.data_actions);
    sanitize_action_list(&mut h3_corp.control_actions);
    sanitize_qpack_plan(&mut h3_corp.qpack_plan);
}

fn load_h3_input<I>(input: &I) -> Option<H3Struct>
where
    I: HasMutatorBytes,
{
    let testcase_limit = env_usize("MERCURIUZZ_H3_MAX_TESTCASE_BYTES", MAX_TESTCASE_BYTES);
    if input.bytes().len() > testcase_limit {
        warn!(
            "skip h3 mutation for oversized testcase: testcase_bytes={} limit={}",
            input.bytes().len(),
            testcase_limit
        );
        return None;
    }

    match deserialize_h3_struct(input.bytes()) {
        Ok(h3_corp) => Some(h3_corp),
        Err(err) => {
            warn!("skip malformed h3 mutation input: {}", err);
            None
        }
    }
}

fn store_h3_input<I>(input: &mut I, h3_corp: &mut H3Struct)
where
    I: HasMutatorBytes,
{
    sanitize_h3_corp(h3_corp);
    let changed_bytes = bincode::serialize(h3_corp).unwrap();
    input.resize(changed_bytes.len(), 0);
    unsafe {
        buffer_copy(
            input.bytes_mut(),
            changed_bytes.as_slice(),
            0,
            0,
            changed_bytes.len(),
        );
    }
}

macro_rules! load_h3_corp_or_skip {
    ($input:expr) => {
        match load_h3_input($input) {
            Some(h3_corp) => h3_corp,
            None => return Ok(MutationResult::Skipped),
        }
    };
}

fn collect_stream_ids_from_actions(
    ids: &mut Vec<u64>,
    actions: &[Action],
    predicate: fn(u64) -> bool,
) {
    for action in actions {
        match action {
            Action::SendFrame { stream_id, .. }
            | Action::SendHeadersFrame { stream_id, .. }
            | Action::StreamBytes { stream_id, .. }
            | Action::ResetStream { stream_id, .. }
            | Action::StopSending { stream_id, .. }
            | Action::OpenUniStream { stream_id, .. } => {
                if predicate(*stream_id) {
                    push_unique_u64(ids, *stream_id);
                }
            }
            Action::Wait {
                wait_type: WaitType::StreamEvent(event),
            } => {
                if predicate(event.stream_id) {
                    push_unique_u64(ids, event.stream_id);
                }
            }
            Action::Wait { .. } | Action::FlushPackets | Action::ConnectionClose { .. } => {}
        }
    }
}

fn collect_request_stream_ids(h3_corp: &H3Struct) -> Vec<u64> {
    let mut ids = Vec::new();

    for idx in 0..h3_corp.data_blocks.len() {
        push_unique_u64(&mut ids, (idx as u64) * 4);
    }

    for step in &h3_corp.qpack_plan.steps {
        if let H3QpackStep::RequestHeaderBlock { stream_id, .. } = step {
            if is_request_stream_id(*stream_id) {
                push_unique_u64(&mut ids, *stream_id);
            }
        }
    }

    collect_stream_ids_from_actions(&mut ids, &h3_corp.data_actions, is_request_stream_id);
    collect_stream_ids_from_actions(&mut ids, &h3_corp.control_actions, is_request_stream_id);

    if ids.is_empty() {
        ids.push(0);
    }

    ids.sort_unstable();
    ids
}

fn is_wait_header_pattern(pattern: &str) -> bool {
    matches!(pattern, "wait_headers" | "wait_data" | "wait_finished")
}

fn strip_wait_primitives(h3_corp: &mut H3Struct) {
    h3_corp.send_timeout = 0;
    h3_corp.recv_timeout = 0;
    h3_corp
        .data_actions
        .retain(|action| !matches!(action, Action::Wait { .. }));
    h3_corp
        .control_actions
        .retain(|action| !matches!(action, Action::Wait { .. }));

    for block in &mut h3_corp.data_blocks {
        block
            .header_patterns
            .retain(|pattern| !is_wait_header_pattern(pattern));
    }
    h3_corp
        .qpack_plan
        .steps
        .retain(|step| !matches!(step, H3QpackStep::WaitMs { .. }));
}

fn collect_control_stream_ids(h3_corp: &H3Struct) -> Vec<u64> {
    let mut ids = Vec::new();

    for step in &h3_corp.qpack_plan.steps {
        match step {
            H3QpackStep::OpenEncoderStream { stream_id, .. }
            | H3QpackStep::OpenDecoderStream { stream_id, .. }
            | H3QpackStep::EncoderInstructions { stream_id, .. }
            | H3QpackStep::DecoderInstructions { stream_id, .. } => {
                if is_control_uni_stream_id(*stream_id) {
                    push_unique_u64(&mut ids, *stream_id);
                }
            }
            H3QpackStep::RequestHeaderBlock { .. }
            | H3QpackStep::Flush
            | H3QpackStep::WaitMs { .. } => {}
        }
    }

    collect_stream_ids_from_actions(&mut ids, &h3_corp.control_actions, is_control_uni_stream_id);
    collect_stream_ids_from_actions(&mut ids, &h3_corp.data_actions, is_control_uni_stream_id);

    if ids.is_empty() {
        ids.push(CLIENT_CONTROL_STREAM_ID);
    }

    ids.sort_unstable();
    ids
}

fn next_control_stream_id(h3_corp: &H3Struct) -> u64 {
    collect_control_stream_ids(h3_corp)
        .into_iter()
        .max()
        .map(|id| id + 4)
        .unwrap_or(CLIENT_CONTROL_STREAM_ID)
}

fn random_control_stream_id<S>(state: &mut S, h3_corp: &H3Struct) -> u64
where
    S: HasRand,
{
    let ids = collect_control_stream_ids(h3_corp);
    ids[state.rand_mut().below(ids.len()) as usize]
}

fn random_control_stream_type<S>(state: &mut S) -> u64
where
    S: HasRand,
{
    match state.rand_mut().below(5) {
        0 => HTTP3_CONTROL_STREAM_TYPE_ID,
        1 => QPACK_ENCODER_STREAM_TYPE_ID,
        2 => QPACK_DECODER_STREAM_TYPE_ID,
        3 => 0x21,
        _ => random_varint_edge(state),
    }
}

fn random_qpack_payload_len<S>(state: &mut S, amplified: bool) -> usize
where
    S: HasRand,
{
    let min_len = blocked_qpack_payload().len();
    let bucket = if amplified {
        choose_from_slice(state, &QPACK_BLOCKED_PAYLOAD_BUCKETS[4..])
    } else {
        choose_from_slice(state, &QPACK_BLOCKED_PAYLOAD_BUCKETS)
    };

    min(MAX_QPACK_BLOCKED_PAYLOAD, max(min_len, bucket.max(min_len)))
}

fn synthesize_qpack_payload<S>(state: &mut S, total_len: usize) -> Vec<u8>
where
    S: HasRand,
{
    let mut payload = blocked_qpack_payload_with_padding(total_len);
    if payload.len() > 3 {
        let mutate_rounds = 1 + state.rand_mut().below(3) as usize;
        for _ in 0..mutate_rounds {
            let idx = 3 + state.rand_mut().below(payload.len() - 3) as usize;
            payload[idx] = state.rand_mut().below(256) as u8;
        }
    }

    payload
}

fn base_settings_frame(blocked_streams: u64) -> QFrame {
    QFrame::Settings {
        max_field_section_size: None,
        qpack_max_table_capacity: None,
        qpack_blocked_streams: Some(blocked_streams),
        connect_protocol_enabled: None,
        h3_datagram: None,
        grease: None,
        additional_settings: None,
        raw: None,
    }
}

fn qpack_noise_bytes<S>(state: &mut S, base: &[u8]) -> Vec<u8>
where
    S: HasRand,
{
    let mut bytes = base.to_vec();
    let extra_len = state.rand_mut().below(16) as usize;
    for _ in 0..extra_len {
        bytes.push(state.rand_mut().below(256) as u8);
    }
    if !bytes.is_empty() {
        let idx = state.rand_mut().below(bytes.len()) as usize;
        bytes[idx] = state.rand_mut().below(256) as u8;
    }
    bytes
}

fn random_send_plan<S>(state: &mut S) -> ByteSendPlan
where
    S: HasRand,
{
    ByteSendPlan {
        chunk_size: choose_from_slice(state, QPACK_CHUNK_BUCKETS),
        flush_each_chunk: state.rand_mut().below(2) == 0,
    }
}

fn qpack_literal(name: &[u8], value: &[u8]) -> QpackFieldRep {
    QpackFieldRep::Literal {
        name: name.to_vec(),
        value: value.to_vec(),
        lowercase_name: true,
    }
}

fn basic_qpack_request_fields(path: &[u8]) -> Vec<QpackFieldRep> {
    vec![
        qpack_literal(b":method", b"GET"),
        qpack_literal(b":scheme", b"https"),
        qpack_literal(b":authority", b"myserver.xx"),
        qpack_literal(b":path", path),
    ]
}

fn padded_qpack_request_block(
    path: &[u8],
    required_insert_count: u64,
    base: u64,
    pad_len: usize,
) -> QpackHeaderBlock {
    let mut fields = basic_qpack_request_fields(path);
    fields.push(QpackFieldRep::Indexed {
        is_static: false,
        index: 0,
    });

    if pad_len > 0 {
        fields.push(QpackFieldRep::Literal {
            name: b"x-pad".to_vec(),
            value: vec![b'A'; pad_len.min(MAX_QPACK_BLOCKED_PAYLOAD)],
            lowercase_name: true,
        });
    }

    QpackHeaderBlock {
        required_insert_count,
        base,
        fields,
    }
}

fn qpack_insert_without_name_ref(name: &[u8], value: &[u8]) -> QpackEncoderInstruction {
    QpackEncoderInstruction::InsertWithoutNameRef {
        name: name.to_vec(),
        value: value.to_vec(),
    }
}

fn qpack_open_encoder_step(stream_id: u64) -> H3QpackStep {
    H3QpackStep::OpenEncoderStream {
        stream_id,
        fin_stream: false,
    }
}

fn qpack_open_decoder_step(stream_id: u64) -> H3QpackStep {
    H3QpackStep::OpenDecoderStream {
        stream_id,
        fin_stream: false,
    }
}

fn qpack_encoder_step(
    stream_id: u64,
    send: ByteSendPlan,
    instructions: Vec<QpackEncoderInstruction>,
) -> H3QpackStep {
    H3QpackStep::EncoderInstructions {
        stream_id,
        send,
        instructions,
    }
}

fn qpack_decoder_step(
    stream_id: u64,
    send: ByteSendPlan,
    instructions: Vec<QpackDecoderInstruction>,
) -> H3QpackStep {
    H3QpackStep::DecoderInstructions {
        stream_id,
        send,
        instructions,
    }
}

fn qpack_request_step(
    stream_id: u64,
    fin_stream: bool,
    send: ByteSendPlan,
    block: QpackHeaderBlock,
) -> H3QpackStep {
    H3QpackStep::RequestHeaderBlock {
        stream_id,
        fin_stream,
        send,
        block,
    }
}

fn qpack_plan_insert_then_use() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_encoder_step(
                6,
                ByteSendPlan::default(),
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 1024 },
                    qpack_insert_without_name_ref(b"x-seed", b"alpha"),
                ],
            ),
            H3QpackStep::Flush,
            qpack_request_step(
                0,
                false,
                ByteSendPlan::default(),
                QpackHeaderBlock {
                    required_insert_count: 1,
                    base: 1,
                    fields: {
                        let mut fields = basic_qpack_request_fields(b"/qpack/insert-then-use");
                        fields.push(QpackFieldRep::Indexed {
                            is_static: false,
                            index: 0,
                        });
                        fields
                    },
                },
            ),
            H3QpackStep::Flush,
        ],
    }
}

fn qpack_plan_blocked_then_unblock() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_request_step(
                0,
                false,
                ByteSendPlan::default(),
                QpackHeaderBlock {
                    required_insert_count: 1,
                    base: 1,
                    fields: {
                        let mut fields = basic_qpack_request_fields(b"/qpack/blocked-then-unblock");
                        fields.push(QpackFieldRep::Indexed {
                            is_static: false,
                            index: 0,
                        });
                        fields
                    },
                },
            ),
            H3QpackStep::Flush,
            qpack_encoder_step(
                6,
                ByteSendPlan::default(),
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 1024 },
                    qpack_insert_without_name_ref(b"x-seed", b"beta"),
                ],
            ),
            H3QpackStep::Flush,
        ],
    }
}

fn qpack_plan_post_base_reference() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_encoder_step(
                6,
                ByteSendPlan::default(),
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 1024 },
                    qpack_insert_without_name_ref(b"x-a", b"one"),
                    qpack_insert_without_name_ref(b"x-b", b"two"),
                ],
            ),
            H3QpackStep::Flush,
            qpack_request_step(
                0,
                false,
                ByteSendPlan::default(),
                QpackHeaderBlock {
                    required_insert_count: 2,
                    base: 1,
                    fields: {
                        let mut fields = basic_qpack_request_fields(b"/qpack/post-base");
                        fields.push(QpackFieldRep::LiteralWithPostBaseNameRef {
                            index: 0,
                            value: b"two".to_vec(),
                        });
                        fields
                    },
                },
            ),
            H3QpackStep::Flush,
        ],
    }
}

fn qpack_plan_duplicate_chain() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_encoder_step(
                6,
                ByteSendPlan::default(),
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 1024 },
                    qpack_insert_without_name_ref(b"x-chain", b"first"),
                    QpackEncoderInstruction::Duplicate { index: 0 },
                    QpackEncoderInstruction::Duplicate { index: 1 },
                ],
            ),
            H3QpackStep::Flush,
            qpack_request_step(
                0,
                false,
                ByteSendPlan::default(),
                QpackHeaderBlock {
                    required_insert_count: 3,
                    base: 3,
                    fields: {
                        let mut fields = basic_qpack_request_fields(b"/qpack/duplicate-chain");
                        fields.push(QpackFieldRep::Indexed {
                            is_static: false,
                            index: 0,
                        });
                        fields.push(QpackFieldRep::Indexed {
                            is_static: false,
                            index: 1,
                        });
                        fields
                    },
                },
            ),
            H3QpackStep::Flush,
        ],
    }
}

fn qpack_plan_ack_then_cancel() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_open_decoder_step(10),
            qpack_encoder_step(
                6,
                ByteSendPlan::default(),
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 1024 },
                    qpack_insert_without_name_ref(b"x-seed", b"gamma"),
                ],
            ),
            H3QpackStep::Flush,
            qpack_request_step(
                0,
                false,
                ByteSendPlan::default(),
                QpackHeaderBlock {
                    required_insert_count: 1,
                    base: 1,
                    fields: {
                        let mut fields = basic_qpack_request_fields(b"/qpack/ack-then-cancel");
                        fields.push(QpackFieldRep::Indexed {
                            is_static: false,
                            index: 0,
                        });
                        fields
                    },
                },
            ),
            H3QpackStep::Flush,
            qpack_decoder_step(
                10,
                ByteSendPlan::default(),
                vec![
                    QpackDecoderInstruction::HeaderAck { stream_id: 0 },
                    QpackDecoderInstruction::StreamCancellation { stream_id: 0 },
                    QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                ],
            ),
            H3QpackStep::Flush,
        ],
    }
}

fn qpack_scenario_plan(index: usize) -> H3QpackPlan {
    match index % 5 {
        0 => qpack_plan_insert_then_use(),
        1 => qpack_plan_blocked_then_unblock(),
        2 => qpack_plan_post_base_reference(),
        3 => qpack_plan_duplicate_chain(),
        _ => qpack_plan_ack_then_cancel(),
    }
}

fn ensure_qpack_plan_seed<S>(state: &mut S, h3_corp: &mut H3Struct)
where
    S: HasRand,
{
    if h3_corp.qpack_plan.steps.is_empty() {
        h3_corp.qpack_plan = qpack_scenario_plan(state.rand_mut().below(5) as usize);
    }
}

fn count_insert_like_instructions(steps: &[H3QpackStep], limit: usize) -> u64 {
    let mut count = 0_u64;

    for step in steps.iter().take(limit) {
        if let H3QpackStep::EncoderInstructions { instructions, .. } = step {
            for instruction in instructions {
                if matches!(
                    instruction,
                    QpackEncoderInstruction::InsertWithNameRef { .. }
                        | QpackEncoderInstruction::InsertWithoutNameRef { .. }
                        | QpackEncoderInstruction::Duplicate { .. }
                ) {
                    count = count.saturating_add(1);
                }
            }
        }
    }

    count
}

fn qpack_plan_request_streams(plan: &H3QpackPlan) -> Vec<u64> {
    let mut streams = Vec::new();
    for step in &plan.steps {
        if let H3QpackStep::RequestHeaderBlock { stream_id, .. } = step {
            push_unique_u64(&mut streams, *stream_id);
        }
    }
    if streams.is_empty() {
        streams.push(0);
    }
    streams
}

fn random_qpack_encoder_instruction<S>(state: &mut S) -> QpackEncoderInstruction
where
    S: HasRand,
{
    match state.rand_mut().below(5) {
        0 => QpackEncoderInstruction::SetDynamicTableCapacity {
            capacity: random_varint_edge(state),
        },
        1 => QpackEncoderInstruction::InsertWithNameRef {
            is_static: state.rand_mut().below(2) == 0,
            name_index: random_varint_edge(state),
            value: random_header_value(state),
        },
        2 => qpack_insert_without_name_ref(&random_header_name(state), &random_header_value(state)),
        3 => QpackEncoderInstruction::Duplicate {
            index: random_varint_edge(state),
        },
        _ => QpackEncoderInstruction::RawBytes {
            bytes: qpack_noise_bytes(state, QPACK_CONTROL_STREAM_BYTES),
        },
    }
}

fn random_qpack_decoder_instruction<S>(
    state: &mut S,
    request_streams: &[u64],
) -> QpackDecoderInstruction
where
    S: HasRand,
{
    let stream_id = request_streams[state.rand_mut().below(request_streams.len()) as usize];

    match state.rand_mut().below(4) {
        0 => QpackDecoderInstruction::HeaderAck { stream_id },
        1 => QpackDecoderInstruction::StreamCancellation { stream_id },
        2 => QpackDecoderInstruction::InsertCountIncrement {
            increment: 1 + state.rand_mut().below(16) as u64,
        },
        _ => QpackDecoderInstruction::RawBytes {
            bytes: qpack_noise_bytes(state, QPACK_DECODER_STREAM_BYTES),
        },
    }
}

fn random_qpack_field_rep<S>(state: &mut S) -> QpackFieldRep
where
    S: HasRand,
{
    match state.rand_mut().below(5) {
        0 => QpackFieldRep::Indexed {
            is_static: state.rand_mut().below(2) == 0,
            index: random_varint_edge(state),
        },
        1 => QpackFieldRep::IndexedPostBase {
            index: random_varint_edge(state),
        },
        2 => QpackFieldRep::LiteralWithNameRef {
            is_static: state.rand_mut().below(2) == 0,
            name_index: random_varint_edge(state),
            value: random_header_value(state),
        },
        3 => QpackFieldRep::LiteralWithPostBaseNameRef {
            index: random_varint_edge(state),
            value: random_header_value(state),
        },
        _ => QpackFieldRep::Literal {
            name: random_header_name(state),
            value: random_header_value(state),
            lowercase_name: state.rand_mut().below(2) == 0,
        },
    }
}

fn random_qpack_step<S>(state: &mut S, h3_corp: &H3Struct) -> H3QpackStep
where
    S: HasRand,
{
    let request_streams = qpack_plan_request_streams(&h3_corp.qpack_plan);
    let request_stream_id = request_streams[state.rand_mut().below(request_streams.len()) as usize];
    let control_stream_id = next_control_stream_id(h3_corp);

    match state.rand_mut().below(7) {
        0 => qpack_open_encoder_step(control_stream_id),
        1 => qpack_open_decoder_step(control_stream_id),
        2 => qpack_encoder_step(
            control_stream_id,
            random_send_plan(state),
            vec![random_qpack_encoder_instruction(state)],
        ),
        3 => qpack_decoder_step(
            control_stream_id,
            random_send_plan(state),
            vec![random_qpack_decoder_instruction(state, &request_streams)],
        ),
        4 => qpack_request_step(
            request_stream_id,
            state.rand_mut().below(2) == 0,
            random_send_plan(state),
            QpackHeaderBlock {
                required_insert_count: state.rand_mut().below(3) as u64,
                base: state.rand_mut().below(3) as u64,
                fields: vec![
                    qpack_literal(b":method", b"GET"),
                    qpack_literal(b":scheme", b"https"),
                    qpack_literal(b":authority", b"myserver.xx"),
                    qpack_literal(b":path", b"/qpack/random"),
                    random_qpack_field_rep(state),
                ],
            },
        ),
        5 => H3QpackStep::Flush,
        _ => H3QpackStep::WaitMs {
            ms: state.rand_mut().below(MAX_MUTATED_TIMEOUT_MS as usize) as u64,
        },
    }
}

fn ensure_settings_block(h3_corp: &mut H3Struct) -> &mut H3ControlBlock {
    let idx = if let Some(idx) = h3_corp
        .control_blocks
        .iter()
        .position(|block| matches!(block.basic_frame, QFrame::Settings { .. }))
    {
        idx
    } else {
        h3_corp.control_blocks.push(H3ControlBlock {
            basic_frame: base_settings_frame(0),
            repeat_num: 1,
        });
        h3_corp.control_blocks.len() - 1
    };

    &mut h3_corp.control_blocks[idx]
}

fn rebuild_qpack_blocked_script<S>(state: &mut S, h3_corp: &mut H3Struct, amplified: bool)
where
    S: HasRand,
{
    let stream_count = choose_from_slice(state, QPACK_STREAM_REPEAT_BUCKETS).max(1);
    let payload_len = random_qpack_payload_len(state, amplified);
    let chunk_size = choose_from_slice(state, QPACK_CHUNK_BUCKETS);

    h3_corp.send_timeout = 0;
    h3_corp.recv_timeout = 0;
    h3_corp.packet_resort_type = pkt_resort_type::None;
    h3_corp.data_blocks.clear();
    h3_corp.control_blocks.clear();
    h3_corp.data_actions.clear();
    h3_corp.control_actions.clear();

    h3_corp.control_actions.push(Action::OpenUniStream {
        stream_id: CLIENT_CONTROL_STREAM_ID,
        fin_stream: false,
        stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
    });
    h3_corp.control_actions.push(Action::SendFrame {
        stream_id: CLIENT_CONTROL_STREAM_ID,
        fin_stream: false,
        frame: base_settings_frame(stream_count as u64 + 2),
    });
    h3_corp.control_actions.push(Action::FlushPackets);

    let mut steps = Vec::new();

    if state.rand_mut().below(2) == 0 {
        steps.push(qpack_open_encoder_step(6));
        steps.push(qpack_encoder_step(
            6,
            ByteSendPlan {
                chunk_size,
                flush_each_chunk: true,
            },
            vec![QpackEncoderInstruction::RawBytes {
                bytes: qpack_noise_bytes(state, QPACK_CONTROL_STREAM_BYTES),
            }],
        ));
        steps.push(H3QpackStep::Flush);
    }

    if state.rand_mut().below(3) == 0 {
        steps.push(qpack_open_decoder_step(10));
        steps.push(qpack_decoder_step(
            10,
            ByteSendPlan {
                chunk_size,
                flush_each_chunk: true,
            },
            vec![QpackDecoderInstruction::RawBytes {
                bytes: qpack_noise_bytes(state, QPACK_DECODER_STREAM_BYTES),
            }],
        ));
        steps.push(H3QpackStep::Flush);
    }

    for stream_index in 0..stream_count {
        let required_insert_count = 1;
        let base = required_insert_count;
        let block = padded_qpack_request_block(
            if amplified {
                b"/qpack/blocked-amplified"
            } else {
                b"/qpack/blocked"
            },
            required_insert_count,
            base,
            payload_len,
        );

        steps.push(qpack_request_step(
            (stream_index as u64) * 4,
            false,
            ByteSendPlan {
                chunk_size,
                flush_each_chunk: true,
            },
            block,
        ));
    }

    h3_corp.qpack_plan = H3QpackPlan { steps };
    sanitize_h3_corp(h3_corp);
}

fn random_len_bucket<S>(state: &mut S, max_len: usize) -> usize
where
    S: HasRand,
{
    if max_len == 0 {
        return 0;
    }

    match state.rand_mut().below(5) {
        0 => state.rand_mut().below(max_len.min(8) + 1) as usize,
        1 | 2 => state.rand_mut().below(max_len.min(128) + 1) as usize,
        3 => state.rand_mut().below(max_len.min(1024) + 1) as usize,
        _ => state.rand_mut().below(max_len + 1) as usize,
    }
}

fn random_text_char<S>(
    state: &mut S,
    allow_ctl: bool,
    allow_upper: bool,
    allow_separators: bool,
) -> char
where
    S: HasRand,
{
    match state.rand_mut().below(if allow_ctl { 6 } else { 5 }) {
        0 => (b'a' + state.rand_mut().below(26) as u8) as char,
        1 => (b'0' + state.rand_mut().below(10) as u8) as char,
        2 => {
            let punctuation = b"!#$%&'*+-.^_`|~:/?=@[]{}(),;";
            punctuation[state.rand_mut().below(punctuation.len()) as usize] as char
        }
        3 if allow_upper => (b'A' + state.rand_mut().below(26) as u8) as char,
        3 | 4 if allow_separators => {
            let separators = [b' ', b'\t'];
            separators[state.rand_mut().below(separators.len()) as usize] as char
        }
        _ if allow_ctl => state.rand_mut().below(32) as u8 as char,
        _ => (33 + state.rand_mut().below(94) as u8) as char,
    }
}

fn random_string<S>(
    state: &mut S,
    max_len: usize,
    allow_ctl: bool,
    allow_upper: bool,
    allow_separators: bool,
) -> String
where
    S: HasRand,
{
    let len = random_len_bucket(state, max_len);
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(random_text_char(
            state,
            allow_ctl,
            allow_upper,
            allow_separators,
        ));
    }
    out
}

fn random_fuzz_byte<S>(state: &mut S) -> u8
where
    S: HasRand,
{
    match state.rand_mut().below(6) {
        0 => state.rand_mut().below(32) as u8,
        1 => 32 + state.rand_mut().below(95) as u8,
        2 => 128 + state.rand_mut().below(128) as u8,
        3 => {
            let specials = [b':', b'-', b'_', b'/', b'?', b'=', b'&', b' '];
            specials[state.rand_mut().below(specials.len()) as usize]
        }
        _ => state.rand_mut().below(256) as u8,
    }
}

fn random_byte_vec<S>(state: &mut S, max_len: usize) -> Vec<u8>
where
    S: HasRand,
{
    let len = random_len_bucket(state, max_len);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(random_fuzz_byte(state));
    }
    out
}

fn random_header_name<S>(state: &mut S) -> Vec<u8>
where
    S: HasRand,
{
    let special = [
        b":authority".as_slice(),
        b":method".as_slice(),
        b":path".as_slice(),
        b":scheme".as_slice(),
        b"content-length".as_slice(),
        b"connection".as_slice(),
        b"transfer-encoding".as_slice(),
        b"proxy-connection".as_slice(),
    ];

    if state.rand_mut().below(4) == 0 {
        return special[state.rand_mut().below(special.len()) as usize].to_vec();
    }

    let mut name = random_byte_vec(state, MAX_HEADER_NAME_LEN);
    if name.is_empty() {
        name.push(b'x');
    }
    if state.rand_mut().below(4) == 0 && !name.starts_with(b":") {
        name.insert(0, b':');
    }
    name
}

fn random_header_value<S>(state: &mut S) -> Vec<u8>
where
    S: HasRand,
{
    random_byte_vec(state, MAX_HEADER_VALUE_LEN)
}

fn random_body_bytes<S>(state: &mut S) -> Vec<u8>
where
    S: HasRand,
{
    random_byte_vec(state, MAX_FRAME_BYTES as usize)
}

fn random_content_length_field<S>(state: &mut S) -> usize
where
    S: HasRand,
{
    let value = random_varint_edge(state);
    if value > MAX_CONTENT_LENGTH_FIELD as u64 {
        MAX_CONTENT_LENGTH_FIELD
    } else {
        value as usize
    }
}

fn random_request_stream_id<S>(state: &mut S, h3_corp: &H3Struct) -> u64
where
    S: HasRand,
{
    let ids = collect_request_stream_ids(h3_corp);
    ids[state.rand_mut().below(ids.len()) as usize]
}

fn random_request_stream_id_with_count<S>(state: &mut S, data_block_count: usize) -> u64
where
    S: HasRand,
{
    if data_block_count == 0 {
        0
    } else {
        (state.rand_mut().below(data_block_count) as u64) * 4
    }
}

fn random_uni_stream_id<S>(state: &mut S) -> u64
where
    S: HasRand,
{
    2 + (state.rand_mut().below(6) as u64) * 4
}

fn random_action<S>(state: &mut S, h3_corp: &H3Struct, prefer_control: bool) -> Action
where
    S: HasRand,
{
    if prefer_control && h3_corp.control_actions.is_empty() && state.rand_mut().below(2) == 0 {
        return Action::OpenUniStream {
            stream_id: CLIENT_CONTROL_STREAM_ID,
            fin_stream: false,
            stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
        };
    }

    let target_request_stream = random_request_stream_id(state, h3_corp);
    let target_control_stream = random_control_stream_id(state, h3_corp);

    match state.rand_mut().below(5) {
        0 => Action::FlushPackets,
        1 => Action::ResetStream {
            stream_id: if prefer_control {
                target_control_stream
            } else {
                target_request_stream
            },
            error_code: random_varint_edge(state),
        },
        2 => Action::StopSending {
            stream_id: if prefer_control {
                target_control_stream
            } else {
                target_request_stream
            },
            error_code: random_varint_edge(state),
        },
        3 => Action::OpenUniStream {
            stream_id: if state.rand_mut().below(3) == 0 {
                next_control_stream_id(h3_corp)
            } else {
                random_uni_stream_id(state)
            },
            fin_stream: state.rand_mut().below(2) == 0,
            stream_type: match state.rand_mut().below(6) {
                0 => HTTP3_CONTROL_STREAM_TYPE_ID,
                1 => HTTP3_PUSH_STREAM_TYPE_ID,
                2 => QPACK_ENCODER_STREAM_TYPE_ID,
                3 => QPACK_DECODER_STREAM_TYPE_ID,
                4 => 0x21,
                _ => random_varint_edge(state),
            },
        },
        _ => Action::StreamBytes {
            stream_id: if prefer_control {
                target_control_stream
            } else {
                target_request_stream
            },
            fin_stream: state.rand_mut().below(2) == 0,
            bytes: random_bytes(
                state,
                if prefer_control {
                    MAX_ACTION_BYTES
                } else {
                    MAX_FRAME_BYTES as usize
                },
            ),
        },
    }
}

fn qpack_encoder_step_indices(plan: &H3QpackPlan) -> Vec<usize> {
    plan.steps
        .iter()
        .enumerate()
        .filter_map(|(idx, step)| match step {
            H3QpackStep::EncoderInstructions { .. } => Some(idx),
            _ => None,
        })
        .collect()
}

fn qpack_decoder_step_indices(plan: &H3QpackPlan) -> Vec<usize> {
    plan.steps
        .iter()
        .enumerate()
        .filter_map(|(idx, step)| match step {
            H3QpackStep::DecoderInstructions { .. } => Some(idx),
            _ => None,
        })
        .collect()
}

fn qpack_request_step_indices(plan: &H3QpackPlan) -> Vec<usize> {
    plan.steps
        .iter()
        .enumerate()
        .filter_map(|(idx, step)| match step {
            H3QpackStep::RequestHeaderBlock { .. } => Some(idx),
            _ => None,
        })
        .collect()
}

fn ensure_qpack_encoder_step<S>(state: &mut S, h3_corp: &mut H3Struct) -> usize
where
    S: HasRand,
{
    ensure_qpack_plan_seed(state, h3_corp);
    if let Some(idx) = qpack_encoder_step_indices(&h3_corp.qpack_plan)
        .first()
        .copied()
    {
        idx
    } else {
        let step = qpack_encoder_step(
            next_control_stream_id(h3_corp),
            ByteSendPlan::default(),
            vec![random_qpack_encoder_instruction(state)],
        );
        h3_corp.qpack_plan.steps.push(step);
        h3_corp.qpack_plan.steps.len() - 1
    }
}

fn ensure_qpack_decoder_step<S>(state: &mut S, h3_corp: &mut H3Struct) -> usize
where
    S: HasRand,
{
    ensure_qpack_plan_seed(state, h3_corp);
    if let Some(idx) = qpack_decoder_step_indices(&h3_corp.qpack_plan)
        .first()
        .copied()
    {
        idx
    } else {
        let request_streams = qpack_plan_request_streams(&h3_corp.qpack_plan);
        let step = qpack_decoder_step(
            next_control_stream_id(h3_corp),
            ByteSendPlan::default(),
            vec![random_qpack_decoder_instruction(state, &request_streams)],
        );
        h3_corp.qpack_plan.steps.push(step);
        h3_corp.qpack_plan.steps.len() - 1
    }
}

fn ensure_qpack_request_step<S>(state: &mut S, h3_corp: &mut H3Struct) -> usize
where
    S: HasRand,
{
    ensure_qpack_plan_seed(state, h3_corp);
    if let Some(idx) = qpack_request_step_indices(&h3_corp.qpack_plan)
        .first()
        .copied()
    {
        idx
    } else {
        let request_stream_id = random_request_stream_id(state, h3_corp);
        h3_corp.qpack_plan.steps.push(qpack_request_step(
            request_stream_id,
            false,
            ByteSendPlan::default(),
            QpackHeaderBlock {
                required_insert_count: 0,
                base: 0,
                fields: vec![
                    qpack_literal(b":method", b"GET"),
                    qpack_literal(b":scheme", b"https"),
                    qpack_literal(b":authority", b"myserver.xx"),
                    qpack_literal(b":path", b"/qpack/generated"),
                ],
            },
        ));
        h3_corp.qpack_plan.steps.len() - 1
    }
}

fn mutate_qpack_encoder_instruction<S>(state: &mut S, instruction: &mut QpackEncoderInstruction)
where
    S: HasRand,
{
    match instruction {
        QpackEncoderInstruction::SetDynamicTableCapacity { capacity } => {
            *capacity = random_varint_edge(state);
        }
        QpackEncoderInstruction::InsertWithNameRef {
            is_static,
            name_index,
            value,
        } => {
            *is_static = state.rand_mut().below(2) == 0;
            *name_index = random_varint_edge(state);
            *value = random_header_value(state);
        }
        QpackEncoderInstruction::InsertWithoutNameRef { name, value } => {
            *name = random_header_name(state);
            *value = random_header_value(state);
        }
        QpackEncoderInstruction::Duplicate { index } => {
            *index = random_varint_edge(state);
        }
        QpackEncoderInstruction::RawBytes { bytes } => {
            if bytes.is_empty() || state.rand_mut().below(2) == 0 {
                *bytes = qpack_noise_bytes(state, QPACK_CONTROL_STREAM_BYTES);
            } else {
                let pos = state.rand_mut().below(bytes.len()) as usize;
                bytes[pos] = random_fuzz_byte(state);
            }
        }
    }
}

fn mutate_qpack_decoder_instruction<S>(
    state: &mut S,
    instruction: &mut QpackDecoderInstruction,
    request_streams: &[u64],
) where
    S: HasRand,
{
    match instruction {
        QpackDecoderInstruction::HeaderAck { stream_id }
        | QpackDecoderInstruction::StreamCancellation { stream_id } => {
            *stream_id = request_streams[state.rand_mut().below(request_streams.len()) as usize];
        }
        QpackDecoderInstruction::InsertCountIncrement { increment } => {
            *increment = 1 + state.rand_mut().below(32) as u64;
        }
        QpackDecoderInstruction::RawBytes { bytes } => {
            if bytes.is_empty() || state.rand_mut().below(2) == 0 {
                *bytes = qpack_noise_bytes(state, QPACK_DECODER_STREAM_BYTES);
            } else {
                let pos = state.rand_mut().below(bytes.len()) as usize;
                bytes[pos] = random_fuzz_byte(state);
            }
        }
    }
}

fn mutate_qpack_field_rep<S>(state: &mut S, field: &mut QpackFieldRep)
where
    S: HasRand,
{
    match field {
        QpackFieldRep::Indexed { is_static, index } => {
            *is_static = state.rand_mut().below(2) == 0;
            *index = random_varint_edge(state);
        }
        QpackFieldRep::IndexedPostBase { index } => {
            *index = random_varint_edge(state);
        }
        QpackFieldRep::LiteralWithNameRef {
            is_static,
            name_index,
            value,
        } => {
            *is_static = state.rand_mut().below(2) == 0;
            *name_index = random_varint_edge(state);
            *value = random_header_value(state);
        }
        QpackFieldRep::LiteralWithPostBaseNameRef { index, value } => {
            *index = random_varint_edge(state);
            *value = random_header_value(state);
        }
        QpackFieldRep::Literal {
            name,
            value,
            lowercase_name,
        } => {
            *name = random_header_name(state);
            *value = random_header_value(state);
            *lowercase_name = state.rand_mut().below(2) == 0;
        }
    }
}
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
// 变异quic数据包收发的比例
pub struct H3SendRecvTimesMutator;
impl H3SendRecvTimesMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3SendRecvTimesMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3SendRecvTimesMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3SendRecvTimesMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3SendRecvTimesMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let had_wait_state = h3_corp.recv_timeout > 0
            || h3_corp.send_timeout > 0
            || h3_corp
                .data_actions
                .iter()
                .any(|action| matches!(action, Action::Wait { .. }))
            || h3_corp
                .control_actions
                .iter()
                .any(|action| matches!(action, Action::Wait { .. }))
            || h3_corp.data_blocks.iter().any(|block| {
                block
                    .header_patterns
                    .iter()
                    .any(|pattern| is_wait_header_pattern(pattern))
            });

        strip_wait_primitives(&mut h3_corp);

        if !had_wait_state {
            return Ok(MutationResult::Skipped);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 变异数据包重新排序的方式
pub struct H3ResortMutator;
impl H3ResortMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ResortMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ResortMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ResortMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ResortMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let changed_packet_resort_type = state.rand_mut().below(4);
        match changed_packet_resort_type {
            0 => {
                h3_corp.packet_resort_type = pkt_resort_type::None;
            }
            1 => {
                h3_corp.packet_resort_type = pkt_resort_type::Random;
            }
            2 => {
                h3_corp.packet_resort_type = pkt_resort_type::Reverse;
            }
            3 => {
                h3_corp.packet_resort_type = pkt_resort_type::Odd_even;
            }
            _ => {
                h3_corp.packet_resort_type = pkt_resort_type::None;
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 数据帧变异

// method修改： GET/POST/PUT/DELETE/HEAD/PATCH/OPTIONS/TRACE/CONNECT/OTHER
// Mutator for changing the HTTP method of a random H3DataBlock.
pub struct H3MethodMutator;
impl H3MethodMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3MethodMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3MethodMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3MethodMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3MethodMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // List of common HTTP methods (including a placeholder "OTHER").
        const METHODS: &[&str] = &[
            "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "TRACE", "CONNECT", "OTHER",
        ];
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let new_method_idx = state.rand_mut().below(METHODS.len()) as usize;
        if new_method_idx == 9 {
            // If "OTHER" is selected, create a random method name.
            let method_len = 3 + state.rand_mut().below(10) as usize; // length 3-12
            let mut other_method = String::new();
            for _ in 0..method_len {
                let ch = (state.rand_mut().below(256) as u8) as char;
                other_method.push(ch);
            }
            h3_corp.data_blocks[block_idx].method = other_method;
        } else {
            // Set to one of the predefined methods.
            h3_corp.data_blocks[block_idx].method = METHODS[new_method_idx].to_string();
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// path变异：添加/删除一个路径
// Mutator for adding or removing a path segment in a random H3DataBlock path.
pub struct H3PathSegmentMutator;
impl H3PathSegmentMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3PathSegmentMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3PathSegmentMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3PathSegmentMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3PathSegmentMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let path = &mut h3_corp.data_blocks[block_idx].path;
        if path.is_empty() {
            // Ensure the path is at least "/" to maintain a valid starting point.
            *path = "/".to_string();
        }
        let do_add = state.rand_mut().below(2) == 0;
        if do_add {
            // Add a new random segment to the path.
            let segment_len = 1 + state.rand_mut().below(10) as usize; // random length 1-10
            let mut new_segment = String::new();
            for _ in 0..segment_len {
                // Generate a random lowercase letter for the segment.
                let ch = (b'a' + (state.rand_mut().below(26) as u8)) as char;
                new_segment.push(ch);
            }
            if path.ends_with('/') {
                // If path already ends with '/', just append segment.
                path.push_str(&new_segment);
            } else {
                // Otherwise, add a '/' then the new segment.
                path.push('/');
                path.push_str(&new_segment);
            }
        } else {
            // Remove the last path segment if possible.
            if path != "/" {
                if let Some(pos) = path.rfind('/') {
                    if pos == 0 {
                        // Path like "/segment" will become just "/"
                        *path = "/".to_string();
                    } else {
                        // Truncate path at the last '/' to remove the last segment.
                        path.truncate(pos);
                    }
                }
            } else {
                // If path is just "/", we cannot remove any segment; skip mutation.
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// path变异：某个路径添加/删除一个随机字节
// Mutator for adding or removing a random byte in the path of a random H3DataBlock.
pub struct H3PathByteMutator;
impl H3PathByteMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3PathByteMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3PathByteMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3PathByteMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3PathByteMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let path = &mut h3_corp.data_blocks[block_idx].path;
        if path.is_empty() {
            // If path is empty (unlikely in valid HTTP/3), initialize as "/".
            *path = "/".to_string();
        }
        let do_add = state.rand_mut().below(2) == 0;
        if do_add {
            // Insert a random byte at a random position in the path.
            let pos = state.rand_mut().below((path.len())) as usize;
            // Generate a random character (printable ASCII).
            let byte_val = 32 + (state.rand_mut().below(95) as u8); // space (32) to ~ (126)
            let ch = byte_val as char;
            if pos >= path.len() {
                path.push(ch);
            } else {
                path.insert(pos, ch);
            }
        } else {
            // Remove a byte at a random position in the path (if length > 0).
            if !path.is_empty() {
                let pos = state.rand_mut().below(path.len()) as usize;
                path.remove(pos);
                if path.is_empty() {
                    // Ensure path is not left empty - use "/" if everything removed.
                    *path = "/".to_string();
                }
            } else {
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// path变异：新增/删除一个参数
// Mutator for adding or removing a query parameter in the path of a random H3DataBlock.
pub struct H3PathParamMutator;
impl H3PathParamMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3PathParamMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3PathParamMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3PathParamMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3PathParamMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let path = &mut h3_corp.data_blocks[block_idx].path;
        if path.is_empty() {
            *path = "/".to_string();
        }
        let do_add = state.rand_mut().below(2) == 0;
        if do_add {
            // Add a new query parameter.
            let param_name_len = 1 + state.rand_mut().below(5) as usize;
            let param_value_len = 1 + state.rand_mut().below(5) as usize;
            let mut param_name = String::new();
            let mut param_value = String::new();
            for _ in 0..param_name_len {
                let ch = (b'a' + (state.rand_mut().below(26) as u8)) as char;
                param_name.push(ch);
            }
            for _ in 0..param_value_len {
                let ch = (b'0' + (state.rand_mut().below(10) as u8)) as char;
                param_value.push(ch);
            }
            if path.contains('?') {
                // Already has a query string, append new param.
                path.push('&');
            } else {
                // No query string yet, add '?' first.
                path.push('?');
            }
            path.push_str(&param_name);
            path.push('=');
            path.push_str(&param_value);
        } else {
            // Remove an existing query parameter if present.
            if let Some(q_idx) = path.find('?') {
                let base_path = path[..q_idx].to_string();
                let query = &path[q_idx + 1..];
                // Split query into parameters.
                let params: Vec<&str> = query.split('&').collect();
                if params.is_empty() {
                    // No actual parameters present after '?', just remove '?'.
                    *path = base_path;
                } else {
                    // Remove one parameter.
                    let remove_idx = state.rand_mut().below(params.len()) as usize;
                    let mut new_params = Vec::new();
                    for (i, &p) in params.iter().enumerate() {
                        if i != remove_idx && !p.is_empty() {
                            new_params.push(p);
                        }
                    }
                    if new_params.is_empty() {
                        // No parameters left, just use base path without any query.
                        *path = base_path;
                    } else {
                        // Reconstruct query string without the removed parameter.
                        *path = base_path + "?" + &new_params.join("&");
                    }
                }
            } else {
                // No query parameters to remove; skip this mutation.
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3HeaderPatternMutator;
impl H3HeaderPatternMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3HeaderPatternMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3HeaderPatternMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3HeaderPatternMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3HeaderPatternMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let patterns = &mut h3_corp.data_blocks[block_idx].header_patterns;
        let selected =
            HEADER_PATTERNS[state.rand_mut().below(HEADER_PATTERNS.len()) as usize].to_string();

        if let Some(idx) = patterns.iter().position(|item| item == &selected) {
            patterns.remove(idx);
        } else {
            patterns.push(selected);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// header变异：新增/删除一个header键值对
// Mutator for adding or removing a header key-value pair in a random H3DataBlock.
pub struct H3HeaderAddRemoveMutator;
impl H3HeaderAddRemoveMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3HeaderAddRemoveMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3HeaderAddRemoveMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3HeaderAddRemoveMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3HeaderAddRemoveMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let normal_headers = h3_corp.normal_headers.clone();
        let headers = &mut h3_corp.data_blocks[block_idx].header_pairs;
        let do_add = (headers.is_empty() || state.rand_mut().below(2) == 0) && headers.len() < 32;
        if do_add {
            let key = if !normal_headers.is_empty() && state.rand_mut().below(3) == 0 {
                normal_headers[state.rand_mut().below(normal_headers.len()) as usize]
                    .as_bytes()
                    .to_vec()
            } else {
                random_header_name(state)
            };
            let value = if key.eq_ignore_ascii_case(b"content-length") {
                random_content_length_field(state).to_string().into_bytes()
            } else if key.as_slice() == b":method" {
                random_string(state, 24, false, true, false).into_bytes()
            } else if key.as_slice() == b":path" {
                random_byte_vec(state, 256)
            } else {
                random_header_value(state)
            };
            headers.push((key, value));
        } else if !headers.is_empty() {
            let idx = state.rand_mut().below(headers.len()) as usize;
            headers.remove(idx);
        } else {
            return Ok(MutationResult::Skipped);
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// header变异：为某个header的值添加/删除一个随机字节
// Mutator for adding or removing a random byte in a value of a random header.
pub struct H3HeaderValueByteMutator;
impl H3HeaderValueByteMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3HeaderValueByteMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3HeaderValueByteMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3HeaderValueByteMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3HeaderValueByteMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let headers = &mut h3_corp.data_blocks[block_idx].header_pairs;
        if headers.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Pick a random header entry.
        let idx = state.rand_mut().below(headers.len()) as usize;
        let (_, ref mut value) = headers[idx];

        if state.rand_mut().below(4) == 0 {
            *value = random_header_value(state);
        } else {
            let do_add = state.rand_mut().below(2) == 0;
            if do_add {
                if value.len() >= MAX_HEADER_VALUE_LEN {
                    return Ok(MutationResult::Skipped);
                }
                let pos = state.rand_mut().below(value.len() + 1) as usize;
                let ch = random_fuzz_byte(state);
                if pos >= value.len() {
                    value.push(ch);
                } else {
                    value.insert(pos, ch);
                }
            } else if !value.is_empty() {
                let pos = state.rand_mut().below(value.len()) as usize;
                value.remove(pos);
            }

            if value.is_empty() && state.rand_mut().below(2) == 0 {
                *value = random_header_value(state);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// header变异：为某个header的key添加/删除一个随机字节
// Mutator for adding or removing a random byte in a header name of a random header.
pub struct H3HeaderNameByteMutator;
impl H3HeaderNameByteMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3HeaderNameByteMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3HeaderNameByteMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3HeaderNameByteMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3HeaderNameByteMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let headers = &mut h3_corp.data_blocks[block_idx].header_pairs;
        if headers.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Pick a random header entry.
        let idx = state.rand_mut().below(headers.len()) as usize;
        let (ref mut key, _) = headers[idx];

        if state.rand_mut().below(4) == 0 {
            *key = random_header_name(state);
        } else {
            let do_add = state.rand_mut().below(2) == 0;
            if do_add {
                if key.len() >= MAX_HEADER_NAME_LEN {
                    return Ok(MutationResult::Skipped);
                }
                let pos = state.rand_mut().below(key.len() + 1) as usize;
                let ch = random_fuzz_byte(state);
                if pos >= key.len() {
                    key.push(ch);
                } else {
                    key.insert(pos, ch);
                }
            } else if !key.is_empty() {
                let pos = state.rand_mut().below(key.len()) as usize;
                key.remove(pos);
            }

            if key.is_empty() {
                *key = random_header_name(state);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// header变异：复制一个已有的header条目，并修改其值
// Mutator for duplicating an existing header entry and modifying its value.
pub struct H3HeaderDuplicateMutator;
impl H3HeaderDuplicateMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3HeaderDuplicateMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3HeaderDuplicateMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3HeaderDuplicateMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3HeaderDuplicateMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let headers = &mut h3_corp.data_blocks[block_idx].header_pairs;
        if headers.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Choose a header to duplicate.
        let idx = state.rand_mut().below(headers.len()) as usize;
        let (ref orig_key, ref orig_val) = headers[idx];
        let new_key = if state.rand_mut().below(3) == 0 {
            random_header_name(state)
        } else {
            orig_key.clone()
        };
        let mut new_val = if state.rand_mut().below(3) == 0 {
            random_header_value(state)
        } else {
            orig_val.clone()
        };
        if new_key.eq_ignore_ascii_case(b"content-length") {
            new_val = random_content_length_field(state).to_string().into_bytes();
        }
        headers.push((new_key, new_val));
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// body变异：修改body的长度，并重新生成内容
// Mutator for changing the body length and regenerating body content accordingly.
pub struct H3BodyUpdateMutator;
impl H3BodyUpdateMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3BodyUpdateMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3BodyUpdateMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3BodyUpdateMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3BodyUpdateMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let data_block = &mut h3_corp.data_blocks[block_idx];
        match state.rand_mut().below(3) {
            0 => data_block.body = random_body_bytes(state),
            1 => data_block
                .body
                .extend_from_slice(&random_byte_vec(state, 512)),
            _ => {
                let new_len = random_len_bucket(state, MAX_FRAME_BYTES as usize);
                data_block.body.truncate(new_len.min(data_block.body.len()));
                if data_block.body.is_empty() && state.rand_mut().below(2) == 0 {
                    data_block.body = random_body_bytes(state);
                }
            }
        }

        if state.rand_mut().below(3) == 0 {
            data_block.content_length = data_block.body.len();
        } else {
            data_block.content_length = random_content_length_field(state);
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// body变异：将content-length修改为与实际body长度不符的值
// 可能和 H3BodyUpdateMutator 冲突，暂时搁置
// Mutator for setting the content_length to a value that does not match the actual body length.
pub struct H3ContentLengthMismatchMutator;
impl H3ContentLengthMismatchMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ContentLengthMismatchMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ContentLengthMismatchMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ContentLengthMismatchMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ContentLengthMismatchMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.data_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
        let data_block = &mut h3_corp.data_blocks[block_idx];
        let actual_len = data_block.body.len();
        let delta = random_len_bucket(state, 4096);
        let new_content_length = match state.rand_mut().below(4) {
            0 => 0,
            1 => actual_len.saturating_add(delta),
            2 => actual_len.saturating_sub(delta),
            _ => random_content_length_field(state),
        };
        data_block.content_length = new_content_length.min(MAX_CONTENT_LENGTH_FIELD);
        // (We do not change the body here, causing the mismatch intentionally.)
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 数据帧数量变异：添加/删除数据帧的数量
// Mutator for adding or removing an entire H3DataBlock (data frame) in the H3Struct.
pub struct H3DataFrameCountMutator;
impl H3DataFrameCountMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3DataFrameCountMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3DataFrameCountMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3DataFrameCountMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3DataFrameCountMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let do_add = state.rand_mut().below(2) == 0;
        if do_add {
            if h3_corp.data_blocks.len() >= MAX_DATA_BLOCKS {
                return Ok(MutationResult::Skipped);
            }
            // Add a new data frame (H3DataBlock) with default or random content.
            let mut new_block = H3DataBlock {
                method: "GET".to_string(),
                path: "/".to_string(),
                body: Vec::new(),
                content_length: 0,
                header_pairs: Vec::new(),
                header_patterns: Vec::new(),
            };
            // Optionally, if there are existing blocks, we might base new one on an existing block.
            if !h3_corp.data_blocks.is_empty() {
                let ref_block_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
                new_block.header_patterns =
                    h3_corp.data_blocks[ref_block_idx].header_patterns.clone();
                new_block.header_pairs = h3_corp.data_blocks[ref_block_idx].header_pairs.clone();
                if state.rand_mut().below(2) == 0 {
                    new_block.method = h3_corp.data_blocks[ref_block_idx].method.clone();
                    new_block.path = h3_corp.data_blocks[ref_block_idx].path.clone();
                }
            }
            if state.rand_mut().below(2) == 0 {
                new_block.body = random_body_bytes(state);
            }
            new_block.content_length = if state.rand_mut().below(2) == 0 {
                new_block.body.len()
            } else {
                random_content_length_field(state)
            };
            h3_corp.data_blocks.push(new_block);
        } else {
            // Remove a data frame if there is at least one.
            if h3_corp.data_blocks.len() > 1 {
                let remove_idx = state.rand_mut().below(h3_corp.data_blocks.len()) as usize;
                h3_corp.data_blocks.remove(remove_idx);
            } else {
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 控制帧变异 修改控制帧的重复次数
// Mutator for modifying the repeat count of a random H3ControlBlock.
pub struct H3ControlRepeatMutator;
impl H3ControlRepeatMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlRepeatMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlRepeatMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlRepeatMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlRepeatMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.control_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let idx = state.rand_mut().below(h3_corp.control_blocks.len()) as usize;
        let ctrl_block = &mut h3_corp.control_blocks[idx];
        let _ori_repeat = ctrl_block.repeat_num;
        ctrl_block.repeat_num = 1 + state.rand_mut().below(MAX_H3_FRAME_ACTIONS) as usize;
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 修改发送/接收控制帧的时间：在控制帧列表插入一个延时帧
// 但是延时属于Action，这里变异主要针对control_blocks，我需要一种映射的形式
// TODO: 目前只是简单地在control_actions中插入一个Wait动作，后续可以改进为更复杂的时间控制
// Mutator for modifying the order/timing of control frame actions (e.g., by reordering control_actions).
pub struct H3ControlTimingMutator;
impl H3ControlTimingMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlTimingMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlTimingMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlTimingMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlTimingMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        strip_wait_primitives(&mut h3_corp);
        let prefer_control = state.rand_mut().below(2) == 0;
        let request_stream_id =
            random_request_stream_id_with_count(state, h3_corp.data_blocks.len());
        let control_stream_id = random_control_stream_id(state, &h3_corp);
        let new_action = match state.rand_mut().below(4) {
            0 => Action::FlushPackets,
            1 => Action::ResetStream {
                stream_id: if prefer_control {
                    control_stream_id
                } else {
                    request_stream_id
                },
                error_code: random_varint_edge(state),
            },
            2 => Action::StopSending {
                stream_id: if prefer_control {
                    control_stream_id
                } else {
                    request_stream_id
                },
                error_code: random_varint_edge(state),
            },
            _ => Action::StreamBytes {
                stream_id: if prefer_control {
                    control_stream_id
                } else {
                    request_stream_id
                },
                fin_stream: false,
                bytes: random_bytes(
                    state,
                    if prefer_control {
                        MAX_ACTION_BYTES
                    } else {
                        MAX_FRAME_BYTES as usize
                    },
                ),
            },
        };
        let target_actions = if prefer_control {
            &mut h3_corp.control_actions
        } else {
            &mut h3_corp.data_actions
        };

        if target_actions.len() >= MAX_ACTION_LIST_LEN {
            return Ok(MutationResult::Skipped);
        }

        let idx = state.rand_mut().below(target_actions.len() + 1) as usize;
        target_actions.insert(idx, new_action);

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 新增一个控制帧
// Mutator for adding a new control frame (H3ControlBlock) to the H3Struct.
pub struct H3ControlAddMutator;
impl H3ControlAddMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlAddMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlAddMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlAddMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlAddMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.control_blocks.len() >= MAX_CONTROL_BLOCKS {
            return Ok(MutationResult::Skipped);
        }
        // If no existing control frame to base on, we create a default Settings frame.
        let new_frame_type = state.rand_mut().below(8);
        let new_frame = match new_frame_type {
            0 => QFrame::CancelPush { push_id: 0 },
            1 => QFrame::PushPromise {
                push_id: 0,
                header_block: random_bytes(state, 256),
            },
            2 => QFrame::Settings {
                max_field_section_size: None,
                qpack_max_table_capacity: None,
                qpack_blocked_streams: None,
                connect_protocol_enabled: None,
                h3_datagram: None,
                grease: None,
                additional_settings: Some(vec![(
                    random_varint_edge(state),
                    random_varint_edge(state),
                )]),
                raw: None,
            },
            3 => QFrame::GoAway { id: 0 },
            4 => QFrame::MaxPushId { push_id: 0 },
            5 => QFrame::PriorityUpdateRequest {
                prioritized_element_id: 0,
                priority_field_value: random_bytes(state, 128),
            },
            6 => QFrame::PriorityUpdatePush {
                prioritized_element_id: 0,
                priority_field_value: random_bytes(state, 128),
            },
            _ => QFrame::Unknown {
                raw_type: 0,
                payload: random_bytes(state, 256),
            },
        };
        // Set repeat_num to 1 by default for the new control frame.
        let new_block = H3ControlBlock {
            basic_frame: new_frame,
            repeat_num: 1,
        };
        h3_corp.control_blocks.push(new_block);
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 删除一个控制帧
// Mutator for removing a random control frame (H3ControlBlock) from the H3Struct.
pub struct H3ControlRemoveMutator;
impl H3ControlRemoveMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlRemoveMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlRemoveMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlRemoveMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlRemoveMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.control_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let remove_idx = state.rand_mut().below(h3_corp.control_blocks.len()) as usize;
        h3_corp.control_blocks.remove(remove_idx);
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 修改一个控制帧的数字类型内容
// Mutator for modifying a numeric field in a control frame's content.
pub struct H3ControlNumericMutator;
impl H3ControlNumericMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlNumericMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlNumericMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlNumericMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlNumericMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.control_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Choose a random control frame.
        let idx = state.rand_mut().below(h3_corp.control_blocks.len()) as usize;
        let frame = &mut h3_corp.control_blocks[idx].basic_frame;
        // Attempt to mutate numeric fields depending on frame type.
        match frame {
            // If frame is a simple numeric (e.g., Cancel Push, GoAway, MaxPushId)
            QFrame::CancelPush { ref mut push_id } => {
                *push_id = random_varint_edge(state);
            }
            QFrame::MaxPushId { ref mut push_id } => {
                *push_id = random_varint_edge(state);
            }
            QFrame::GoAway { ref mut id } => {
                *id = random_varint_edge(state);
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
                if state.rand_mut().below(2) == 0 {
                    *additional_settings = Some(vec![
                        (random_varint_edge(state), random_varint_edge(state)),
                        (random_varint_edge(state), random_varint_edge(state)),
                    ]);
                } else {
                    *raw = Some(vec![(random_varint_edge(state), random_varint_edge(state))]);
                    *max_field_section_size = Some(random_varint_edge(state));
                    *qpack_max_table_capacity = Some(random_varint_edge(state));
                    *qpack_blocked_streams = Some(random_varint_edge(state));
                    *connect_protocol_enabled = Some(random_varint_edge(state));
                    *h3_datagram = Some(random_varint_edge(state));
                    *grease = Some((random_varint_edge(state), random_varint_edge(state)));
                }
            }
            QFrame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                *prioritized_element_id = random_varint_edge(state);
            }
            QFrame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                *prioritized_element_id = random_varint_edge(state);
            }
            QFrame::PushPromise {
                push_id,
                header_block,
            } => {
                *push_id = random_varint_edge(state);
            }
            QFrame::Unknown { raw_type, payload } => {
                *raw_type = random_varint_edge(state);
            }
            _ => {
                // If frame type not recognized for numeric mutation, skip.
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 修改一个控制帧的字符串类型内容
// Mutator for modifying a string field in a control frame's content (e.g., header name or value in QPACK instructions).
pub struct H3ControlStringChangeMutator;
impl H3ControlStringChangeMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlStringChangeMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlStringChangeMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlStringChangeMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlStringChangeMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.control_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Choose a random control frame.
        let idx = state.rand_mut().below(h3_corp.control_blocks.len()) as usize;
        let frame = &mut h3_corp.control_blocks[idx].basic_frame;
        match frame {
            QFrame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                if priority_field_value.is_empty() {
                    priority_field_value.push(0x41 as u8);
                } else {
                    let idx = state.rand_mut().below(priority_field_value.len()) as usize;
                    let ch = state.rand_mut().below(255) as u8;
                    priority_field_value[idx] = ch;
                }
            }
            QFrame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                if priority_field_value.is_empty() {
                    priority_field_value.push(0x41 as u8);
                } else {
                    let idx = state.rand_mut().below(priority_field_value.len()) as usize;
                    let ch = state.rand_mut().below(255) as u8;
                    priority_field_value[idx] = ch;
                }
            }
            QFrame::PushPromise {
                push_id,
                header_block,
            } => {
                if header_block.is_empty() {
                    header_block.push(0x41 as u8);
                } else {
                    let idx = state.rand_mut().below(header_block.len()) as usize;
                    let ch = state.rand_mut().below(255) as u8;
                    header_block[idx] = ch;
                }
            }
            QFrame::Unknown { raw_type, payload } => {
                if payload.is_empty() {
                    payload.push(0x41 as u8);
                } else {
                    let idx = state.rand_mut().below(payload.len()) as usize;
                    let ch = state.rand_mut().below(255) as u8;
                    payload[idx] = ch;
                }
            }
            _ => {
                // If no string content in this frame type, skip.
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 修改一个控制帧的字符串长度及内容
// Mutator for modifying a string field in a control frame's content (e.g., header name or value in QPACK instructions).
pub struct H3ControlStringLengthMutator;
impl H3ControlStringLengthMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ControlStringLengthMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlStringLengthMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ControlStringLengthMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ControlStringLengthMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.control_blocks.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Choose a random control frame.
        let idx = state.rand_mut().below(h3_corp.control_blocks.len()) as usize;
        let frame = &mut h3_corp.control_blocks[idx].basic_frame;
        match frame {
            QFrame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                if priority_field_value.is_empty() {
                    priority_field_value.push(0x41 as u8);
                } else {
                    let new_size = state
                        .rand_mut()
                        .below(min(priority_field_value.len() << 1, 4096))
                        as usize;
                    if new_size <= priority_field_value.len() {
                        priority_field_value.truncate(new_size);
                    } else {
                        while priority_field_value.len() < new_size {
                            let ch = state.rand_mut().below(255) as u8;
                            priority_field_value.push(ch);
                        }
                    }
                }
            }
            QFrame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                if priority_field_value.is_empty() {
                    priority_field_value.push(0x41 as u8);
                } else {
                    let new_size = state
                        .rand_mut()
                        .below(min(priority_field_value.len() << 1, 4096))
                        as usize;
                    if new_size <= priority_field_value.len() {
                        priority_field_value.truncate(new_size);
                    } else {
                        while priority_field_value.len() < new_size {
                            let ch = state.rand_mut().below(255) as u8;
                            priority_field_value.push(ch);
                        }
                    }
                }
            }
            QFrame::PushPromise {
                push_id,
                header_block,
            } => {
                if header_block.is_empty() {
                    header_block.push(0x41 as u8);
                } else {
                    let new_size =
                        state.rand_mut().below(min(header_block.len() << 1, 4096)) as usize;
                    if new_size <= header_block.len() {
                        header_block.truncate(new_size);
                    } else {
                        while header_block.len() < new_size {
                            let ch = state.rand_mut().below(255) as u8;
                            header_block.push(ch);
                        }
                    }
                }
            }
            QFrame::Unknown { raw_type, payload } => {
                if payload.is_empty() {
                    payload.push(0x41 as u8);
                } else {
                    let new_size = state.rand_mut().below(min(payload.len() << 1, 4096)) as usize;
                    if new_size <= payload.len() {
                        payload.truncate(new_size);
                    } else {
                        while payload.len() < new_size {
                            let ch = state.rand_mut().below(255) as u8;
                            payload.push(ch);
                        }
                    }
                }
            }
            _ => {
                // If no string content in this frame type, skip.
                return Ok(MutationResult::Skipped);
            }
        }
        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackBlockedMutator;
impl H3QpackBlockedMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackBlockedMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackBlockedMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackBlockedMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackBlockedMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        rebuild_qpack_blocked_script(state, &mut h3_corp, false);

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackAmplifyMutator;
impl H3QpackAmplifyMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackAmplifyMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackAmplifyMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackAmplifyMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackAmplifyMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        rebuild_qpack_blocked_script(state, &mut h3_corp, true);

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackStepCountMutator;
impl H3QpackStepCountMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackStepCountMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackStepCountMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackStepCountMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackStepCountMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        ensure_qpack_plan_seed(state, &mut h3_corp);

        let add_step = h3_corp.qpack_plan.steps.len() <= 1
            || (h3_corp.qpack_plan.steps.len() < MAX_QPACK_PLAN_STEPS
                && state.rand_mut().below(2) == 0);

        if add_step {
            let idx = state.rand_mut().below(h3_corp.qpack_plan.steps.len() + 1) as usize;
            let step = random_qpack_step(state, &h3_corp);
            h3_corp.qpack_plan.steps.insert(idx, step);
        } else if !h3_corp.qpack_plan.steps.is_empty() {
            let idx = state.rand_mut().below(h3_corp.qpack_plan.steps.len()) as usize;
            h3_corp.qpack_plan.steps.remove(idx);
        } else {
            return Ok(MutationResult::Skipped);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackEncoderInstructionMutator;
impl H3QpackEncoderInstructionMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackEncoderInstructionMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackEncoderInstructionMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackEncoderInstructionMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackEncoderInstructionMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let idx = ensure_qpack_encoder_step(state, &mut h3_corp);

        if let H3QpackStep::EncoderInstructions { instructions, .. } =
            &mut h3_corp.qpack_plan.steps[idx]
        {
            let action = if instructions.is_empty() {
                0
            } else {
                state.rand_mut().below(3)
            };

            match action {
                0 if instructions.len() < MAX_QPACK_INSTRUCTION_COUNT => {
                    let insert_at = state.rand_mut().below(instructions.len() + 1) as usize;
                    instructions.insert(insert_at, random_qpack_encoder_instruction(state));
                }
                1 if instructions.len() > 1 => {
                    let remove_at = state.rand_mut().below(instructions.len()) as usize;
                    instructions.remove(remove_at);
                }
                _ => {
                    let target = state.rand_mut().below(instructions.len()) as usize;
                    if state.rand_mut().below(3) == 0 {
                        instructions[target] = random_qpack_encoder_instruction(state);
                    } else {
                        mutate_qpack_encoder_instruction(state, &mut instructions[target]);
                    }
                }
            }
        } else {
            return Ok(MutationResult::Skipped);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackDecoderInstructionMutator;
impl H3QpackDecoderInstructionMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackDecoderInstructionMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackDecoderInstructionMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackDecoderInstructionMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackDecoderInstructionMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let idx = ensure_qpack_decoder_step(state, &mut h3_corp);
        let request_streams = qpack_plan_request_streams(&h3_corp.qpack_plan);

        if let H3QpackStep::DecoderInstructions { instructions, .. } =
            &mut h3_corp.qpack_plan.steps[idx]
        {
            let action = if instructions.is_empty() {
                0
            } else {
                state.rand_mut().below(3)
            };

            match action {
                0 if instructions.len() < MAX_QPACK_INSTRUCTION_COUNT => {
                    let insert_at = state.rand_mut().below(instructions.len() + 1) as usize;
                    instructions.insert(
                        insert_at,
                        random_qpack_decoder_instruction(state, &request_streams),
                    );
                }
                1 if instructions.len() > 1 => {
                    let remove_at = state.rand_mut().below(instructions.len()) as usize;
                    instructions.remove(remove_at);
                }
                _ => {
                    let target = state.rand_mut().below(instructions.len()) as usize;
                    if state.rand_mut().below(3) == 0 {
                        instructions[target] =
                            random_qpack_decoder_instruction(state, &request_streams);
                    } else {
                        mutate_qpack_decoder_instruction(
                            state,
                            &mut instructions[target],
                            &request_streams,
                        );
                    }
                }
            }
        } else {
            return Ok(MutationResult::Skipped);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackHeaderBlockRepMutator;
impl H3QpackHeaderBlockRepMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackHeaderBlockRepMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackHeaderBlockRepMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackHeaderBlockRepMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackHeaderBlockRepMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let idx = ensure_qpack_request_step(state, &mut h3_corp);

        if let H3QpackStep::RequestHeaderBlock { block, .. } = &mut h3_corp.qpack_plan.steps[idx] {
            if block.fields.is_empty() {
                block.fields.push(random_qpack_field_rep(state));
            }

            let action = state.rand_mut().below(4);
            match action {
                0 if block.fields.len() < MAX_QPACK_FIELD_COUNT => {
                    let insert_at = state.rand_mut().below(block.fields.len() + 1) as usize;
                    block
                        .fields
                        .insert(insert_at, random_qpack_field_rep(state));
                }
                1 if block.fields.len() > 1 => {
                    let remove_at = state.rand_mut().below(block.fields.len()) as usize;
                    block.fields.remove(remove_at);
                }
                2 => {
                    let field_idx = state.rand_mut().below(block.fields.len()) as usize;
                    mutate_qpack_field_rep(state, &mut block.fields[field_idx]);
                }
                _ => {
                    let field_idx = state.rand_mut().below(block.fields.len()) as usize;
                    block.fields[field_idx] = random_qpack_field_rep(state);
                }
            }
        } else {
            return Ok(MutationResult::Skipped);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackReferenceConsistencyMutator;
impl H3QpackReferenceConsistencyMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackReferenceConsistencyMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackReferenceConsistencyMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackReferenceConsistencyMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackReferenceConsistencyMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);

        let encoder_idx = ensure_qpack_encoder_step(state, &mut h3_corp);
        if let H3QpackStep::EncoderInstructions { instructions, .. } =
            &mut h3_corp.qpack_plan.steps[encoder_idx]
        {
            if !instructions.iter().any(|instruction| {
                matches!(
                    instruction,
                    QpackEncoderInstruction::InsertWithNameRef { .. }
                        | QpackEncoderInstruction::InsertWithoutNameRef { .. }
                        | QpackEncoderInstruction::Duplicate { .. }
                )
            }) {
                instructions.push(qpack_insert_without_name_ref(b"x-ref", b"seed"));
            }
        }

        let total_inserts = count_insert_like_instructions(
            &h3_corp.qpack_plan.steps,
            h3_corp.qpack_plan.steps.len(),
        )
        .max(1);
        let request_idx = ensure_qpack_request_step(state, &mut h3_corp);

        if let H3QpackStep::RequestHeaderBlock { block, .. } =
            &mut h3_corp.qpack_plan.steps[request_idx]
        {
            if block.fields.is_empty() {
                block.fields.push(qpack_literal(b":path", b"/qpack/ref"));
            }

            let target = state.rand_mut().below(block.fields.len()) as usize;
            let mode = state.rand_mut().below(4);

            match mode {
                0 => {
                    block.required_insert_count = total_inserts.min(1);
                    block.base = block.required_insert_count;
                    block.fields[target] = QpackFieldRep::Indexed {
                        is_static: false,
                        index: 0,
                    };
                }
                1 => {
                    block.required_insert_count = total_inserts + 1;
                    block.base = block.required_insert_count;
                    block.fields[target] = QpackFieldRep::LiteralWithNameRef {
                        is_static: false,
                        name_index: 0,
                        value: random_header_value(state),
                    };
                }
                2 => {
                    block.required_insert_count =
                        total_inserts + 8 + state.rand_mut().below(8) as u64;
                    block.base = block.required_insert_count.saturating_sub(1);
                    block.fields[target] = QpackFieldRep::Indexed {
                        is_static: false,
                        index: total_inserts + 4,
                    };
                }
                _ => {
                    block.required_insert_count = total_inserts.min(1);
                    block.base = block.required_insert_count;
                    block.fields[target] = QpackFieldRep::IndexedPostBase {
                        index: RFC_VARINT_MAX.saturating_sub(32),
                    };
                }
            }
        } else {
            return Ok(MutationResult::Skipped);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackInterleaveMutator;
impl H3QpackInterleaveMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackInterleaveMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackInterleaveMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackInterleaveMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackInterleaveMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let encoder_idx = ensure_qpack_encoder_step(state, &mut h3_corp);
        let request_idx = ensure_qpack_request_step(state, &mut h3_corp);
        let mode = state.rand_mut().below(4);

        match mode {
            0 => h3_corp.qpack_plan.steps.swap(encoder_idx, request_idx),
            1 => {
                let step = h3_corp.qpack_plan.steps.remove(encoder_idx);
                let target = request_idx.min(h3_corp.qpack_plan.steps.len());
                h3_corp.qpack_plan.steps.insert(target, step);
            }
            2 => {
                let step = h3_corp.qpack_plan.steps.remove(request_idx);
                let target = encoder_idx.min(h3_corp.qpack_plan.steps.len());
                h3_corp.qpack_plan.steps.insert(target, step);
            }
            _ => {
                if h3_corp.qpack_plan.steps.len() < MAX_QPACK_PLAN_STEPS {
                    let anchor = min(encoder_idx, request_idx) + 1;
                    h3_corp.qpack_plan.steps.insert(anchor, H3QpackStep::Flush);
                } else if let Some(flush_idx) = h3_corp
                    .qpack_plan
                    .steps
                    .iter()
                    .position(|step| matches!(step, H3QpackStep::Flush))
                {
                    h3_corp.qpack_plan.steps.swap(flush_idx, request_idx);
                }
            }
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackChunkingMutator;
impl H3QpackChunkingMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackChunkingMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackChunkingMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackChunkingMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackChunkingMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        ensure_qpack_plan_seed(state, &mut h3_corp);
        let idx = state.rand_mut().below(h3_corp.qpack_plan.steps.len()) as usize;

        match &mut h3_corp.qpack_plan.steps[idx] {
            H3QpackStep::OpenEncoderStream { fin_stream, .. }
            | H3QpackStep::OpenDecoderStream { fin_stream, .. } => {
                *fin_stream = !*fin_stream;
            }
            H3QpackStep::EncoderInstructions { send, .. }
            | H3QpackStep::DecoderInstructions { send, .. } => {
                send.chunk_size = choose_from_slice(state, QPACK_CHUNK_BUCKETS);
                send.flush_each_chunk = state.rand_mut().below(2) == 0;
            }
            H3QpackStep::RequestHeaderBlock {
                fin_stream, send, ..
            } => {
                *fin_stream = state.rand_mut().below(2) == 0;
                send.chunk_size = choose_from_slice(state, QPACK_CHUNK_BUCKETS);
                send.flush_each_chunk = state.rand_mut().below(2) == 0;
            }
            H3QpackStep::Flush => {
                h3_corp.qpack_plan.steps[idx] = H3QpackStep::WaitMs {
                    ms: state.rand_mut().below(MAX_MUTATED_TIMEOUT_MS as usize) as u64,
                };
            }
            H3QpackStep::WaitMs { ms } => {
                if state.rand_mut().below(2) == 0 {
                    *ms = state.rand_mut().below(MAX_MUTATED_TIMEOUT_MS as usize) as u64;
                } else {
                    h3_corp.qpack_plan.steps[idx] = H3QpackStep::Flush;
                }
            }
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackSettingsSyncMutator;
impl H3QpackSettingsSyncMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackSettingsSyncMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackSettingsSyncMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackSettingsSyncMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackSettingsSyncMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        ensure_qpack_plan_seed(state, &mut h3_corp);

        let request_count = qpack_request_step_indices(&h3_corp.qpack_plan).len() as u64;
        let dynamic_count = count_insert_like_instructions(
            &h3_corp.qpack_plan.steps,
            h3_corp.qpack_plan.steps.len(),
        );
        let settings = ensure_settings_block(&mut h3_corp);

        if let QFrame::Settings {
            qpack_max_table_capacity,
            qpack_blocked_streams,
            additional_settings,
            ..
        } = &mut settings.basic_frame
        {
            match state.rand_mut().below(4) {
                0 => {
                    *qpack_max_table_capacity =
                        Some((dynamic_count.max(1) * 128).min(RFC_VARINT_MAX));
                    *qpack_blocked_streams = Some(request_count.max(1) + 1);
                }
                1 => {
                    *qpack_max_table_capacity = Some(0);
                    *qpack_blocked_streams = Some(0);
                }
                2 => {
                    *qpack_max_table_capacity = Some(random_varint_edge(state));
                    *qpack_blocked_streams = Some(request_count.saturating_sub(1));
                }
                _ => {
                    *qpack_max_table_capacity = None;
                    *qpack_blocked_streams = Some(request_count.max(1) + 4);
                    let extras = additional_settings.get_or_insert_with(Vec::new);
                    extras.push((
                        0xff00 + state.rand_mut().below(16) as u64,
                        dynamic_count.max(1),
                    ));
                }
            }
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackBlockedLifecycleMutator;
impl H3QpackBlockedLifecycleMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackBlockedLifecycleMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackBlockedLifecycleMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackBlockedLifecycleMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackBlockedLifecycleMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        if h3_corp.qpack_plan.steps.is_empty() {
            h3_corp.qpack_plan = qpack_plan_blocked_then_unblock();
        }

        let encoder_idx = ensure_qpack_encoder_step(state, &mut h3_corp);
        let request_idx = ensure_qpack_request_step(state, &mut h3_corp);
        let mode = state.rand_mut().below(4);

        match mode {
            0 => {
                if let H3QpackStep::EncoderInstructions { instructions, .. } =
                    &mut h3_corp.qpack_plan.steps[encoder_idx]
                {
                    instructions.retain(|instruction| {
                        !matches!(
                            instruction,
                            QpackEncoderInstruction::InsertWithNameRef { .. }
                                | QpackEncoderInstruction::InsertWithoutNameRef { .. }
                                | QpackEncoderInstruction::Duplicate { .. }
                        )
                    });
                    if instructions.is_empty() {
                        instructions.push(QpackEncoderInstruction::RawBytes {
                            bytes: qpack_noise_bytes(state, QPACK_CONTROL_STREAM_BYTES),
                        });
                    }
                }
                if let H3QpackStep::RequestHeaderBlock { block, .. } =
                    &mut h3_corp.qpack_plan.steps[request_idx]
                {
                    block.required_insert_count = 1;
                    block.base = 1;
                }
            }
            1 => {
                if encoder_idx < request_idx {
                    let step = h3_corp.qpack_plan.steps.remove(encoder_idx);
                    let insert_at = request_idx.min(h3_corp.qpack_plan.steps.len());
                    h3_corp.qpack_plan.steps.insert(insert_at, step);
                }
                if h3_corp.qpack_plan.steps.len() < MAX_QPACK_PLAN_STEPS {
                    let insert_at = min(request_idx + 1, h3_corp.qpack_plan.steps.len());
                    h3_corp
                        .qpack_plan
                        .steps
                        .insert(insert_at, H3QpackStep::Flush);
                }
            }
            2 => {
                if encoder_idx > request_idx {
                    let step = h3_corp.qpack_plan.steps.remove(encoder_idx);
                    let insert_at = request_idx.min(h3_corp.qpack_plan.steps.len());
                    h3_corp.qpack_plan.steps.insert(insert_at, step);
                }
                if let H3QpackStep::RequestHeaderBlock { block, .. } =
                    &mut h3_corp.qpack_plan.steps[request_idx]
                {
                    block.required_insert_count = 1;
                    block.base = 1;
                }
            }
            _ => {
                if h3_corp.qpack_plan.steps.len() < MAX_QPACK_PLAN_STEPS {
                    let new_stream_id = collect_request_stream_ids(&h3_corp)
                        .into_iter()
                        .max()
                        .map(|id| id + 4)
                        .unwrap_or(0);
                    if let H3QpackStep::RequestHeaderBlock {
                        fin_stream,
                        send,
                        block,
                        ..
                    } = h3_corp.qpack_plan.steps[request_idx].clone()
                    {
                        h3_corp.qpack_plan.steps.insert(
                            request_idx,
                            H3QpackStep::RequestHeaderBlock {
                                stream_id: new_stream_id,
                                fin_stream,
                                send,
                                block,
                            },
                        );
                    }
                }
            }
        }

        let blocked_streams = qpack_request_step_indices(&h3_corp.qpack_plan).len() as u64 + 1;
        if let QFrame::Settings {
            qpack_blocked_streams,
            ..
        } = &mut ensure_settings_block(&mut h3_corp).basic_frame
        {
            *qpack_blocked_streams = Some(blocked_streams);
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackStreamTopologyMutator;
impl H3QpackStreamTopologyMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackStreamTopologyMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackStreamTopologyMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackStreamTopologyMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackStreamTopologyMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        ensure_qpack_plan_seed(state, &mut h3_corp);

        let open_indices: Vec<usize> = h3_corp
            .qpack_plan
            .steps
            .iter()
            .enumerate()
            .filter_map(|(idx, step)| match step {
                H3QpackStep::OpenEncoderStream { .. } | H3QpackStep::OpenDecoderStream { .. } => {
                    Some(idx)
                }
                _ => None,
            })
            .collect();

        match state.rand_mut().below(4) {
            0 if !open_indices.is_empty() => {
                let idx = open_indices[state.rand_mut().below(open_indices.len()) as usize];
                match &mut h3_corp.qpack_plan.steps[idx] {
                    H3QpackStep::OpenEncoderStream { stream_id, .. }
                    | H3QpackStep::OpenDecoderStream { stream_id, .. } => {
                        *stream_id = if state.rand_mut().below(2) == 0 {
                            random_uni_stream_id(state)
                        } else {
                            random_varint_edge(state)
                        };
                    }
                    _ => {}
                }
            }
            1 if !open_indices.is_empty()
                && h3_corp.qpack_plan.steps.len() < MAX_QPACK_PLAN_STEPS =>
            {
                let idx = open_indices[state.rand_mut().below(open_indices.len()) as usize];
                let insert_at = state.rand_mut().below(h3_corp.qpack_plan.steps.len() + 1) as usize;
                let step = h3_corp.qpack_plan.steps[idx].clone();
                h3_corp.qpack_plan.steps.insert(insert_at, step);
            }
            2 if h3_corp.control_actions.len() < MAX_ACTION_LIST_LEN => {
                let stream_id = if open_indices.is_empty() {
                    next_control_stream_id(&h3_corp)
                } else {
                    collect_control_stream_ids(&h3_corp)[state
                        .rand_mut()
                        .below(collect_control_stream_ids(&h3_corp).len())
                        as usize]
                };
                h3_corp.control_actions.push(Action::OpenUniStream {
                    stream_id,
                    fin_stream: state.rand_mut().below(2) == 0,
                    stream_type: random_control_stream_type(state),
                });
            }
            _ if h3_corp.control_actions.len() < MAX_ACTION_LIST_LEN => {
                let target_stream_id = random_control_stream_id(state, &h3_corp);
                let action = if state.rand_mut().below(2) == 0 {
                    Action::ResetStream {
                        stream_id: target_stream_id,
                        error_code: random_varint_edge(state),
                    }
                } else {
                    Action::StopSending {
                        stream_id: target_stream_id,
                        error_code: random_varint_edge(state),
                    }
                };
                h3_corp.control_actions.push(action);
            }
            _ => return Ok(MutationResult::Skipped),
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackRawCorruptionMutator;
impl H3QpackRawCorruptionMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackRawCorruptionMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackRawCorruptionMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackRawCorruptionMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackRawCorruptionMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        ensure_qpack_plan_seed(state, &mut h3_corp);

        match state.rand_mut().below(3) {
            0 => {
                let idx = ensure_qpack_encoder_step(state, &mut h3_corp);
                if let H3QpackStep::EncoderInstructions { instructions, .. } =
                    &mut h3_corp.qpack_plan.steps[idx]
                {
                    let mut bytes =
                        serialize_qpack_encoder_instructions(instructions).unwrap_or_default();
                    if bytes.is_empty() {
                        bytes = qpack_noise_bytes(state, QPACK_CONTROL_STREAM_BYTES);
                    }
                    let flip_count = 1 + state.rand_mut().below(3) as usize;
                    for _ in 0..flip_count {
                        let pos = state.rand_mut().below(bytes.len()) as usize;
                        bytes[pos] = random_fuzz_byte(state);
                    }
                    instructions.clear();
                    instructions.push(QpackEncoderInstruction::RawBytes { bytes });
                }
            }
            1 => {
                let idx = ensure_qpack_decoder_step(state, &mut h3_corp);
                if let H3QpackStep::DecoderInstructions { instructions, .. } =
                    &mut h3_corp.qpack_plan.steps[idx]
                {
                    let mut bytes =
                        serialize_qpack_decoder_instructions(instructions).unwrap_or_default();
                    if bytes.is_empty() {
                        bytes = qpack_noise_bytes(state, QPACK_DECODER_STREAM_BYTES);
                    }
                    let flip_count = 1 + state.rand_mut().below(3) as usize;
                    for _ in 0..flip_count {
                        let pos = state.rand_mut().below(bytes.len()) as usize;
                        bytes[pos] = random_fuzz_byte(state);
                    }
                    instructions.clear();
                    instructions.push(QpackDecoderInstruction::RawBytes { bytes });
                }
            }
            _ => {
                let idx = ensure_qpack_request_step(state, &mut h3_corp);
                let step = h3_corp.qpack_plan.steps.remove(idx);
                if let H3QpackStep::RequestHeaderBlock {
                    stream_id,
                    fin_stream,
                    send,
                    block,
                } = step
                {
                    let mut payload = serialize_qpack_header_block(&block).unwrap_or_default();
                    if payload.is_empty() {
                        payload = synthesize_qpack_payload(state, blocked_qpack_payload().len());
                    }
                    let mut frame_bytes = raw_headers_frame_bytes(&payload);
                    let flip_count = 1 + state.rand_mut().below(4) as usize;
                    for _ in 0..flip_count {
                        let pos = state.rand_mut().below(frame_bytes.len()) as usize;
                        frame_bytes[pos] = random_fuzz_byte(state);
                    }

                    let send = send.normalized();
                    let chunks = split_bytes(&frame_bytes, send.chunk_size);
                    for (chunk_idx, chunk) in chunks.iter().enumerate() {
                        h3_corp.data_actions.push(Action::StreamBytes {
                            stream_id,
                            fin_stream: fin_stream && chunk_idx + 1 == chunks.len(),
                            bytes: chunk.clone(),
                        });
                        if send.flush_each_chunk {
                            h3_corp.data_actions.push(Action::FlushPackets);
                        }
                    }
                } else {
                    h3_corp.qpack_plan.steps.insert(idx, step);
                    return Ok(MutationResult::Skipped);
                }
            }
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3QpackScenarioSeedMutator;
impl H3QpackScenarioSeedMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3QpackScenarioSeedMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3QpackScenarioSeedMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3QpackScenarioSeedMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3QpackScenarioSeedMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);

        h3_corp.send_timeout = 0;
        h3_corp.recv_timeout = 0;
        h3_corp.packet_resort_type = pkt_resort_type::None;
        h3_corp.data_blocks.clear();
        h3_corp.data_actions.clear();
        h3_corp.control_actions.clear();
        h3_corp.control_blocks.clear();
        h3_corp.qpack_plan = qpack_scenario_plan(state.rand_mut().below(5) as usize);

        let blocked_streams = qpack_request_step_indices(&h3_corp.qpack_plan).len() as u64 + 1;
        ensure_settings_block(&mut h3_corp).basic_frame = base_settings_frame(blocked_streams);

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3ActionAddMutator;
impl H3ActionAddMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ActionAddMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ActionAddMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ActionAddMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ActionAddMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let prefer_control = state.rand_mut().below(2) == 0;
        let new_action = random_action(state, &h3_corp, prefer_control);
        let target_actions = if prefer_control {
            &mut h3_corp.control_actions
        } else {
            &mut h3_corp.data_actions
        };
        if target_actions.len() >= MAX_ACTION_LIST_LEN {
            return Ok(MutationResult::Skipped);
        }
        let idx = state.rand_mut().below(target_actions.len() + 1) as usize;
        target_actions.insert(idx, new_action);

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3ActionRemoveMutator;
impl H3ActionRemoveMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ActionRemoveMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ActionRemoveMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ActionRemoveMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ActionRemoveMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        let total_actions = h3_corp.data_actions.len() + h3_corp.control_actions.len();
        if total_actions == 0 {
            return Ok(MutationResult::Skipped);
        }

        let remove_from_control = if h3_corp.control_actions.is_empty() {
            false
        } else if h3_corp.data_actions.is_empty() {
            true
        } else {
            state.rand_mut().below(2) == 0
        };

        let target_actions = if remove_from_control {
            &mut h3_corp.control_actions
        } else {
            &mut h3_corp.data_actions
        };
        let idx = state.rand_mut().below(target_actions.len()) as usize;
        target_actions.remove(idx);

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

pub struct H3ActionContentMutator;
impl H3ActionContentMutator {
    pub fn new() -> Self {
        Self
    }
}
impl Named for H3ActionContentMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("H3ActionContentMutator");
        &NAME
    }
}
impl<I, S> Mutator<I, S> for H3ActionContentMutator
where
    S: HasRand + HasMetadata,
    I: HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        debug!("H3ActionContentMutator");
        let mut h3_corp = load_h3_corp_or_skip!(input);
        strip_wait_primitives(&mut h3_corp);
        let request_stream_id = random_request_stream_id(state, &h3_corp);
        let control_stream_id = random_control_stream_id(state, &h3_corp);
        let fresh_control_stream_id = next_control_stream_id(&h3_corp);

        let mutate_control = if h3_corp.control_actions.is_empty() {
            false
        } else if h3_corp.data_actions.is_empty() {
            true
        } else {
            state.rand_mut().below(2) == 0
        };

        let target_actions = if mutate_control {
            &mut h3_corp.control_actions
        } else {
            &mut h3_corp.data_actions
        };

        if target_actions.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let idx = state.rand_mut().below(target_actions.len()) as usize;
        let target_action = &mut target_actions[idx];
        match target_action {
            Action::Wait { .. } => {
                *target_action = Action::FlushPackets;
            }
            Action::OpenUniStream {
                stream_id,
                fin_stream,
                stream_type,
            } => {
                *stream_id = if state.rand_mut().below(2) == 0 {
                    fresh_control_stream_id
                } else {
                    random_uni_stream_id(state)
                };
                *fin_stream = state.rand_mut().below(2) == 0;
                *stream_type = random_control_stream_type(state);
            }
            Action::StreamBytes {
                stream_id,
                fin_stream,
                bytes,
            } => {
                let use_control_stream = mutate_control || is_control_uni_stream_id(*stream_id);
                *stream_id = if use_control_stream {
                    control_stream_id
                } else {
                    request_stream_id
                };
                *fin_stream = state.rand_mut().below(2) == 0;
                if bytes.is_empty() || state.rand_mut().below(2) == 0 {
                    *bytes = random_bytes(
                        state,
                        if use_control_stream {
                            MAX_ACTION_BYTES
                        } else {
                            MAX_FRAME_BYTES as usize
                        },
                    );
                } else {
                    let pos = state.rand_mut().below(bytes.len()) as usize;
                    bytes[pos] = random_fuzz_byte(state);
                }
            }
            Action::ResetStream {
                stream_id,
                error_code,
            }
            | Action::StopSending {
                stream_id,
                error_code,
            } => {
                *stream_id = if mutate_control || is_control_uni_stream_id(*stream_id) {
                    control_stream_id
                } else {
                    request_stream_id
                };
                *error_code = random_varint_edge(state);
            }
            Action::SendFrame {
                stream_id,
                fin_stream,
                frame,
            } => {
                let use_control_stream = mutate_control
                    || is_control_uni_stream_id(*stream_id)
                    || matches!(
                        frame,
                        QFrame::CancelPush { .. }
                            | QFrame::Settings { .. }
                            | QFrame::PushPromise { .. }
                            | QFrame::GoAway { .. }
                            | QFrame::MaxPushId { .. }
                            | QFrame::PriorityUpdateRequest { .. }
                            | QFrame::PriorityUpdatePush { .. }
                    );
                *stream_id = if use_control_stream {
                    CLIENT_CONTROL_STREAM_ID
                } else {
                    request_stream_id
                };
                *fin_stream = state.rand_mut().below(2) == 0;
                match frame {
                    QFrame::Data { payload }
                    | QFrame::Headers {
                        header_block: payload,
                    }
                    | QFrame::Unknown {
                        raw_type: _,
                        payload,
                    } => {
                        if payload.is_empty() || state.rand_mut().below(2) == 0 {
                            *payload = random_bytes(
                                state,
                                if use_control_stream {
                                    MAX_ACTION_BYTES
                                } else {
                                    MAX_FRAME_BYTES as usize
                                },
                            );
                        } else {
                            let pos = state.rand_mut().below(payload.len()) as usize;
                            payload[pos] = random_fuzz_byte(state);
                        }
                    }
                    _ => return Ok(MutationResult::Skipped),
                }
            }
            Action::FlushPackets
            | Action::ConnectionClose { .. }
            | Action::SendHeadersFrame { .. } => {
                return Ok(MutationResult::Skipped);
            }
        }

        store_h3_input(input, &mut h3_corp);
        Ok(MutationResult::Mutated)
    }
}

// 修改一个控制帧长度类型的内容
// Mutator for modifying a length field in a control frame's content (e.g., length fields in QPACK instructions).
// pub struct H3ControlLengthMutator;
// impl H3ControlLengthMutator {
//     pub fn new() -> Self {
//         Self
//     }
// }
// impl Named for H3ControlLengthMutator {
//     fn name(&self) -> &Cow<'static, str> {
//         static NAME: Cow<'static, str> = Cow::Borrowed("H3ControlLengthMutator");
//         &NAME
//     }
// }
// impl<I, S> Mutator<I, S> for H3ControlLengthMutator
// where
//     S: HasRand + HasMetadata,
//     I: HasMutatorBytes,
// {
//     fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
//         debug!("H3ControlLengthMutator");
//         let mut h3_corp: H3Struct = bincode::deserialize(input.bytes()).unwrap();
//         if h3_corp.control_blocks.is_empty() {
//             return Ok(MutationResult::Skipped);
//         }
//         // Choose a random control frame.
//         let idx = state.rand_mut().below(h3_corp.control_blocks.len()) as usize;
//         let frame = &mut h3_corp.control_blocks[idx].basic_frame;
//         match frame {
//             // If QPACK insertion with explicit length fields for name/value.
//             QFrame::InsertWithoutNameRef { ref mut name, ref mut value } => {
//                 // Intentionally corrupt the length by adding or subtracting 1 from actual lengths.
//                 // (We assume the struct stores length implicitly by strings' length.)
//                 if !name.is_empty() {
//                     if state.rand_mut().below(2) == 0 {
//                         // Remove last byte of name to simulate length longer than actual.
//                         name.pop();
//                     } else {
//                         // Add an extra null byte to name string to simulate actual shorter than length.
//                         name.push('\0');
//                     }
//                 }
//                 if !value.is_empty() {
//                     if state.rand_mut().below(2) == 0 {
//                         value.pop();
//                     } else {
//                         value.push('\0');
//                     }
//                 }
//             }
//             // If QPACK insertion with name reference (only value length relevant).
//             QFrame::InsertWithNameRef { ref mut value, .. } => {
//                 if !value.is_empty() {
//                     if state.rand_mut().below(2) == 0 {
//                         value.pop();
//                     } else {
//                         value.push('\0');
//                     }
//                 }
//             }
//             // If unknown frame with payload, perhaps manipulate its payload length indirectly by truncation/extension.
//             QFrame::Unknown(ref mut ty, ref mut payload) => {
//                 if !payload.is_empty() {
//                     if state.rand_mut().below(2) == 0 {
//                         // Drop last byte of payload to simulate advertised length larger than actual.
//                         payload.pop();
//                     } else {
//                         // Add a padding byte to payload to simulate advertised length smaller than actual.
//                         payload.push(0);
//                     }
//                 }
//             }
//             _ => {
//                 // If frame type has no length field to manipulate, skip.
//                 return Ok(MutationResult::Skipped);
//             }
//         }
//         let changed_bytes = bincode::serialize(&h3_corp).unwrap();
//         input.resize(changed_bytes.len(), 0);
//         unsafe {
//             buffer_copy(input.bytes_mut(), changed_bytes.as_slice(), 0, 0, changed_bytes.len());
//         }
//         Ok(MutationResult::Mutated)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use libafl::inputs::{BytesInput, HasMutatorBytes};
    use libafl::state::NopState;

    fn oversized_stream_bytes(stream_id: u64) -> Action {
        Action::StreamBytes {
            stream_id,
            fin_stream: false,
            bytes: vec![0x41; MAX_ACTION_BYTES + 64],
        }
    }

    fn input_from_h3(h3_corp: &H3Struct) -> BytesInput {
        BytesInput::new(bincode::serialize(h3_corp).unwrap())
    }

    fn decode_input(input: &BytesInput) -> H3Struct {
        bincode::deserialize(input.bytes()).unwrap()
    }

    #[test]
    fn store_h3_input_truncates_oversized_actions() {
        let mut h3_corp = H3Struct::new();
        h3_corp.send_timeout = MAX_MUTATED_TIMEOUT_MS + 250;
        h3_corp.recv_timeout = MAX_MUTATED_TIMEOUT_MS + 500;
        h3_corp.data_actions = (0..(MAX_ACTION_LIST_LEN + 6))
            .map(|idx| oversized_stream_bytes((idx as u64) * 4))
            .collect();
        h3_corp.control_actions.push(Action::ConnectionClose {
            error: quiche::ConnectionError {
                is_app: true,
                error_code: quiche::h3::WireErrorCode::NoError as u64,
                reason: vec![0x42; MAX_ACTION_REASON_BYTES + 32],
            },
        });
        h3_corp.control_actions.extend(
            (0..(MAX_ACTION_LIST_LEN + 6))
                .map(|idx| oversized_stream_bytes(CLIENT_CONTROL_STREAM_ID + (idx as u64) * 4)),
        );

        let mut input = BytesInput::new(Vec::new());
        store_h3_input(&mut input, &mut h3_corp);

        let stored: H3Struct = bincode::deserialize(input.bytes()).unwrap();
        assert_eq!(stored.send_timeout, MAX_MUTATED_TIMEOUT_MS);
        assert_eq!(stored.recv_timeout, MAX_MUTATED_TIMEOUT_MS);
        assert_eq!(stored.data_actions.len(), MAX_ACTION_LIST_LEN);
        assert_eq!(stored.control_actions.len(), MAX_ACTION_LIST_LEN);

        for action in stored
            .data_actions
            .iter()
            .chain(stored.control_actions.iter())
        {
            match action {
                Action::StreamBytes { bytes, .. } => {
                    assert!(bytes.len() <= MAX_ACTION_BYTES);
                }
                Action::ConnectionClose { error } => {
                    assert!(error.reason.len() <= MAX_ACTION_REASON_BYTES);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn load_h3_input_skips_oversized_testcase() {
        let input = BytesInput::new(vec![0; MAX_TESTCASE_BYTES + 1]);
        assert!(load_h3_input(&input).is_none());
    }

    #[test]
    fn qpack_blocked_mutator_builds_structured_plan() {
        let mut state = NopState::<BytesInput>::new();
        let mut input = input_from_h3(&H3Struct::new());
        let mut mutator = H3QpackBlockedMutator::new();

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);

        let stored = decode_input(&input);
        assert!(!stored.qpack_plan.steps.is_empty());
        assert!(stored.data_blocks.is_empty());
        assert!(stored
            .qpack_plan
            .steps
            .iter()
            .any(|step| matches!(step, H3QpackStep::RequestHeaderBlock { .. })));
        assert!(stored.control_actions.iter().any(|action| matches!(
            action,
            Action::SendFrame {
                frame: QFrame::Settings { .. },
                ..
            }
        )));
    }

    #[test]
    fn qpack_amplify_mutator_keeps_structured_requests() {
        let mut state = NopState::<BytesInput>::new();
        let mut input = input_from_h3(&H3Struct::new());
        let mut mutator = H3QpackAmplifyMutator::new();

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);

        let stored = decode_input(&input);
        let request_steps: Vec<&QpackHeaderBlock> = stored
            .qpack_plan
            .steps
            .iter()
            .filter_map(|step| match step {
                H3QpackStep::RequestHeaderBlock { block, .. } => Some(block),
                _ => None,
            })
            .collect();

        assert!(!request_steps.is_empty());
        assert!(request_steps.iter().all(|block| {
            serialize_qpack_header_block(block)
                .map(|bytes| bytes.len() <= MAX_QPACK_BLOCKED_PAYLOAD)
                .unwrap_or(false)
        }));
    }

    #[test]
    fn qpack_scenario_seed_mutator_replaces_testcase_with_structured_seed() {
        let mut state = NopState::<BytesInput>::new();
        let mut input = input_from_h3(&H3Struct::new());
        let mut mutator = H3QpackScenarioSeedMutator::new();

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);

        let stored = decode_input(&input);
        assert!(stored.data_blocks.is_empty());
        assert!(stored.data_actions.is_empty());
        assert!(!stored.qpack_plan.steps.is_empty());
        assert!(stored
            .control_blocks
            .iter()
            .any(|block| matches!(block.basic_frame, QFrame::Settings { .. })));
        assert!(stored.qpack_plan.steps.iter().any(|step| matches!(
            step,
            H3QpackStep::OpenEncoderStream { .. } | H3QpackStep::OpenDecoderStream { .. }
        )));
    }
}

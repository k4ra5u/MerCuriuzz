use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use h3i::actions::h3::Action;
use h3i::{
    HTTP3_CONTROL_STREAM_TYPE_ID, QPACK_DECODER_STREAM_TYPE_ID, QPACK_ENCODER_STREAM_TYPE_ID,
};
use mylibafl::inputstruct::{
    h3_input::{
        append_raw_headers_stream_script, blocked_qpack_payload,
        blocked_qpack_payload_with_padding, raw_headers_frame_bytes, ByteSendPlan, H3ControlBlock,
        H3DataBlock, H3QpackPlan, H3QpackStep, H3Struct, QpackDecoderInstruction,
        QpackEncoderInstruction, QpackFieldRep, QpackHeaderBlock,
    },
    *,
};
use quiche::h3::frame::Frame as QFrame;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../my_h3_fuzzer/corpus-nor")
}

fn write_case(name: &str, h3_struct: &H3Struct) {
    let out_dir = corpus_dir();
    fs::create_dir_all(&out_dir).unwrap();
    let file_name = out_dir.join(name);
    let mut file = File::create(file_name).unwrap();
    let testcase_bytes = bincode::serialize(h3_struct).unwrap();
    file.write_all(&testcase_bytes).unwrap();
}

fn base_struct() -> H3Struct {
    let mut h3_struct = H3Struct::new();
    h3_struct.send_timeout = 0;
    h3_struct.recv_timeout = 0;
    h3_struct.packet_resort_type = pkt_resort_type::None;
    h3_struct
}

fn basic_block(method: &str, path: &str) -> H3DataBlock {
    let mut block = H3DataBlock::new();
    block.method = method.to_string();
    block.path = path.to_string();
    block
        .header_pairs
        .push((b"user-agent".to_vec(), b"Mercuriuzz".to_vec()));
    block
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

fn structured_qpack_case(plan: H3QpackPlan) -> H3Struct {
    let mut h3_struct = base_struct();
    let blocked_streams = plan
        .steps
        .iter()
        .filter(|step| matches!(step, H3QpackStep::RequestHeaderBlock { .. }))
        .count() as u64
        + 1;

    let mut settings = H3ControlBlock::new();
    settings.repeat_num = 1;
    settings.basic_frame = QFrame::Settings {
        max_field_section_size: None,
        qpack_max_table_capacity: Some(1024),
        qpack_blocked_streams: Some(blocked_streams),
        connect_protocol_enabled: None,
        h3_datagram: None,
        grease: None,
        additional_settings: None,
        raw: None,
    };

    h3_struct.control_blocks.push(settings);
    h3_struct.qpack_plan = plan;
    h3_struct
}

fn qpack_plan_insert_then_use() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_encoder_step(
                6,
                ByteSendPlan {
                    chunk_size: 256,
                    flush_each_chunk: true,
                },
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 512 },
                    qpack_insert_without_name_ref(b"x-seed", b"alpha"),
                ],
            ),
            H3QpackStep::Flush,
            qpack_request_step(
                0,
                false,
                ByteSendPlan {
                    chunk_size: 128,
                    flush_each_chunk: true,
                },
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
                ByteSendPlan {
                    chunk_size: 64,
                    flush_each_chunk: true,
                },
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
                ByteSendPlan {
                    chunk_size: 128,
                    flush_each_chunk: true,
                },
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 512 },
                    qpack_insert_without_name_ref(b"x-seed", b"beta"),
                ],
            ),
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
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 512 },
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
                        fields.push(QpackFieldRep::IndexedPostBase { index: 0 });
                        fields.push(QpackFieldRep::LiteralWithPostBaseNameRef {
                            index: 0,
                            value: b"pb".to_vec(),
                        });
                        fields
                    },
                },
            ),
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
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 512 },
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
                            index: 2,
                        });
                        fields
                    },
                },
            ),
        ],
    }
}

fn qpack_plan_decoder_feedback_mix() -> H3QpackPlan {
    H3QpackPlan {
        steps: vec![
            qpack_open_encoder_step(6),
            qpack_open_decoder_step(10),
            qpack_encoder_step(
                6,
                ByteSendPlan::default(),
                vec![
                    QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 512 },
                    qpack_insert_without_name_ref(b"x-seed", b"gamma"),
                ],
            ),
            H3QpackStep::Flush,
            qpack_request_step(
                0,
                false,
                ByteSendPlan {
                    chunk_size: 96,
                    flush_each_chunk: true,
                },
                QpackHeaderBlock {
                    required_insert_count: 1,
                    base: 1,
                    fields: {
                        let mut fields = basic_qpack_request_fields(b"/qpack/decoder-feedback-mix");
                        fields.push(QpackFieldRep::Indexed {
                            is_static: false,
                            index: 0,
                        });
                        fields
                    },
                },
            ),
            qpack_decoder_step(
                10,
                ByteSendPlan::default(),
                vec![
                    QpackDecoderInstruction::HeaderAck { stream_id: 0 },
                    QpackDecoderInstruction::StreamCancellation { stream_id: 0 },
                    QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                ],
            ),
        ],
    }
}

fn gen_h3_get_frame() {
    let mut h3_struct = base_struct();
    h3_struct.data_blocks.push(basic_block("GET", "/"));
    write_case("h3_get_testcase", &h3_struct);
}

fn gen_h3_post_frame() {
    let mut h3_struct = base_struct();
    let mut post_block = basic_block("POST", "/submit");
    post_block.header_pairs.push((
        b"content-type".to_vec(),
        b"application/x-www-form-urlencoded".to_vec(),
    ));
    post_block.body = b"field1=value1&field2=value2".to_vec();
    post_block.content_length = post_block.body.len();
    h3_struct.data_blocks.push(post_block);
    write_case("h3_post_testcase", &h3_struct);
}

fn gen_h3_options_asterisk_frame() {
    let mut h3_struct = base_struct();
    h3_struct.data_blocks.push(basic_block("OPTIONS", "*"));
    write_case("h3_options_asterisk_testcase", &h3_struct);
}

fn gen_h3_multi_stream_frame() {
    let mut h3_struct = base_struct();

    let get_block = basic_block("GET", "/multi/a");

    let mut post_block = basic_block("POST", "/multi/upload");
    post_block.body = b"abcdefgh12345678".to_vec();
    post_block.content_length = post_block.body.len();
    post_block.header_patterns.push("split_body".to_string());

    let mut head_block = basic_block("HEAD", "/multi/status");
    head_block
        .header_pairs
        .push((b"accept".to_vec(), b"*/*".to_vec()));

    h3_struct.data_blocks.push(get_block);
    h3_struct.data_blocks.push(post_block);
    h3_struct.data_blocks.push(head_block);
    h3_struct.data_actions.push(Action::FlushPackets);
    write_case("h3_multi_stream_testcase", &h3_struct);
}

fn gen_h3_control_settings_frame() {
    let mut h3_struct = base_struct();
    h3_struct.data_blocks.push(basic_block("GET", "/settings"));

    let mut settings = H3ControlBlock::new();
    settings.repeat_num = 1;
    settings.basic_frame = QFrame::Settings {
        max_field_section_size: None,
        qpack_max_table_capacity: None,
        qpack_blocked_streams: None,
        connect_protocol_enabled: None,
        h3_datagram: None,
        grease: None,
        additional_settings: Some(vec![(0x21, 1), (0x2a, 16)]),
        raw: None,
    };

    let mut goaway = H3ControlBlock::new();
    goaway.repeat_num = 1;
    goaway.basic_frame = QFrame::GoAway { id: 0 };

    h3_struct.control_blocks.push(settings);
    h3_struct.control_blocks.push(goaway);
    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 2,
        fin_stream: false,
        stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
    });
    h3_struct.control_actions.push(Action::FlushPackets);
    write_case("h3_control_settings_testcase", &h3_struct);
}

fn gen_h3_control_mix_frame() {
    let mut h3_struct = base_struct();
    h3_struct.data_blocks.push(basic_block("GET", "/control"));

    let mut cancel_push = H3ControlBlock::new();
    cancel_push.repeat_num = 2;
    cancel_push.basic_frame = QFrame::CancelPush { push_id: 1 };

    let mut max_push = H3ControlBlock::new();
    max_push.repeat_num = 1;
    max_push.basic_frame = QFrame::MaxPushId { push_id: 8 };

    let mut prio_req = H3ControlBlock::new();
    prio_req.repeat_num = 1;
    prio_req.basic_frame = QFrame::PriorityUpdateRequest {
        prioritized_element_id: 4,
        priority_field_value: b"u=3".to_vec(),
    };

    let mut unknown = H3ControlBlock::new();
    unknown.repeat_num = 1;
    unknown.basic_frame = QFrame::Unknown {
        raw_type: 0x41,
        payload: b"mystery".to_vec(),
    };

    h3_struct.control_blocks.push(cancel_push);
    h3_struct.control_blocks.push(max_push);
    h3_struct.control_blocks.push(prio_req);
    h3_struct.control_blocks.push(unknown);
    write_case("h3_control_mix_testcase", &h3_struct);
}

fn gen_h3_trailers_wait_frame() {
    let mut h3_struct = base_struct();

    let mut block = basic_block("POST", "/trailers");
    block.body = b"0123456789abcdef".to_vec();
    block.content_length = block.body.len();
    block.header_patterns.push("trailers".to_string());
    h3_struct.data_blocks.push(block);
    h3_struct.data_actions.push(Action::FlushPackets);
    write_case("h3_trailers_wait_testcase", &h3_struct);
}

fn gen_h3_duplicate_content_length_frame() {
    let mut h3_struct = base_struct();
    let mut block = basic_block("POST", "/dup-cl");
    block.body = b"abcdef".to_vec();
    block.content_length = block.body.len();
    block
        .header_patterns
        .push("duplicate_content_length".to_string());
    block
        .header_pairs
        .push((b"content-length".to_vec(), b"999".to_vec()));
    h3_struct.data_blocks.push(block);
    write_case("h3_duplicate_content_length_testcase", &h3_struct);
}

fn gen_h3_omitted_pseudo_frame() {
    let mut h3_struct = base_struct();
    let mut block = basic_block("GET", "/pseudo");
    block.header_patterns.push("omit_path".to_string());
    block.header_patterns.push("extras_first".to_string());
    block
        .header_pairs
        .push((b"x-extra".to_vec(), b"1".to_vec()));
    block
        .header_pairs
        .push((b":authority".to_vec(), b"override.example".to_vec()));
    h3_struct.data_blocks.push(block);
    write_case("h3_omitted_pseudo_testcase", &h3_struct);
}

fn gen_h3_data_before_headers_frame() {
    let mut h3_struct = base_struct();
    let mut block = basic_block("POST", "/out-of-order");
    block.body = b"body-before-headers".to_vec();
    block.content_length = block.body.len();
    block
        .header_patterns
        .push("data_before_headers".to_string());
    block.header_patterns.push("split_body".to_string());
    h3_struct.data_blocks.push(block);
    write_case("h3_data_before_headers_testcase", &h3_struct);
}

fn gen_h3_action_reserved_uni_frame() {
    let mut h3_struct = base_struct();
    h3_struct
        .data_blocks
        .push(basic_block("GET", "/reserved-uni"));
    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 6,
        fin_stream: false,
        stream_type: 0x21,
    });
    h3_struct.control_actions.push(Action::StreamBytes {
        stream_id: 6,
        fin_stream: true,
        bytes: vec![0, 64, 64, 5, 1, 2, 3, 4, 5],
    });
    h3_struct.control_actions.push(Action::FlushPackets);
    write_case("h3_action_reserved_uni_stream_testcase", &h3_struct);
}

fn gen_h3_qpack_like_raw_frame() {
    let mut h3_struct = base_struct();
    h3_struct
        .data_blocks
        .push(basic_block("GET", "/qpack-like"));
    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 10,
        fin_stream: false,
        stream_type: QPACK_ENCODER_STREAM_TYPE_ID,
    });
    h3_struct.control_actions.push(Action::StreamBytes {
        stream_id: 10,
        fin_stream: false,
        bytes: vec![0x3f, 0xe1, 0xff, 0x00, 0x01, 0x02],
    });
    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 14,
        fin_stream: false,
        stream_type: QPACK_DECODER_STREAM_TYPE_ID,
    });
    h3_struct.control_actions.push(Action::StreamBytes {
        stream_id: 14,
        fin_stream: true,
        bytes: vec![0x80, 0x00, 0xff],
    });
    write_case("h3_qpack_like_raw_stream_testcase", &h3_struct);
}

fn gen_h3_qpack_blocked_decode_frame() {
    let mut h3_struct = base_struct();

    let frame_bytes = raw_headers_frame_bytes(&blocked_qpack_payload());
    let first_split = frame_bytes.len().min(5);
    let second_split = frame_bytes.len().min(first_split + 16);
    let third_split = frame_bytes.len().min(second_split + 16);
    let split_points = [first_split, second_split, third_split, frame_bytes.len()];

    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 2,
        fin_stream: false,
        stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
    });
    h3_struct.control_actions.push(Action::SendFrame {
        stream_id: 2,
        fin_stream: false,
        frame: QFrame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: None,
        },
    });
    h3_struct.control_actions.push(Action::FlushPackets);

    // F01: request stream HEADERS starts with Required Insert Count = 1 and a
    // dynamic-table reference, then keeps receiving the rest of the payload
    // without ever sending the encoder-stream inserts needed to unblock it.
    let mut start = 0usize;
    for end in split_points.iter().copied() {
        if start >= end {
            continue;
        }
        h3_struct.data_actions.push(Action::StreamBytes {
            stream_id: 0,
            fin_stream: false,
            bytes: frame_bytes[start..end].to_vec(),
        });
        h3_struct.data_actions.push(Action::FlushPackets);

        start = end;
    }

    write_case("h3_qpack_blocked_decode_testcase", &h3_struct);
}

fn gen_h3_qpack_blocked_decode_amplified_frame() {
    let mut h3_struct = base_struct();

    let request_streams = [0_u64, 4, 8, 12];
    let qpack_payload = blocked_qpack_payload_with_padding(64 * 1024 * 128);

    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 2,
        fin_stream: false,
        stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
    });
    h3_struct.control_actions.push(Action::SendFrame {
        stream_id: 2,
        fin_stream: false,
        frame: QFrame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: Some(request_streams.len() as u64 + 2),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: None,
        },
    });
    h3_struct.control_actions.push(Action::FlushPackets);

    // F01 amplified: keep several request streams blocked at the same time and
    // continue feeding each one a larger HEADERS payload without ever sending
    // encoder-stream inserts to unblock the QPACK decoder.
    for stream_id in request_streams.iter() {
        append_raw_headers_stream_script(
            &mut h3_struct.data_actions,
            *stream_id,
            &qpack_payload,
            4096,
            0,
        );
    }

    write_case("h3_qpack_blocked_decode_amplified_testcase", &h3_struct);
}

fn gen_h3_qpack_blocked_decode_single_stream_large_frame() {
    let mut h3_struct = base_struct();

    let qpack_payload = blocked_qpack_payload_with_padding(512 * 1024);

    h3_struct.control_actions.push(Action::OpenUniStream {
        stream_id: 2,
        fin_stream: false,
        stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
    });
    h3_struct.control_actions.push(Action::SendFrame {
        stream_id: 2,
        fin_stream: false,
        frame: QFrame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: Some(4),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: None,
        },
    });
    h3_struct.control_actions.push(Action::FlushPackets);

    // This variant avoids peer MAX_STREAMS bottlenecks by keeping a single
    // request stream blocked while continuously extending the same HEADERS
    // frame payload.
    append_raw_headers_stream_script(&mut h3_struct.data_actions, 0, &qpack_payload, 4096, 0);

    write_case(
        "h3_qpack_blocked_decode_single_stream_large_testcase",
        &h3_struct,
    );
}

fn gen_h3_qpack_insert_then_use_frame() {
    let h3_struct = structured_qpack_case(qpack_plan_insert_then_use());
    write_case("h3_qpack_insert_then_use_testcase", &h3_struct);
}

fn gen_h3_qpack_blocked_then_unblock_frame() {
    let h3_struct = structured_qpack_case(qpack_plan_blocked_then_unblock());
    write_case("h3_qpack_blocked_then_unblock_testcase", &h3_struct);
}

fn gen_h3_qpack_post_base_reference_frame() {
    let h3_struct = structured_qpack_case(qpack_plan_post_base_reference());
    write_case("h3_qpack_post_base_reference_testcase", &h3_struct);
}

fn gen_h3_qpack_duplicate_chain_frame() {
    let h3_struct = structured_qpack_case(qpack_plan_duplicate_chain());
    write_case("h3_qpack_duplicate_chain_testcase", &h3_struct);
}

fn gen_h3_qpack_decoder_feedback_mix_frame() {
    let h3_struct = structured_qpack_case(qpack_plan_decoder_feedback_mix());
    write_case("h3_qpack_decoder_feedback_mix_testcase", &h3_struct);
}

fn gen_h3_reset_stop_sending_frame() {
    let mut h3_struct = base_struct();
    h3_struct.data_blocks.push(basic_block("GET", "/interrupt"));
    h3_struct.data_actions.push(Action::FlushPackets);
    h3_struct.data_actions.push(Action::StopSending {
        stream_id: 0,
        error_code: 0x10,
    });
    h3_struct.data_actions.push(Action::ResetStream {
        stream_id: 0,
        error_code: 0x11,
    });
    write_case("h3_reset_stop_sending_testcase", &h3_struct);
}

fn gen_h3_wait_for_headers_frame() {
    let mut h3_struct = base_struct();
    h3_struct.data_blocks.push(basic_block("GET", "/wait"));
    h3_struct.data_actions.push(Action::FlushPackets);
    write_case("h3_wait_for_headers_testcase", &h3_struct);
}

fn main() {
    gen_h3_get_frame();
    gen_h3_post_frame();
    gen_h3_options_asterisk_frame();
    gen_h3_multi_stream_frame();
    gen_h3_control_settings_frame();
    gen_h3_control_mix_frame();
    gen_h3_trailers_wait_frame();
    gen_h3_duplicate_content_length_frame();
    gen_h3_omitted_pseudo_frame();
    gen_h3_data_before_headers_frame();
    gen_h3_action_reserved_uni_frame();
    gen_h3_qpack_like_raw_frame();
    gen_h3_qpack_blocked_decode_frame();
    gen_h3_qpack_blocked_decode_amplified_frame();
    gen_h3_qpack_blocked_decode_single_stream_large_frame();
    gen_h3_qpack_insert_then_use_frame();
    gen_h3_qpack_blocked_then_unblock_frame();
    gen_h3_qpack_post_base_reference_frame();
    gen_h3_qpack_duplicate_chain_frame();
    gen_h3_qpack_decoder_feedback_mix_frame();
    gen_h3_reset_stop_sending_frame();
    gen_h3_wait_for_headers_frame();
    println!("generated corpus in {}", corpus_dir().display());
}

use std::{fs::File, io::Write};

use mylibafl::inputstruct::*;

use quiche::{frame, packet, stream::RangeBuf, Connection, ConnectionId, Error, Header};


fn gen_ping_frame() {
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(1);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(100);
    let ping_frame = frame::Frame::Ping {
        mtu_probe: None,
    };
    frame_cycle1 = frame_cycle1.add_frame(ping_frame);

    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);

    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    // input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/gen_testcase/corpus/pingframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);
}

fn gen_crypto_flood_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(1);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(1);
    for i in 0..100{
        let data: Vec<u8> = std::iter::repeat(41).take(1000).collect();
        let range_buf_data = RangeBuf::from(&data,i*1024,false);
        let crypto_frame = frame::Frame::Crypto {
            data: range_buf_data,
        };
        frame_cycle1 = frame_cycle1.add_frame(crypto_frame);
    }
    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);

    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    // input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/gen_testcase/corpus/cryptoframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);
}

fn gen_cid_flood_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(1);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(10000);
    let nci_frame = frame::Frame::NewConnectionId {
        seq_num: 2,
        retire_prior_to:2,
        conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
        reset_token: [100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115],
    };
    frame_cycle1 = frame_cycle1.add_frame(nci_frame);

    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);

    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    // input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/gen_testcase/corpus/cidframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);
}

fn gen_pc_flood_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(1);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(10000);
    let pc_frame = frame::Frame::PathChallenge {
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    frame_cycle1 = frame_cycle1.add_frame(pc_frame);
    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);

    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    // input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/gen_testcase/corpus/pcframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);
}
fn gen_cc_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(1);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(1);
    let cc_frame = frame::Frame::ConnectionClose {
        error_code: 0,
        frame_type: 0,
        reason: vec![255; 1200],
    };
    frame_cycle1 = frame_cycle1.add_frame(cc_frame);
    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);
    let mut frame_cycle2 = FramesCycleStruct::new();
    frame_cycle2 = frame_cycle2.set_repeat_num(10000);
    let cc_next_frame = frame::Frame::Others {
        data: vec![255;1200],
    };
    frame_cycle2 = frame_cycle2.add_frame(cc_next_frame);
    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/gen_testcase/corpus/ccframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);

}

fn gen_nci_huge_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(1);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(1);
    let nci_frame = frame::Frame::NewConnectionId  {
        seq_num: 0x100000000,
        retire_prior_to:0,
        conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
        reset_token: [100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115],
    };
    frame_cycle1 = frame_cycle1.add_frame(nci_frame);
    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/gen_testcase/corpus/nci_huge_frames";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);

}

fn gen_neqo_nci_crash_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(20);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(2);
    let nci_frame = frame::Frame::NewConnectionId  {
        seq_num: 4,
        retire_prior_to:0x3FFF_FFFF_FFFF_FFFE,
        conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8,9,10,11,12,13,14,15,16,17,18,19,20],
        reset_token: [100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115],
    };
    let ping_frame = frame::Frame::Ping { mtu_probe: Some((1000)) };
    frame_cycle1 = frame_cycle1.add_frame(nci_frame);
    frame_cycle1 = frame_cycle1.add_frame(ping_frame);
    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "./corpus/neqo_nci_frame";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);

}

fn gen_aioquic_rc_flood_frame(){
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(10);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(10000000000);
    let rc_frame = frame::Frame::RetireConnectionId {
        seq_num: 1,
    };
    frame_cycle1 = frame_cycle1.add_frame(rc_frame);
    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);

    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    // input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "./corpus/aioquic_rcframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);
}

fn main() {
    // println!("gen ping frame");
    // gen_ping_frame();
    // println!("gen crypto flood frame");
    // gen_crypto_flood_frame();
    // println!("gen cid flood frame");
    // gen_cid_flood_frame();
    // println!("gen pc flood frame");
    // gen_pc_flood_frame();
    // println!("gen cc frame");
    // gen_cc_frame();
    // println!("gen neqo nci crash frame");
    // gen_neqo_nci_crash_frame();
    println!("gen aioquic rc flood frame");
    gen_aioquic_rc_flood_frame();
    println!("finished")
}

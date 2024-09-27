use std::{fs::File, io::Write};

use mylibafl::inputstruct::*;

use quiche::{frame, packet, Connection, ConnectionId, Error, Header};

fn main() {
    let mut input_struct = InputStruct::new();
    input_struct = input_struct.set_pkt_type(packet::Type::Short).set_recv_timeout(20).set_send_timeout(10);
    input_struct = input_struct.set_packet_resort_type(pkt_resort_type::None);
    let mut frame_cycle1 = FramesCycleStruct::new();
    frame_cycle1 = frame_cycle1.set_repeat_num(500);
    // let pc_frame = frame::Frame::PathChallenge {
    //     data: [1, 2, 3, 4, 5, 6, 7, 8],
    // };
    let nci_frame = frame::Frame::NewConnectionId {
        seq_num: 2,
        retire_prior_to:1,
        conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
        reset_token: [100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115],
    };
    let ping_frame = frame::Frame::Ping { mtu_probe: Some(0) };
    //frame_cycle1 = frame_cycle1.add_frame(pc_frame);
    frame_cycle1 = frame_cycle1.add_frame(ping_frame);

    // let mut frame_cycle2 = FramesCycleStruct::new();
    // frame_cycle2 = frame_cycle2.set_repeat_num(200);
    // let pad_frame = frame::Frame::Padding { len: (100) };
    // frame_cycle2 = frame_cycle2.add_frame(pad_frame);
    input_struct = input_struct.add_frames_cycle(frame_cycle1);
    // input_struct = input_struct.add_frames_cycle(frame_cycle2);
    input_struct = input_struct.calc_frames_cycle_len();
    let input_bytes = input_struct.serialize();
    let file_name = "/home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/corpus/nciframes";
    let mut file = File::create(file_name).unwrap();
    let des_input = quic_input::InputStruct_deserialize(&input_bytes);
    file.write_all(&input_bytes);

}

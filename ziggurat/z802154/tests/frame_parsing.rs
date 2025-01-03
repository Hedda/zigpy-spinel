use z802154::*;

#[test]
fn test_frame_control() {
    let bytes = [0x61, 0x88, 0xFF];
    let (frame_control, remaining) = FrameControl::deserialize(&bytes).unwrap();

    assert_eq!(frame_control.frame_type, FrameType::Data);
    assert_eq!(frame_control.security_enabled, false);
    assert_eq!(frame_control.frame_pending, false);
    assert_eq!(frame_control.ack_request, true);
    assert_eq!(frame_control.pan_id_compression, true);
    assert_eq!(frame_control.reserved, false);
    assert_eq!(frame_control.sequence_number_suppression, false);
    assert_eq!(frame_control.information_elements_present, false);
    assert_eq!(frame_control.dest_addr_mode, AddressingMode::Short);
    assert_eq!(frame_control.frame_version, 0);
    assert_eq!(frame_control.src_addr_mode, AddressingMode::Short);

    assert_eq!(remaining, [0xFF]);
    assert_eq!(frame_control.to_bytes(), bytes[..2]);
}

#[test]
fn test_frame_data() {
    let bytes = [
        0x61, 0x88, 0xa3, 0xf5, 0x3e, 0x34, 0x52, 0x63, 0xf6, 0x48, 0x02, 0x00,
        0x00, 0xa5, 0x79, 0x1d, 0xc1, 0x28, 0x41, 0xf0, 0x48, 0x02, 0x8b, 0x86,
        0x34, 0xfe, 0xff, 0x27, 0x71, 0x84, 0x00, 0x13, 0xdc, 0x42, 0x64, 0x0f,
        0xca, 0x9c, 0x6e, 0xff, 0xc9, 0xcf, 0xd3, 0x35, 0x53, 0x54, 0xca, 0x68,
        0x16, 0x1c, 0xc9, 0x44, 0xc4, 0xad, 0x37, 0xc5, 0xea
    ];

    let frame = Frame::from_bytes(&bytes).unwrap();

    assert_eq!(frame.frame_control.frame_type, FrameType::Data);
    assert_eq!(frame.frame_control.security_enabled, false);
    assert_eq!(frame.frame_control.frame_pending, false);
    assert_eq!(frame.frame_control.ack_request, true);
    assert_eq!(frame.frame_control.pan_id_compression, true);
    assert_eq!(frame.frame_control.reserved, false);
    assert_eq!(frame.frame_control.sequence_number_suppression, false);
    assert_eq!(frame.frame_control.information_elements_present, false);
    assert_eq!(frame.frame_control.dest_addr_mode, AddressingMode::Short);
    assert_eq!(frame.frame_control.frame_version, 0);
    assert_eq!(frame.frame_control.src_addr_mode, AddressingMode::Short);

    assert_eq!(frame.sequence_number, Some(163));
    assert_eq!(frame.dest_pan_id, Some(0x3EF5));
    assert_eq!(frame.dest_address, Some(Address::NWK(NWK(0x5234))));
    assert_eq!(frame.src_pan_id, Some(0x3EF5));
    assert_eq!(frame.src_address, Some(Address::NWK(NWK(0xF663))));

    assert_eq!(frame.payload, bytes[9 .. bytes.len() - 2]);
    assert_eq!(frame.fcs, 0xEAC5);

    assert_eq!(frame.to_bytes(), bytes);
}

#[test]
fn test_frame_bad_fcs() {
    let mut bytes = [
        0x61, 0x88, 0xa3, 0xf5, 0x3e, 0x34, 0x52, 0x63, 0xf6, 0x48, 0x02, 0x00,
        0x00, 0xa5, 0x79, 0x1d, 0xc1, 0x28, 0x41, 0xf0, 0x48, 0x02, 0x8b, 0x86,
        0x34, 0xfe, 0xff, 0x27, 0x71, 0x84, 0x00, 0x13, 0xdc, 0x42, 0x64, 0x0f,
        0xca, 0x9c, 0x6e, 0xff, 0xc9, 0xcf, 0xd3, 0x35, 0x53, 0x54, 0xca, 0x68,
        0x16, 0x1c, 0xc9, 0x44, 0xc4, 0xad, 0x37, 0xc5, 0xea
    ];

    bytes[5] ^= 0xFF;

    let err = Frame::from_bytes(&bytes).unwrap_err();
    assert_eq!(err, "Invalid FCS");
}

#[test]
fn test_frame_ack() {
    let bytes = [0x02, 0x00, 0xd1, 0xbc, 0x72];

    let frame = Frame::from_bytes(&bytes).unwrap();

    assert_eq!(frame.frame_control.frame_type, FrameType::Ack);
    assert_eq!(frame.frame_control.security_enabled, false);
    assert_eq!(frame.frame_control.frame_pending, false);
    assert_eq!(frame.frame_control.ack_request, false);
    assert_eq!(frame.frame_control.pan_id_compression, false);
    assert_eq!(frame.frame_control.reserved, false);
    assert_eq!(frame.frame_control.sequence_number_suppression, false);
    assert_eq!(frame.frame_control.information_elements_present, false);
    assert_eq!(frame.frame_control.dest_addr_mode, AddressingMode::None);
    assert_eq!(frame.frame_control.frame_version, 0);
    assert_eq!(frame.frame_control.src_addr_mode, AddressingMode::None);

    assert_eq!(frame.sequence_number, Some(209));
    assert_eq!(frame.dest_pan_id, None);
    assert_eq!(frame.dest_address, None);
    assert_eq!(frame.src_pan_id, None);
    assert_eq!(frame.src_address, None);

    assert_eq!(frame.payload, []);
    assert_eq!(frame.fcs, 0x72BC);

    assert_eq!(frame.to_bytes(), bytes);
}
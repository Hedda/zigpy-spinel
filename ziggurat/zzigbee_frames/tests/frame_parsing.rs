use zzigbee_frames::*;
use hex_literal::hex;


#[test]
fn test_decryption_unicast() {
    let bytes = hex!("0802426b00000f2e287a0a0000a8ef171e004b120000f7a7e37b47adb47593c8a375c98ba6");
    let nwk_frame = NwkFrame::from_bytes(&bytes).unwrap();

    let expected_nwk_frame = NwkFrame {
        encrypted: true,
        nwk_header: NwkHeader {
            frame_control: NwkFrameControl {
                frame_type: NwkFrameType::Data,
                protocol_version: 2,
                discover_route: NwkRouteDiscovery::Suppress,
                multicast: false,
                security: true,
                source_route: false,
                destination: false,
                extended_source: false,
                end_device_initiator: false,
                reserved: 0b00,
            },
            destination: NWK(0x6b42),
            source: NWK(0x0000),
            radius: 15,
            sequence_number: 46,
            destination_ieee: None,
            source_ieee: None,
            multicast_control: None,
            source_route_relay_index: None,
            source_route: None,
        },
        aux_header: Some(NwkAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::NetworkKey,
                extended_source: true,
                require_verified_frame_counter: false,
                reserved: 0b0,
            },
            frame_counter: 2682,
            extended_source: Some(EUI64::from_hex("00:12:4b:00:1e:17:ef:a8")),
            key_sequence_number: 0,
        }),
        payload: hex!("f7a7e37b47adb47593c8a375c98ba6").to_vec(),
    };

    assert_eq!(nwk_frame, expected_nwk_frame);

    let key = Key::from_hex("e8785a1ed5996b3ef715cb3fbdd69187");
    let decrypted_nwk_frame = nwk_frame.decrypt(&key).unwrap();

    let expected_decrypted_nwk_frame = NwkFrame {
        encrypted: false,
        nwk_header: expected_nwk_frame.nwk_header,
        aux_header: expected_nwk_frame.aux_header,
        payload: hex!("00010600040101a9015701").to_vec(),
    };

    assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

    let aps_frame = ApsFrame::from_bytes(&decrypted_nwk_frame.payload).unwrap();

    let expected_aps_frame = ApsFrame {
        frame_control: ApsFrameControl {
            frame_type: ApsFrameType::Data,
            delivery_mode: ApsDeliveryMode::Unicast,
            reserved: 0b0,
            security: false,
            ack_request: false,
            extended_header: false,
        },
        destination_endpoint: 1,
        cluster_id: 0x0006,
        profile_id: 0x0104,
        source_endpoint: 1,
        counter: 169,
        asdu: hex!("015701").to_vec(),
    };

    assert_eq!(aps_frame, expected_aps_frame);
}


#[test]
fn test_decryption_broadcast() {
    let bytes = hex!("0802fdff426b1ebb28000000004fdeb726004b1200004062462a391a65a7d9e4b093bdb8abe90a0ea145c73f3b93");
    let nwk_frame = NwkFrame::from_bytes(&bytes).unwrap();

    let key = Key::from_hex("e8785a1ed5996b3ef715cb3fbdd69187");
    let decrypted_nwk_frame = nwk_frame.decrypt(&key).unwrap();

    let aps_frame = ApsFrame::from_bytes(&decrypted_nwk_frame.payload).unwrap();

    let expected_aps_frame = ApsFrame {
        frame_control: ApsFrameControl {
            frame_type: ApsFrameType::Data,
            delivery_mode: ApsDeliveryMode::Broadcast,
            reserved: 0b0,
            security: false,
            ack_request: false,
            extended_header: false,
        },
        destination_endpoint: 0,
        cluster_id: 0x0013,
        profile_id: 0x0000,
        source_endpoint: 0,
        counter: 0,
        asdu: hex!("00426b4fdeb726004b12008e").to_vec(),
    };

    assert_eq!(aps_frame, expected_aps_frame);
}

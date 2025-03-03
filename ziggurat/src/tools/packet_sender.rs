use serial2_tokio::SerialPort;
use std::env;
use ziggurat::ieee_802154::Ieee802154Frame;
use ziggurat::spinel::SpinelPropertyId;
use ziggurat::spinel_client::{SpinelClient, SpinelTxFrame};

use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let port = SerialPort::open(&args[1], 460_800)?;

    let client = SpinelClient::new(port);
    client.spawn_reader();

    let ncp_version = client
        .get_ncp_version()
        .await
        .expect("Invalid UTF-8 string");
    println!("NCP Version: {:?}", ncp_version);

    client
        .prop_value_set(SpinelPropertyId::PhyEnabled as u32, vec![true as u8])
        .await
        .expect("Failed to enable the PHY");

    client
        .prop_value_set(SpinelPropertyId::MacPromiscuousMode as u32, vec![2])
        .await
        .expect("Failed to set the MAC promiscuous mode");

    client
        .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![20])
        .await
        .expect("Failed to set the PHY");

    client
        .prop_value_set(
            SpinelPropertyId::MacRawStreamEnabled as u32,
            vec![true as u8],
        )
        .await
        .expect("Failed to enable the RAW stream");

    loop {
        let frame = SpinelTxFrame {
            psdu: Ieee802154Frame {
                frame_control: Ieee802154FrameControl {
                    frame_type: Command,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: false,
                    reserved: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Short,
                    frame_version: 0,
                    src_addr_mode: None,
                },
                sequence_number: Some(164),
                dest_pan_id: Some(PanId(0xffff)),
                dest_address: Some(Nwk(Nwk(0xffff))),
                src_pan_id: None,
                src_address: None,
                payload: b"\x07\x00\x09".to_vec(),
                fcs: 12972,
            },
            channel: 20,
            max_csma_backoffs: 1,
            max_frame_retries: 4,
            enable_csma_ca: true,
            is_header_updated: true,
            is_a_retransmit: false,
            is_security_processed: true,
            tx_delay: 0 as u32,
            tx_delay_base_time: 0 as u32,
            rx_channel_after_tx: 20,
            tx_power: 8,
        };

        match client.transmit_frame(&frame).await {
            Ok(status) => println!("Frame transmitted: {:?}", status),
            Err(e) => eprintln!("Error transmitting frame: {:?}", e),
        }
    }

    Ok(())
}

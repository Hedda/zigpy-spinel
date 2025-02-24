use serial2_tokio::SerialPort;
use ziggurat::ieee_802154::Ieee802154Frame;
use ziggurat::spinel::SpinelPropertyId;
use ziggurat::spinel_client::SpinelClient;

use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = SerialPort::open("/dev/cu.SLAB_USBtoUART", 460_800)?;

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
        .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![25])
        .await
        .expect("Failed to set the PHY");

    client
        .prop_value_set(
            SpinelPropertyId::MacRawStreamEnabled as u32,
            vec![true as u8],
        )
        .await
        .expect("Failed to enable the RAW stream");

    let (stream_raw_tx, mut stream_raw_rx) = mpsc::channel(32);

    {
        let mut guard = client.protocol.lock().await;
        guard.set_property_update_receiver(SpinelPropertyId::StreamRaw as u32, stream_raw_tx);
    }

    while let Some(stream_raw_prop) = stream_raw_rx.recv().await {
        let raw_packet = stream_raw_prop.value;
        if raw_packet.len() < 2 {
            continue;
        }

        let packet_len = u16::from_le_bytes([raw_packet[0], raw_packet[1]]) as usize;
        if packet_len > raw_packet.len() - 2 {
            continue;
        }

        let frame_data = raw_packet[2..packet_len + 2].to_vec();

        if let Ok(ieee_frame) = Ieee802154Frame::from_bytes_without_fcs(&frame_data) {
            println!("Received frame: {:#?}\n\n", ieee_frame);
        }
    }

    Ok(())
}

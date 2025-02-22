use serial2_tokio::SerialPort;
use ziggurat::spinel::{
    packed_uint21_to_bytes, HdlcLiteFrame, SpinelCommandId, SpinelFrame, SpinelHeader,
    SpinelPropertyId, SpinelProtocol, SpinelResetReason,
};
use ziggurat::spinel_client::SpinelClient;

use std::string::String;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = SerialPort::open("/dev/cu.SLAB_USBtoUART", 460_800)?;

    let client = SpinelClient::new(port);
    client.spawn_reader();

    let timeout = std::time::Duration::from_secs(5);
    let ncp_version_rsp = client
        .prop_value_get(SpinelPropertyId::NcpVersion as u32, timeout)
        .await
        .unwrap();

    let ncp_version_with_null = String::from_utf8(ncp_version_rsp).expect("Invalid UTF-8 string");
    let ncp_version = ncp_version_with_null.trim_matches(char::from(0x00));

    println!("NCP Version: {:?}", ncp_version);

    client
        .prop_value_set(SpinelPropertyId::PhyEnabled as u32, vec![1], timeout)
        .await
        .unwrap();

    client
        .prop_value_set(
            SpinelPropertyId::MacPromiscuousMode as u32,
            vec![2],
            timeout,
        )
        .await
        .unwrap();

    client
        .prop_value_set(
            SpinelPropertyId::MacRawStreamEnabled as u32,
            vec![1],
            timeout,
        )
        .await
        .unwrap();

    client
        .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![25], timeout)
        .await
        .unwrap();

    // Sleep for 30s
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    Ok(())
}

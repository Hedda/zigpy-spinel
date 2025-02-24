use crate::spinel::{
    packed_uint21_deserialize, packed_uint21_to_bytes, HdlcLiteFrame, SpinelCommandId, SpinelFrame,
    SpinelPropertyId, SpinelProtocol,
};
use serial2_tokio::SerialPort;
use std::string::String;

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct SpinelClient {
    pub port: Arc<SerialPort>,
    pub protocol: Arc<Mutex<SpinelProtocol>>,
}

#[derive(Debug)]
pub enum SpinelSendError {
    IoError(std::io::Error),
    ChannelClosed,
    Timeout,
}

impl SpinelClient {
    pub fn new(port: SerialPort) -> Self {
        Self {
            port: Arc::new(port),
            protocol: Arc::new(Mutex::new(SpinelProtocol::new())),
        }
    }

    /// Start a reading loop to parse and handle inbound frames.
    pub fn spawn_reader(&self) {
        let port_clone = Arc::clone(&self.port);
        let client_clone = Arc::clone(&self.protocol);

        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];

            loop {
                match port_clone.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        let mut protocol = client_clone.lock().await;
                        protocol.handle_inbound_bytes(&buffer[..n])
                    }
                    Ok(_) => {
                        eprintln!("EOF or 0 bytes read, stopping.");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error reading port: {:?}", e);
                        break;
                    }
                }
            }
        });
    }

    pub async fn send_command(
        &self,
        command_id: u8,
        payload: Vec<u8>,
    ) -> Result<SpinelFrame, SpinelSendError> {
        let (frame, rx) = {
            let mut guard = self.protocol.lock().await;
            guard.prepare_request(command_id, payload)
        };

        let hdlc_frame = HdlcLiteFrame {
            data: frame.to_bytes(),
        };

        let data = hdlc_frame.to_bytes_with_flags();

        self.port
            .write(&data)
            .await
            .map_err(SpinelSendError::IoError)?;

        match timeout(TIMEOUT, rx).await {
            Ok(Ok(response_frame)) => Ok(response_frame),
            Ok(Err(_recv_closed)) => {
                let mut guard = self.protocol.lock().await;
                guard.cancel_request(frame.header.transaction_id);

                Err(SpinelSendError::ChannelClosed)
            }
            Err(_elapsed) => {
                let mut guard = self.protocol.lock().await;
                guard.cancel_request(frame.header.transaction_id);

                Err(SpinelSendError::Timeout)
            }
        }
    }

    pub async fn prop_value_get(&self, property_id: u32) -> Result<Vec<u8>, SpinelSendError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueGet as u8,
                packed_uint21_to_bytes(property_id),
            )
            .await?;

        let response_payload = response.payload;
        let (rsp_property_id, payload) = match packed_uint21_deserialize(&response_payload) {
            Ok((property_id, payload)) => (property_id, payload),
            Err(e) => {
                return Err(SpinelSendError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            }
        };

        if rsp_property_id != property_id {
            return Err(SpinelSendError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Property ID mismatch",
            )));
        }

        Ok(payload.to_vec())
    }

    pub async fn prop_value_set(
        &self,
        property_id: u32,
        value: Vec<u8>,
    ) -> Result<Vec<u8>, SpinelSendError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueSet as u8,
                packed_uint21_to_bytes(property_id)
                    .iter()
                    .chain(value.iter())
                    .cloned()
                    .collect(),
            )
            .await?;

        let response_payload = response.payload;
        let (rsp_property_id, payload) = match packed_uint21_deserialize(&response_payload) {
            Ok((property_id, payload)) => (property_id, payload),
            Err(e) => {
                return Err(SpinelSendError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            }
        };

        if rsp_property_id != property_id {
            return Err(SpinelSendError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Property ID mismatch",
            )));
        }

        Ok(payload.to_vec())
    }

    pub async fn get_ncp_version(&self) -> Result<String, SpinelSendError> {
        let ncp_version_rsp = self
            .prop_value_get(SpinelPropertyId::NcpVersion as u32)
            .await
            .unwrap();

        let ncp_version_with_null =
            String::from_utf8(ncp_version_rsp).expect("Invalid UTF-8 string");

        Ok(ncp_version_with_null
            .trim_matches(char::from(0x00))
            .to_string())
    }
}

#![allow(dead_code)]

use std::convert::TryFrom;
use constant_time_eq::constant_time_eq;

use cbc::Encryptor;
use aes::Block;
use aes::Aes128;
use aes::cipher::KeyInit;
use aes::cipher::KeyIvInit;
use aes::cipher::BlockModeEncrypt;
use cbc::cipher::BlockCipherEncrypt;


#[derive(Debug, PartialEq, Copy, Clone)]
pub struct NWK(pub u16);

impl NWK {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 2 {
            return Err("Not enough data to parse NWK");
        }

        Ok((Self(u16::from_be_bytes([bytes[0], bytes[1]])), &bytes[2..]))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}


#[derive(Debug, PartialEq, Copy, Clone)]
pub struct EUI64(pub [u8; 8]);

impl EUI64 {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse EUI64");
        }

        let mut eui = [0; 8];
        eui.copy_from_slice(&bytes[..8]);

        Ok((Self(eui), &bytes[8..]))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}


#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Address {
    NWK(NWK),
    EUI64(EUI64),
}


#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkFrameType {
    Data = 0b00,
    Command = 0b01,
}

impl TryFrom<u8> for NwkFrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(NwkFrameType::Data),
            0b01 => Ok(NwkFrameType::Command),
            _ => Err("Invalid frame type"),
        }
    }
}


#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkRouteDiscovery {
    Suppress = 0b00,
    Enable = 0b01,
    WithMulticast = 0b10,
}

impl TryFrom<u8> for NwkRouteDiscovery {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(NwkRouteDiscovery::Suppress),
            0b01 => Ok(NwkRouteDiscovery::Enable),
            0b10 => Ok(NwkRouteDiscovery::WithMulticast),
            _ => Err("Invalid route discovery"),
        }
    }
}


#[derive(Debug, Clone)]
pub struct NwkFrameControl {
    pub frame_type: NwkFrameType,
    pub protocol_version: u8,
    pub discover_route: NwkRouteDiscovery,
    pub multicast: bool,
    pub security: bool,
    pub source_route: bool,
    pub destination: bool,
    pub extended_source: bool,
    pub end_device_initiator: bool,
    pub reserved: u8,
}

impl NwkFrameControl {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 2 {
            return Err("Not enough data to parse NwkFrameControl");
        }

        Ok((
            Self {
                frame_type: NwkFrameType::try_from((bytes[0] >> 0) & 0b11)?,
                protocol_version: (bytes[0] >> 2) & 0b1111,
                discover_route: NwkRouteDiscovery::try_from((bytes[0] >> 6) & 0b11)?,
                multicast: (bytes[1] >> 0) & 0b1 == 1,
                security: (bytes[1] >> 1) & 0b1 == 1,
                source_route: (bytes[1] >> 2) & 0b1 == 1,
                destination: (bytes[1] >> 3) & 0b1 == 1,
                extended_source: (bytes[1] >> 4) & 0b1 == 1,
                end_device_initiator: (bytes[1] >> 5) & 0b1 == 1,
                reserved: (bytes[1] >> 6) & 0b11,
            },
            &bytes[2..],
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(
            (((self.frame_type as u8) & 0b11) << 0)
          | (((self.protocol_version as u8) & 0b1111) << 2)
          | (((self.discover_route as u8) & 0b11) << 6),
        );

        bytes.push(
            (((self.multicast as u8) & 0b1) << 0)
          | (((self.security as u8) & 0b1) << 1)
          | (((self.source_route as u8) & 0b1) << 2)
          | (((self.destination as u8) & 0b1) << 3)
          | (((self.extended_source as u8) & 0b1) << 4)
          | (((self.end_device_initiator as u8) & 0b1) << 5)
          | (((self.reserved as u8) & 0b11) << 6),
        );

        bytes
    }
}



#[derive(Debug, Clone)]
pub struct NwkHeader {
    pub frame_control: NwkFrameControl,
    pub destination: NWK,
    pub source: NWK,
    pub radius: u8,
    pub sequence_number: u8,
    pub destination_ieee: Option<EUI64>,
    pub source_ieee: Option<EUI64>,
    pub multicast_control: Option<u8>,
    pub source_route_relay_index: Option<u8>,
    pub source_route: Option<Vec<NWK>>,
}

impl NwkHeader {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse NwkHeader");
        }

        let mut remaining = bytes;
        let frame_control;
        let destination;
        let source;

        (frame_control, remaining) = NwkFrameControl::deserialize(remaining)?;
        (destination, remaining) = NWK::deserialize(remaining)?;
        (source, remaining) = NWK::deserialize(remaining)?;

        let radius = remaining[0];
        let sequence_number = remaining[1];
        remaining = &remaining[2..];

        let mut destination_ieee = None;
        let mut source_ieee = None;
        let mut multicast_control = None;
        let mut source_route_relay_index = None;
        let mut source_route = None;

        if frame_control.destination {
            let ieee;
            (ieee, remaining) = EUI64::deserialize(remaining)?;
            destination_ieee = Some(ieee);
        }

        if frame_control.extended_source {
            let ieee;
            (ieee, remaining) = EUI64::deserialize(remaining)?;
            source_ieee = Some(ieee);
        }

        if frame_control.multicast {
            multicast_control = Some(remaining[0]);
            remaining = &remaining[1..];
        }

        if frame_control.source_route {
            let relay_count = remaining[0];
            source_route_relay_index = Some(remaining[1]);
            remaining = &remaining[2..];

            let mut temp_source_route = Vec::new();

            for _ in 0..relay_count {
                let nwk;
                (nwk, remaining) = NWK::deserialize(remaining)?;
                temp_source_route.push(nwk);
            }

            source_route = Some(temp_source_route);
        }

        Ok(
            (Self {
                frame_control,
                destination,
                source,
                radius,
                sequence_number,
                destination_ieee,
                source_ieee,
                multicast_control,
                source_route_relay_index,
                source_route,
            }, remaining)
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.frame_control.to_bytes());
        bytes.extend(self.destination.to_bytes());
        bytes.extend(self.source.to_bytes());
        bytes.push(self.radius);
        bytes.push(self.sequence_number);

        if let Some(ieee) = self.destination_ieee {
            bytes.extend(ieee.to_bytes());
        }

        if let Some(ieee) = self.source_ieee {
            bytes.extend(ieee.to_bytes());
        }

        if let Some(control) = self.multicast_control {
            bytes.push(control);
        }

        if self.source_route.is_none() != self.source_route_relay_index.is_none() {
            panic!("Source route relay index must be present if source route is present");
        }

        if let Some(relay_index) = self.source_route_relay_index {
            // Unnecessary
            if let Some(source_route) = &self.source_route {
                bytes.push(source_route.len() as u8);
                bytes.push(relay_index);

                for nwk in source_route {
                    bytes.extend(nwk.to_bytes());
                }
            }
        }

        bytes
    }
}


#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkSecurityHeaderKeyId {
    DataKey = 0x00,
    NetworkKey = 0x01,
    KeyTransportKey = 0x02,
    KeyLoadKey = 0x03,
}

impl TryFrom<u8> for NwkSecurityHeaderKeyId {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NwkSecurityHeaderKeyId::DataKey),
            0x01 => Ok(NwkSecurityHeaderKeyId::NetworkKey),
            0x02 => Ok(NwkSecurityHeaderKeyId::KeyTransportKey),
            0x03 => Ok(NwkSecurityHeaderKeyId::KeyLoadKey),
            _ => Err("Invalid NWK security header key ID"),
        }
    }
}


#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkSecurityLevel {
    NoSecurity = 0x00,
    AesCbcMac32 = 0x01,
    AesCbcMac64 = 0x02,
    AesCbcMac128 = 0x03,
    AesCtr = 0x04,
    AesCcm32 = 0x05,
    AesCcm64 = 0x06,
    AesCcm128 = 0x07,
}

impl TryFrom<u8> for NwkSecurityLevel {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NwkSecurityLevel::NoSecurity),
            0x01 => Ok(NwkSecurityLevel::AesCbcMac32),
            0x02 => Ok(NwkSecurityLevel::AesCbcMac64),
            0x03 => Ok(NwkSecurityLevel::AesCbcMac128),
            0x04 => Ok(NwkSecurityLevel::AesCtr),
            0x05 => Ok(NwkSecurityLevel::AesCcm32),
            0x06 => Ok(NwkSecurityLevel::AesCcm64),
            0x07 => Ok(NwkSecurityLevel::AesCcm128),
            _ => Err("Invalid NWK security level"),
        }
    }
}


#[derive(Debug, Clone)]
pub struct NwkSecurityHeaderControlField {
    pub security_level: NwkSecurityLevel,
    pub key_id: NwkSecurityHeaderKeyId,
    pub extended_source: bool,
    pub require_verified_frame_counter: bool,
    pub reserved: u8,
}

impl NwkSecurityHeaderControlField {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data to parse NwkSecurityHeaderControlField");
        }

        Ok(
            (Self {
                security_level: NwkSecurityLevel::try_from((bytes[0] >> 0) & 0b111)?,
                key_id: NwkSecurityHeaderKeyId::try_from((bytes[0] >> 3) & 0b11)?,
                extended_source: (bytes[0] >> 5) & 0b1 == 1,
                require_verified_frame_counter: (bytes[0] >> 6) & 0b1 == 1,
                reserved: (bytes[0] >> 7) & 0b1,
            }, &bytes[1..])
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(
            ((self.security_level as u8) & 0b111)
          | (((self.key_id as u8) & 0b11) << 3)
          | ((self.extended_source as u8) << 5)
          | ((self.require_verified_frame_counter as u8) << 6)
          | ((self.reserved & 0b1) << 7)
        );

        bytes
    }
}


#[derive(Debug, Clone)]
pub struct NwkAuxHeader {
    pub security_control: NwkSecurityHeaderControlField,
    pub frame_counter: u32,
    pub extended_source: Option<EUI64>,
    pub key_sequence_number: u8,
}

impl NwkAuxHeader {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 6 {
            return Err("Not enough data to parse NwkAuxHeader");
        }

        let mut remaining = bytes;

        let security_control;
        (security_control, remaining) = NwkSecurityHeaderControlField::deserialize(remaining)?;

        let frame_counter = u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        remaining = &remaining[4..];

        let mut extended_source = None;

        if security_control.extended_source {
            let ieee;
            (ieee, remaining) = EUI64::deserialize(remaining)?;
            extended_source = Some(ieee);
        }

        let key_sequence_number = remaining[0];
        remaining = &remaining[1..];

        Ok(
            (Self {
                security_control,
                frame_counter,
                extended_source,
                key_sequence_number,
            }, remaining)
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.security_control.to_bytes());
        bytes.extend(self.frame_counter.to_le_bytes().to_vec());

        if let Some(ieee) = self.extended_source {
            bytes.extend(ieee.to_bytes());
        }

        bytes.push(self.key_sequence_number);

        bytes
    }
}


#[derive(Debug, Clone)]
pub struct Key(pub [u8; 16]);

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 16 {
            return Err("Invalid key length");
        }

        let mut key = [0; 16];
        key.copy_from_slice(&bytes);

        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}


fn right_pad_to_multiple_of_16(data: &[u8]) -> Vec<u8> {
    // from the left
    let mut padded = Vec::new();
    padded.extend(data);

    let padding = 16 - (data.len() % 16);

    for _ in 0..padding {
        padded.push(0x00);
    }

    padded
}


#[derive(Debug, Clone)]
pub struct NwkFrame {
    pub nwk_header: NwkHeader,
    pub aux_header: Option<NwkAuxHeader>,
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

impl NwkFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut remaining;
        let nwk_header;
        (nwk_header, remaining) = NwkHeader::deserialize(bytes)?;

        let mut aux_header = None;

        if nwk_header.frame_control.security {
            let unwrapped_aux_header;
            (unwrapped_aux_header, remaining) = NwkAuxHeader::deserialize(remaining)?;
            aux_header = Some(unwrapped_aux_header);
        }

        let encrypted = nwk_header.frame_control.security;

        Ok(
            Self {
                nwk_header: nwk_header,
                aux_header: aux_header,
                payload: remaining.to_vec(),
                encrypted: encrypted,
            }
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.nwk_header.to_bytes());

        if let Some(aux_header) = &self.aux_header {
            bytes.extend(aux_header.to_bytes());
        }

        bytes.extend(self.payload.clone());

        bytes
    }

    pub fn get_modified_aux_header(&self, nib_security_level: NwkSecurityLevel) -> NwkAuxHeader {
        if self.aux_header.is_none() {
            panic!("Auxiliary header is missing");
        }

        let mut aux_header = self.aux_header.clone().unwrap();
        aux_header.security_control.security_level = nib_security_level;

        aux_header
    }

    pub fn get_encryption_l_and_m(&self) -> (u8, u8) {
        // TODO: pull this from the security level
        (2, 4)
    }

    pub fn get_nonce(&self, aux_header: &NwkAuxHeader) -> Vec<u8> {
        let source;

        if !aux_header.extended_source.is_none() {
            source = aux_header.extended_source.unwrap();
        } else if !self.nwk_header.source_ieee.is_none() {
            source = self.nwk_header.source_ieee.unwrap();
        } else {
            // XXX: this can't happen
            panic!("Cannot compute nonce with no source address");
        }

        let mut nonce = Vec::new();
        nonce.extend(source.to_bytes());
        nonce.extend(aux_header.frame_counter.to_le_bytes().to_vec());
        nonce.extend(aux_header.security_control.to_bytes());

        nonce
    }

    pub fn compute_mac(&self, l: u8, m: u8, key: &Key, plaintext: &[u8], aux_header: &NwkAuxHeader, nonce: &[u8]) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend(self.nwk_header.to_bytes());
        auth_data.extend(aux_header.to_bytes());

        let encoded_auth_data_len = auth_data.len().to_be_bytes();
        let mut added_auth_data = Vec::new();
        added_auth_data.extend(&encoded_auth_data_len[encoded_auth_data_len.len() - l as usize..]);
        added_auth_data.extend(auth_data.clone());
        added_auth_data = right_pad_to_multiple_of_16(&added_auth_data);

        let mut b0 = Vec::new();
        b0.push(0b0_1_001_001);
        b0.extend(nonce);

        let encoded_plaintext_len = plaintext.len().to_be_bytes();
        b0.extend(&encoded_plaintext_len[encoded_plaintext_len.len() - l as usize..]);

        let mut authed_plaintext = Vec::new();
        authed_plaintext.extend(added_auth_data.clone());
        authed_plaintext.extend(plaintext);
        authed_plaintext = right_pad_to_multiple_of_16(&authed_plaintext);

        let mut ciphertext = Vec::new();
        ciphertext.extend(b0.clone());
        ciphertext.extend(authed_plaintext.clone());

        let mut buffer = ciphertext.clone();
        assert!(buffer.len() % 16 == 0, "Buffer must be padded to a multiple of the block size");

        let mut blocks: Vec<Block> = buffer
            .chunks_exact_mut(16)
            .map(|chunk| {
                let chunk_array: [u8; 16] = chunk.try_into().expect("Chunk size must be 16 bytes");
                Block::from(chunk_array)
            })
            .collect();

        let iv = [0x00; 16];
        let mut encryptor = Encryptor::<Aes128>::new(&(key.0).into(), &iv.into());
        encryptor.encrypt_blocks(&mut blocks);

        let mac_tag = blocks[blocks.len() - 1][..m as usize].to_vec();

        mac_tag
    }

    pub fn encrypt_decrypt(&self, l: u8, m: u8, key: &Key, nonce: &[u8], mac_tag: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = Aes128::new(&(key.0).into());

        let mut tagged_plaintext = Vec::new();
        tagged_plaintext.extend(right_pad_to_multiple_of_16(mac_tag));
        tagged_plaintext.extend(right_pad_to_multiple_of_16(plaintext));

        let mut tagged_ciphertext = Vec::new();
        let mut buffer_block = Block::default();

        // Hazardous: a nonstandard counter scheme is used so we have to manually implement CTR mode
        for block_num in 0..tagged_plaintext.len() / 16 {
            let encoded_block_num = block_num.to_be_bytes();

            let mut counter = Vec::new();
            counter.push(0b0_0_000_001);
            counter.extend(nonce);
            counter.extend(&encoded_block_num[encoded_block_num.len() - l as usize..]);

            let counter_block_array: [u8; 16] = counter.try_into().expect("Counter must be 16 bytes");
            let mut counter_block = Block::from(counter_block_array);
            cipher.encrypt_block_b2b(&mut counter_block, &mut buffer_block);

            let tagged_plaintext_block = tagged_plaintext[16 * block_num..16 * (block_num + 1)].to_vec();

            for i in 0..16 {
                tagged_ciphertext.push(buffer_block[i] ^ tagged_plaintext_block[i]);
            }
        }

        let encrypted_mac_tag = tagged_ciphertext[0..m as usize].to_vec();
        let ciphertext = tagged_ciphertext[16..16 + plaintext.len()].to_vec();

        (encrypted_mac_tag, ciphertext)
    }

    pub fn decrypt(&self, key: &Key) -> Result<Self, &'static str> {
        if !self.encrypted {
            return Err("Cannot decrypt unencrypted frame");
        }

        let (l, m) = self.get_encryption_l_and_m();
        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::AesCcm32);
        let nonce = self.get_nonce(&aux_header);
        let ciphertext = &self.payload[..self.payload.len() - m as usize];
        let encrypted_mac_tag = &self.payload[self.payload.len() - m as usize..];

        let (provided_mac_tag, plaintext) = self.encrypt_decrypt(l, m, key, &nonce, encrypted_mac_tag, ciphertext);
        let mac_tag = self.compute_mac(l, m, key, &plaintext, &aux_header, &nonce);

        if !constant_time_eq(&provided_mac_tag, &mac_tag) {
            return Err("Decryption failed, invalid MAC tag");
        }

        Ok(
            Self {
                nwk_header: self.nwk_header.clone(),
                aux_header: self.aux_header.clone(),
                payload: plaintext,
                encrypted: false,
            }
        )
    }

    pub fn encrypt(&self, key: &Key) -> Result<Self, &'static str> {
        if self.encrypted {
            return Err("Cannot encrypt already encrypted frame");
        }

        let (l, m) = self.get_encryption_l_and_m();
        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::AesCcm32);
        let nonce = self.get_nonce(&aux_header);
        let plaintext = &self.payload;

        let mac_tag = self.compute_mac(l, m, key, &plaintext, &aux_header, &nonce);
        let (encrypted_mac_tag, ciphertext) = self.encrypt_decrypt(l, m, key, &nonce, &mac_tag, &plaintext);

        let mut payload = ciphertext;
        payload.extend(encrypted_mac_tag);

        Ok(
            Self {
                nwk_header: self.nwk_header.clone(),
                aux_header: self.aux_header.clone(),
                payload: payload,
                encrypted: true,
            }
        )
    }
}

use std::env;
use std::fs::File;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use shellexpand;

use ziggurat::ieee_802154::{Ieee802154Frame, Ieee802154FrameType};
use ziggurat::types::Key;
use ziggurat::zigbee_nwk::NwkFrame;

fn main() {
    let keys_path = shellexpand::tilde("~/.config/wireshark/zigbee_pc_keys").into_owned();
    let mut keys = Vec::<Key>::new();

    for line in std::fs::read_to_string(keys_path)
        .expect("Failed to read keys file")
        .lines()
    {
        if !line.starts_with('"') {
            continue;
        }

        let key_text = line
            .split(',')
            .nth(0)
            .expect("Line must have commas")
            .split("\"")
            .nth(1)
            .expect("Failed to parse key");
        let key = Key::from_hex(key_text);
        keys.push(key);
    }

    println!("Loaded {} keys from Wireshark", keys.len());

    let pcap = std::env::args().nth(1).expect("no pcap file given");

    let file = File::open(pcap).expect("failed to open pcap file");

    let mut reader = LegacyPcapReader::new(65536, file).expect("Failed to create reader");

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        println!("Block header: {:?}", hdr);
                    }

                    PcapBlockOwned::Legacy(block) => {
                        let frame = Ieee802154Frame::from_bytes(&block.data)
                            .expect("Failed to parse frame");

                        if frame.frame_control.frame_type == Ieee802154FrameType::Data {
                            let nwk_frame = NwkFrame::from_bytes(&frame.payload)
                                .expect("Failed to parse NWK frame");
                            let mut decrypted = None;

                            for (index, key) in keys.iter().enumerate() {
                                match nwk_frame.decrypt(&key) {
                                    Ok(decrypted_frame) => {
                                        // Swap the first key with this one for efficiency
                                        let temp = keys[0].clone();
                                        keys[0] = keys[index].clone();
                                        keys[index] = temp;

                                        decrypted = Some(decrypted_frame);
                                        break;
                                    }

                                    Err(_) => {
                                        continue;
                                    }
                                }
                            }

                            if decrypted.is_none() {
                                println!("Failed to decrypt frame: {:?}", nwk_frame);
                            } else {
                                println!("Decrypted frame: {:?}", decrypted.unwrap());
                            }
                        }
                    }

                    _ => {
                        panic!("Unexpected block type");
                    }
                }

                reader.consume(offset);
            }

            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }

            Err(PcapError::Eof) => break,

            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
}

#![allow(dead_code)]

use crc_all::CrcAlgo;
use strum_macros::FromRepr;

const CRC_KERMIT: CrcAlgo<u16> = CrcAlgo::<u16>::new(0x1021, 16, 0xFFFF, 0xFFFF, true);

#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
pub enum SpinelCommandId {
    Noop = 0,
    Reset = 1,
    PropValueGet = 2,
    PropValueSet = 3,
    PropValueInsert = 4,
    PropValueRemove = 5,
    PropValueIs = 6,
    PropValueInserted = 7,
    PropValueRemoved = 8,
    Peek = 18,
    PeekRet = 19,
    Poke = 20,
    PropValueMultiGet = 21,
    PropValueMultiSet = 22,
    PropValuesAre = 23,
    NetSave = 9,
    NetClear = 10,
    NetRecall = 11,
    HboOffload = 12,
    HboReclaim = 13,
    HboDrop = 14,
    HboOffloaded = 15,
    HboReclaimed = 16,
    HboDropped = 17,
}

#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
pub enum SpinelPropertyId {
    // Core Properties
    LastStatus = 0,
    ProtocolVersion = 1,
    NcpVersion = 2,
    InterfaceType = 3,
    InterfaceVendorId = 4,
    Caps = 5,
    InterfaceCount = 6,
    PowerState = 7,
    Hwaddr = 8,
    Lock = 9,

    // Host Buffer Offload
    HboMemMax = 10,
    HboBlockMax = 11,

    // Stream Properties
    StreamDebug = 112,
    StreamRaw = 113,
    StreamNet = 114,

    // PHY Properties
    PhyEnabled = 32,
    PhyChan = 33,
    PhyChanSupported = 34,
    PhyFreq = 35,
    PhyCcaThreshold = 36,
    PhyTxPower = 37,
    PhyRssi = 38,
    PhyRxSensitivity = 39,

    // MAC Properties
    // MacScanState = 38,  // collides with PhyRssi
    MacScanMask = 49,
    MacScanPeriod = 50,
    MacScanBeacon = 51,
    Mac154Laddr = 52,
    Mac154Saddr = 53,
    Mac154Panid = 54,
    MacRawStreamEnabled = 55,
    MacPromiscuousMode = 56,
    MacEnergyScanResult = 57,
    MacWhitelist = 4864,
    MacWhitelistEnabled = 4865,

    // NET Properties
    NetSaved = 64,
    NetIfUp = 65,
    NetStackUp = 66,
    NetRole = 67,
    NetNetworkName = 68,
    NetXpanid = 69,
    NetMasterKey = 70,
    NetKeySequenceCounter = 71,
    NetPartitionId = 72,
    NetRequireJoinExisting = 73,
    NetKeySwitchGuardtime = 74,
    NetPskc = 75,

    // IPv6 Properties
    Ipv6LlAddr = 96,
    Ipv6MlAddr = 97,
    Ipv6MlPrefix = 98,
    Ipv6AddressTable = 99,
    Ipv6IcmpPingOffload = 101,

    // Debug Properties
    DebugTestAssert = 16384,
    DebugNcpLogLevel = 16385,

    // Thread Properties
    ThreadLeaderAddr = 80,
    ThreadParent = 81,
    ThreadChildTable = 82,
    ThreadLeaderRid = 83,
    ThreadLeaderWeight = 84,
    ThreadLocalLeaderWeight = 85,
    ThreadNetworkData = 86,
    ThreadNetworkDataVersion = 87,
    ThreadStableNetworkData = 88,
    ThreadStableNetworkDataVersion = 89,
    ThreadOnMeshNets = 90,
    ThreadLocalRoutes = 91,
    ThreadAssistingPorts = 92,
    ThreadAllowLocalNetDataChange = 93,
    ThreadMode = 94,
    ThreadChildTimeout = 5376,
    ThreadRloc16 = 5377,
    ThreadRouterUpgradeThreshold = 5378,
    ThreadContextReuseDelay = 5379,
    ThreadNetworkIdTimeout = 5380,
    ThreadActiveRouterIds = 5381,
    ThreadRloc16DebugPassthru = 5382,
    ThreadRouterRoleEnabled = 5383,
    ThreadRouterDowngradeThreshold = 5384,
    ThreadRouterSelectionJitter = 5385,
    ThreadPreferredRouterId = 5386,
    ThreadNeighborTable = 5387,
    ThreadChildCountMax = 5388,
    ThreadLeaderNetworkData = 5389,
    ThreadStableLeaderNetworkData = 5390,
    ThreadJoiners = 5391,
    ThreadCommissionerEnabled = 5392,
    ThreadBaProxyEnabled = 5393,
    ThreadBaProxyStream = 5394,
    ThreadDisoveryScanJoinerFlag = 5395,
    ThreadDiscoveryScanEnableFiltering = 5396,
    ThreadDiscoveryScanPanid = 5397,
    ThreadSteeringData = 5398,

    // Jam detection
    JamDetectEnable = 4608,
    JamDetected = 4609,
    JamDetectRssiThreshold = 4610,
    JamDetectWindow = 4611,
    JamDetectBusy = 4612,
    JamDetectHistoryBitmap = 4613,

    // GPIO
    GpioConfig = 4096,
    GpioState = 4098,
    GpioStateSet = 4099,
    GpioStateClear = 4100,

    // True random number generation
    Trng32 = 4101,
    Trng128 = 4102,
    TrngRaw32 = 4103,

    NestStreamMfg = 0x3BC0,
}

#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
pub enum SpinelResetReason {
    Platform = 1,
    Stack = 2,
    Bootloader = 3,
}

#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
pub enum SpinelStatus {
    Ok = 0,
    Failure = 1,
    Unimplemented = 2,
    InvalidArgument = 3,
    InvalidState = 4,
    InvalidCommand = 5,
    InvalidInterface = 6,
    InternalError = 7,
    SecurityError = 8,
    ParseError = 9,
    InProgress = 10,
    Nomem = 11,
    Busy = 12,
    PropNotFound = 13,
    Dropped = 14,
    Empty = 15,
    CmdTooBig = 16,
    NoAck = 17,
    CcaFailure = 18,
    Already = 19,
    ItemNotFound = 20,
    InvalidCommandForProp = 21,
    UnknownNeighbor = 22,
    NotCapable = 23,
    ResponseTimeout = 24,
    ResetPowerOn = 112,
    ResetExternal = 113,
    ResetSoftware = 114,
    ResetFault = 115,
    ResetCrash = 116,
    ResetAssert = 117,
    ResetOther = 118,
    ResetUnknown = 119,
    ResetWatchdog = 120,
}

pub fn packed_uint21_deserialize(bytes: &[u8]) -> Result<(u32, &[u8]), &'static str> {
    if bytes.len() < 1 {
        return Err("Not enough data to parse a uint21");
    }

    let mut buffer: [u8; 3] = [0, 0, 0];
    let mut ended_index = usize::MAX;

    for (index, byte) in bytes[0..3].iter().enumerate() {
        buffer[index] = byte & 0b01111111;

        if byte & 0b10000000 == 0 {
            ended_index = index;
            break;
        }
    }

    if ended_index == usize::MAX {
        return Err("Packed uint21 did not terminate");
    }

    let mut result: u32 = 0b00000000_00000000_00000000;

    for chunk in buffer.iter().rev() {
        result = (result << 7) | (*chunk as u32);
    }

    Ok((result, &bytes[ended_index..]))
}

pub fn packed_uint21_to_bytes(value: u32) -> Vec<u8> {
    if value > (2 << 21) {
        panic!("Cannot serialize value, too big");
    }

    let mut chunks = Vec::new();
    let mut temp = value;

    loop {
        // Set the least significant bit on all other octets
        chunks.push(((temp as u8) & 0b01111111) | 0b10000000);
        temp >>= 7;

        if temp == 0 {
            break;
        }
    }

    // Clear the most significant bit of the most significant octet
    let len = chunks.len();
    chunks[len - 1] &= 0b01111111;

    chunks
}

#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
pub enum HdlcSpecial {
    Flag = 0x7E,
    Escape = 0x7D,
    Xon = 0x11,
    Xoff = 0x13,
    Vendor = 0xF8,
}

#[derive(Debug, Clone)]
pub enum HdlcLiteFrameParsingError {
    BadEscapeByte,
    InvalidCrc,
    BadLength,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HdlcLiteFrame {
    pub data: Vec<u8>,
}

impl HdlcLiteFrame {
    fn from_bytes(bytes: &[u8]) -> Result<Self, HdlcLiteFrameParsingError> {
        if bytes.len() < 2 {
            return Err(HdlcLiteFrameParsingError::BadLength);
        }

        let mut data = Vec::new();
        let mut unescaping = false;

        for byte in bytes.iter() {
            let mut result_byte = *byte;

            if unescaping {
                result_byte ^= 0x20;
                unescaping = false;

                if result_byte != (HdlcSpecial::Flag as u8)
                    && result_byte != (HdlcSpecial::Escape as u8)
                    && result_byte != (HdlcSpecial::Xon as u8)
                    && result_byte != (HdlcSpecial::Xoff as u8)
                    && result_byte != (HdlcSpecial::Vendor as u8)
                {
                    return Err(HdlcLiteFrameParsingError::BadEscapeByte);
                }
            } else if result_byte == HdlcSpecial::Escape as u8 {
                unescaping = true;
                continue;
            } else if result_byte == HdlcSpecial::Flag as u8 {
                continue;
            }

            data.push(result_byte);
        }

        if data.len() < 2 {
            return Err(HdlcLiteFrameParsingError::BadLength);
        }

        let mut crc = 0x0000u16;
        CRC_KERMIT.init_crc(&mut crc);
        CRC_KERMIT.update_crc(&mut crc, &data[..data.len() - 2]);
        CRC_KERMIT.finish_crc(&mut crc);

        if crc != u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]) {
            return Err(HdlcLiteFrameParsingError::InvalidCrc);
        }

        Ok(Self {
            data: data[..data.len() - 2].to_vec(),
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut crc = 0x0000u16;
        CRC_KERMIT.init_crc(&mut crc);
        CRC_KERMIT.update_crc(&mut crc, &self.data);
        CRC_KERMIT.finish_crc(&mut crc);

        let mut result = self.data.clone();
        result.extend(&crc.to_le_bytes());
        result
    }
}

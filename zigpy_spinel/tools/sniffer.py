import asyncio
import struct
import sys
import zigpy.types

from ..common import connect_protocol
from ..spinel import SpinelProtocol
from ..spinel_types import CommandID, PropertyID


def ieee_15_4_fcs(data: bytes) -> bytes:
    # Modified from the implementation in `scapy.layers.dot15d4:Dot15d4FCS.compute_fcs`
    crc = 0x0000

    for c in data:
        q = (crc ^ c) & 15  # Do low-order 4 bits
        crc = (crc // 16) ^ (q * 0x1081)

        q = (crc ^ (c // 16)) & 15  # And high 4 bits
        crc = (crc // 16) ^ (q * 0x1081)

    return crc.to_bytes(2, "little")


class PcapWriter:
    """Class responsible to write in pcap format."""

    def __init__(self, fdesc):
        """Initialize pcap file and write global header."""
        self.fdesc = fdesc

    def write_header(self, linktype):
        magic_number = 0xA1B2C3D4
        self.fdesc.write(struct.pack("<L", magic_number))
        self.fdesc.write(struct.pack("<H", 2))
        self.fdesc.write(struct.pack("<H", 4))
        self.fdesc.write(struct.pack("<L", 0))
        self.fdesc.write(struct.pack("<L", 0))
        self.fdesc.write(struct.pack("<L", 65535))
        self.fdesc.write(struct.pack("<L", linktype))
        self.fdesc.flush()

    def write_packet(self, packet_bytes, timestamp):
        """Write a packet with its header."""
        timestamp_sec = int(timestamp.timestamp())
        timestamp_usec = int(timestamp.microsecond)
        self.fdesc.write(struct.pack("<L", timestamp_sec))
        self.fdesc.write(struct.pack("<L", timestamp_usec))
        self.fdesc.write(struct.pack("<L", len(packet_bytes)))
        self.fdesc.write(struct.pack("<L", len(packet_bytes)))
        self.fdesc.write(packet_bytes)
        self.fdesc.flush()


async def main():
    async with connect_protocol(sys.argv[1], 460800, SpinelProtocol) as spinel:
        await spinel.probe()
        await spinel.send_command(CommandID.RESET, b"", wait_response=False)
        await asyncio.sleep(2)

        with open(sys.argv[3], "wb"):
            pcap_writer = PcapWriter(sys.stdout.buffer)
            # pcap_writer = PcapWriter(f)
            pcap_writer.write_header(195)  # LINKTYPE_IEEE802_15_4

            await spinel.set_property(PropertyID.PHY_ENABLED, zigpy.types.uint8_t(1))
            await spinel.set_property(
                PropertyID.MAC_PROMISCUOUS_MODE, zigpy.types.uint8_t(2)
            )
            await spinel.set_property(
                PropertyID.MAC_RAW_STREAM_ENABLED, zigpy.types.Bool.true
            )
            await spinel.set_property(
                PropertyID.PHY_CHAN, zigpy.types.uint8_t(int(sys.argv[2]))
            )

            async for timestamp, frame, metadata in spinel.sniff():
                # Recompute the FCS
                frame = frame[:-2] + ieee_15_4_fcs(frame[:-2])
                pcap_writer.write_packet(frame, timestamp)


if __name__ == "__main__":
    import coloredlogs

    coloredlogs.install()

    asyncio.run(main())

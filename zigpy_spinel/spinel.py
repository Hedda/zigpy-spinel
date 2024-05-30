from __future__ import annotations

import asyncio
import dataclasses
import datetime
import logging
import time
import typing

import async_timeout
import zigpy.types

from .common import SerialProtocol, Version, crc16_kermit
from .spinel_types import CommandID, HDLCSpecial, PropertyID, ResetReason, PackedUInt21

_LOGGER = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class HDLCLiteFrame:
    data: bytes

    def serialize(self) -> bytes:
        payload = self.data + crc16_kermit(self.data).to_bytes(2, "little")
        encoded = bytearray()

        for byte in payload:
            if byte in (
                HDLCSpecial.FLAG,
                HDLCSpecial.ESCAPE,
                HDLCSpecial.XON,
                HDLCSpecial.XOFF,
                HDLCSpecial.VENDOR,
            ):
                encoded.append(HDLCSpecial.ESCAPE)
                byte ^= 0x20

            encoded.append(byte)

        return bytes([HDLCSpecial.FLAG]) + bytes(encoded) + bytes([HDLCSpecial.FLAG])

    @classmethod
    def from_bytes(cls, data: bytes) -> HDLCLiteFrame:
        unescaped = bytearray()
        unescaping = False

        for byte in data:
            if unescaping:
                byte ^= 0x20

                if byte not in (
                    HDLCSpecial.FLAG,
                    HDLCSpecial.ESCAPE,
                    HDLCSpecial.XON,
                    HDLCSpecial.XOFF,
                    HDLCSpecial.VENDOR,
                ):
                    raise ValueError(f"Invalid unescaped byte: 0x{byte:02X}")

                unescaping = False
            elif byte == HDLCSpecial.ESCAPE:
                unescaping = True
                continue
            elif byte == HDLCSpecial.FLAG:
                continue

            unescaped.append(byte)

        data = unescaped[:-2]
        crc = unescaped[-2:]
        computed_crc = crc16_kermit(data).to_bytes(2, "little")

        if computed_crc != crc:
            raise ValueError(f"Invalid CRC-16: expected {crc!r}, got {computed_crc!r}")

        return cls(data=bytes(data))


class SpinelHeader(zigpy.types.Struct):
    # TODO: allow specifying struct endianness
    transaction_id: zigpy.types.uint4_t
    network_link_id: zigpy.types.uint2_t
    flag: zigpy.types.uint2_t


@dataclasses.dataclass(frozen=True)
class SpinelFrame:
    header: SpinelHeader
    command_id: CommandID
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SpinelFrame:
        orig_data = data
        header, data = SpinelHeader.deserialize(data)

        if header.flag != 0b10:
            raise ValueError(f"Spinel header flag is invalid in frame: {orig_data!r}")

        command_id, data = CommandID.deserialize(data)

        return cls(header=header, command_id=command_id, data=data)

    def serialize(self) -> bytes:
        return self.header.serialize() + self.command_id.serialize() + self.data


class SpinelProtocol(SerialProtocol):
    def __init__(self) -> None:
        super().__init__()
        self._transaction_id: int = 1
        self._pending_frames: dict[int, asyncio.Future] = {}
        self._raw_frame_queue = asyncio.Queue()

    def data_received(self, data: bytes) -> None:
        super().data_received(data)

        while self._buffer:
            chunk, flag, self._buffer = self._buffer.partition(
                bytes([HDLCSpecial.FLAG])
            )

            # If the flag isn't found, we're done
            if not flag:
                self._buffer = chunk
                break

            # Sometimes the flag can be repeated multiple times
            if not chunk:
                continue

            # Decode the HDLC frame
            try:
                hdlc_frame = HDLCLiteFrame.from_bytes(chunk)
            except ValueError:
                _LOGGER.debug("Failed to decode HDLC chunk %r", chunk)
                continue

            _LOGGER.debug("Decoded HDLC frame: %r", hdlc_frame)

            # And finally the Spinel frame
            try:
                spinel_frame = SpinelFrame.from_bytes(hdlc_frame.data)
            except ValueError as e:
                _LOGGER.debug("Failed to decode Spinel frame: %r", e)
                continue

            self.frame_received(spinel_frame)

    def frame_received(self, frame: SpinelFrame) -> None:
        _LOGGER.debug("Parsed frame %r", frame)

        if frame.header.transaction_id in self._pending_frames:
            self._pending_frames[frame.header.transaction_id].set_result(frame)
        else:
            if (
                frame.command_id == CommandID.PROP_VALUE_IS
                and frame.data[0] == PropertyID.STREAM_RAW
            ):
                frame_len, data = zigpy.types.uint16_t.deserialize(frame.data[1:])
                frame = data[:frame_len]
                metadata = data[frame_len:]

                _LOGGER.debug("Enqueueing frame...")
                self._raw_frame_queue.put_nowait(
                    (datetime.datetime.now(datetime.timezone.utc), frame, metadata)
                )

    @typing.overload
    async def send_frame(
        self,
        frame: SpinelFrame,
        *,
        wait_response: typing.Literal[True],
        retries: int,
        timeout: float,
        retry_delay: float,
    ) -> None:
        ...

    @typing.overload
    async def send_frame(
        self,
        frame: SpinelFrame,
        *,
        wait_response: typing.Literal[False],
        retries: int,
        timeout: float,
        retry_delay: float,
    ) -> SpinelFrame:
        ...

    async def send_frame(
        self,
        frame: SpinelFrame,
        *,
        wait_response: bool = True,
        retries: int = 3,
        timeout: float = 1,
        retry_delay: float = 0.1,
    ) -> SpinelFrame | None:
        # A transaction ID of `0` is special: we only use 1-15
        self._transaction_id = (self._transaction_id + 1) % (0b1111 - 1)
        tid = 1 + self._transaction_id

        future = asyncio.get_running_loop().create_future()
        self._pending_frames[tid] = future

        # Replace the transaction ID
        new_frame = dataclasses.replace(
            frame, header=frame.header.replace(transaction_id=tid)
        )

        if not wait_response:
            _LOGGER.debug("Sending frame %r", new_frame)
            self.send_data(HDLCLiteFrame(data=new_frame.serialize()).serialize())
            return None

        start = time.time()

        try:
            for attempt in range(retries + 1):
                _LOGGER.debug("Sending frame %r", new_frame)
                self.send_data(HDLCLiteFrame(data=new_frame.serialize()).serialize())

                try:
                    async with async_timeout.timeout(timeout):
                        return await asyncio.shield(future)
                except asyncio.TimeoutError:
                    _LOGGER.debug(
                        "Failed to send %s, trying again in %0.2fs (attempt %s of %s)",
                        frame,
                        retry_delay,
                        attempt + 1,
                        retries + 1,
                    )

                    if attempt >= retries:
                        raise

                    await asyncio.sleep(retry_delay)
        finally:
            self._pending_frames.pop(tid, None)
            delta = time.time() - start
            _LOGGER.debug("Frame %r took %0.2fs", frame, delta)

        raise AssertionError("Unreachable")

    async def send_command(
        self, command_id: CommandID, data: bytes, **kwargs
    ) -> SpinelFrame:
        frame = SpinelFrame(
            header=SpinelHeader(
                flag=0b10,
                network_link_id=0,
                transaction_id=None,
            ),
            command_id=command_id,
            data=data,
        )

        return await self.send_frame(frame, **kwargs)

    async def probe(self) -> Version:
        rsp = await self.send_command(
            CommandID.PROP_VALUE_GET,
            PropertyID.NCP_VERSION.serialize(),
        )

        prop_id, version_string = PropertyID.deserialize(rsp.data)
        assert prop_id == PropertyID.NCP_VERSION

        # SL-OPENTHREAD/2.2.2.0_GitHub-91fa1f455; EFR32; Mar 14 2023 16:03:40
        version = version_string.rstrip(b"\x00").decode("ascii")

        # We strip off the date code to get something reasonably stable
        short_version, _ = version.split(";", 1)

        return Version(short_version)

    async def enter_bootloader(self) -> None:
        await self.send_command(
            CommandID.RESET,
            ResetReason.BOOTLOADER.serialize(),
            wait_response=False,
        )

        # A small delay is necessary when switching baudrates
        await asyncio.sleep(0.5)

    async def sniff(self) -> typing.AsyncGenerator[typing.Tuple[datetime.datetime, bytes, bytes], None]:
        while True:
            timestamp, frame, metadata = await self._raw_frame_queue.get()
            yield timestamp, frame, metadata

    async def set_property(self, property_id: PropertyID, value, *, timeout=1) -> tuple[PropertyID, bytes]:
        orig_value = value

        if not isinstance(value, bytes):
            value = value.serialize()

        rsp = await self.send_command(
            CommandID.PROP_VALUE_SET,
            (property_id.serialize() + value),
            timeout=timeout,
        )

        rsp_prop_id, rest = PackedUInt21.deserialize(rsp.data)
        rsp_prop_id = PropertyID(rsp_prop_id)
        _LOGGER.info("Setting %s=%s, result %s=%r", property_id, orig_value, rsp_prop_id, rest)

        return rsp_prop_id, rest


if __name__ == "__main__":
    import asyncio
    import struct
    import sys

    import coloredlogs

    from .common import connect_protocol

    coloredlogs.install(level="DEBUG")

    def ieee_15_4_fcs(data: bytes) -> bytes:
        # Modified from the implementation in `scapy.layers.dot15d4:Dot15d4FCS.compute_fcs`
        crc = 0x0000

        for c in data:
            q = (crc ^ c) & 15  # Do low-order 4 bits
            crc = (crc // 16) ^ (q * 0x1081)

            q = (crc ^ (c // 16)) & 15  # And high 4 bits
            crc = (crc // 16) ^ (q * 0x1081)

        return crc.to_bytes(2, "little")

    def create_ieee802_15_4_frame(
        seq_num, dest_pan, dest_addr, src_pan, src_addr, payload
    ):
        frame_control = 0x8841  # Data frame, intra-PAN, ACK Request, etc.
        fcf = struct.pack("<H", frame_control)
        seq = struct.pack("<B", seq_num)
        d_pan = struct.pack("<H", dest_pan)
        d_addr = struct.pack("<Q", dest_addr)  # Assuming extended addressing
        struct.pack("<H", src_pan)
        s_addr = struct.pack("<Q", src_addr)  # Assuming extended addressing
        frame_body = fcf + seq + d_pan + d_addr + s_addr + payload
        return frame_body

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
        async with connect_protocol(
            sys.argv[1], 460800, SpinelProtocol
        ) as spinel:
            await spinel.probe()
            await spinel.send_command(CommandID.RESET, b"", wait_response=False)
            await asyncio.sleep(2)

            with open(sys.argv[3], "wb"):
                pcap_writer = PcapWriter(sys.stdout.buffer)
                # pcap_writer = PcapWriter(f)
                pcap_writer.write_header(195)  # LINKTYPE_IEEE802_15_4

                await spinel.set_property(PropertyID.PHY_ENABLED, zigpy.types.uint8_t(1))
                await spinel.set_property(PropertyID.MAC_PROMISCUOUS_MODE, zigpy.types.uint8_t(2))
                await spinel.set_property(PropertyID.MAC_RAW_STREAM_ENABLED, zigpy.types.Bool.true)
                await spinel.set_property(PropertyID.PHY_CHAN, zigpy.types.uint8_t(int(sys.argv[2])))

                async for timestamp, frame, metadata in spinel.sniff():
                    # Recompute the FCS
                    frame = frame[:-2] + ieee_15_4_fcs(frame[:-2])
                    pcap_writer.write_packet(frame, timestamp)

    asyncio.run(main())

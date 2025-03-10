import asyncio
import time
import random
import sys
import zigpy.types
import zigpy.types as t

from ..common import connect_protocol
from ..spinel import SpinelProtocol
from ..spinel_types import PropertyID
from .. import zigbee_types as zigbee


async def main():
    channels = list(map(int, sys.argv[2].split(",")))
    current_channel = random.choice(channels)

    async with connect_protocol(sys.argv[1], 460800, SpinelProtocol) as spinel:
        await spinel.probe()
        await spinel.reset()

        await spinel.set_property(PropertyID.PHY_ENABLED, zigpy.types.uint8_t(1))
        await spinel.set_property(
            PropertyID.MAC_RAW_STREAM_ENABLED, zigpy.types.Bool.true
        )
        await spinel.set_property(
            PropertyID.PHY_CHAN, zigpy.types.uint8_t(current_channel)
        )

        last_time = time.time()
        seq = 0

        while True:
            next_time = time.time()
            print(f"=== Delta: {next_time - last_time:0.8f}")
            last_time = next_time

            seq = (seq + 1) % 0xFF
            frame = zigbee.IEEE802154Frame(
                frame_control=zigbee.IEEE802154FrameControl(
                    frame_type=zigbee.IEEE802154FrameType.Command,
                    security_enabled=False,
                    frame_pending=False,
                    ack_request=False,
                    pan_id_compression=False,
                    reserved=0b0,
                    sequence_number_suppression=False,
                    information_elements_present=False,
                    dest_addr_mode=zigbee.IEEE802154AddressingMode.Short,
                    frame_version=0b00,
                    src_addr_mode=zigbee.IEEE802154AddressingMode.None_,
                ),
                sequence_number=t.uint8_t(seq),
                dest_pan_id=t.uint16_t(0xFFFF),
                dest_address=t.uint16_t(0xFFFF),
                src_pan_id=None,
                src_address=None,
                payload=zigbee.IEEE802154CommandId.BeaconRequest.serialize(),
                fcs=None,
            )

            data = frame.serialize()

            await spinel.set_property(
                PropertyID.STREAM_RAW,
                (
                    t.uint16_t(len(data)).serialize()
                    + data
                    + t.uint8_t(current_channel).serialize()
                    + t.uint8_t(1).serialize()  # CCA backoff attempts
                    + t.uint8_t(4).serialize()  # CCA retries
                    + t.Bool.false.serialize()  # enable CSMA-CA
                    + t.Bool.true.serialize()  # mIsHeaderUpdated
                    + t.Bool.false.serialize()  # mIsARetx
                    + t.Bool.true.serialize()  # mIsSecurityProcessed
                    + t.uint8_t(0).serialize()  # mTxDelay
                    + t.uint8_t(0).serialize()  # mTxDelayBaseTime
                    + t.uint8_t(current_channel).serialize()  # RX channel after TX done
                ),
            )

        await asyncio.sleep(900)


if __name__ == "__main__":
    import logging
    import coloredlogs

    coloredlogs.install(level=logging.DEBUG)

    asyncio.run(main())

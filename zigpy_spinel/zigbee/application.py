import time
import asyncio
import random
import pathlib
import logging

import zigpy.application
import zigpy.backups
import zigpy.endpoint
import zigpy.exceptions
import zigpy.serial
import zigpy.types as t
import zigpy.zdo.types as zdo_t

from .. import zigbee_types as zigbee
from ..spinel import PropertyID, SpinelProtocol
from ..spinel_types import Status

_LOGGER = logging.getLogger(__name__)


class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._spinel = None
        self._rx_task = None

        self._permit_reset_task = None
        self._debug_tx_counter = 0

    async def _watchdog_feed(self):
        await self._spinel.probe()

    async def connect(self):
        loop = asyncio.get_running_loop()
        _, spinel = await zigpy.serial.create_serial_connection(
            loop=loop,
            protocol_factory=SpinelProtocol,
            url=self.config["device"]["path"],
            baudrate=self.config["device"]["baudrate"],
            rtscts=True,
        )
        await spinel.wait_until_connected()
        await spinel.probe()
        await spinel.reset()

        self._spinel = spinel

    async def disconnect(self):
        pathlib.Path("frame_counter.json").write_text(
            str(self.state.network_info.network_key.tx_counter)
        )

        if self._spinel is not None:
            self._spinel.disconnect()

        if self._rx_task is not None:
            self._rx_task.cancel()
            self._rx_task = None

    async def start_network(self):
        _LOGGER.info("Started network!")

        coordinator = self.add_device(
            nwk=self.state.node_info.nwk, ieee=self.state.node_info.ieee
        )
        coordinator.model = "OpenThread RCP"
        coordinator.manufacturer = "Zigpy"
        coordinator.node_desc = zdo_t.NodeDescriptor(
            logical_type=zdo_t.LogicalType.Coordinator,
            complex_descriptor_available=0,
            user_descriptor_available=0,
            reserved=0,
            aps_flags=0,
            frequency_band=zdo_t.NodeDescriptor.FrequencyBand.Freq2400MHz,
            mac_capability_flags=zdo_t.NodeDescriptor.MACCapabilityFlags.AllocateAddress,
            manufacturer_code=4174,
            maximum_buffer_size=82,
            maximum_incoming_transfer_size=82,
            server_mask=0,
            maximum_outgoing_transfer_size=82,
            descriptor_capability_field=zdo_t.NodeDescriptor.DescriptorCapability.NONE,
        )

        await self.register_endpoints()

        await self._spinel.set_property(PropertyID.PHY_ENABLED, t.uint8_t(1))
        await self._spinel.set_property(
            PropertyID.MAC_15_4_LADDR, self.state.node_info.ieee
        )
        await self._spinel.set_property(
            PropertyID.MAC_15_4_SADDR, self.state.node_info.nwk
        )
        await self._spinel.set_property(
            PropertyID.MAC_15_4_PANID, self.state.network_info.pan_id
        )
        # await self._spinel.set_property(PropertyID.MAC_PROMISCUOUS_MODE, t.uint8_t(1))
        await self._spinel.set_property(PropertyID.MAC_RAW_STREAM_ENABLED, t.Bool.true)
        await self._spinel.set_property(
            PropertyID.PHY_CHAN, t.uint8_t(self.state.network_info.channel)
        )

        await asyncio.sleep(1)

        self._spinel.add_property_listener(
            PropertyID.STREAM_RAW, self._spinel_packet_callback
        )

    async def force_remove(self, device):
        pass

    async def add_endpoint(self, descriptor):
        ep = self._device.add_endpoint(descriptor.endpoint)
        ep.profile_id = descriptor.profile
        ep.device_type = descriptor.device_type

        for cluster_id in descriptor.input_clusters:
            ep.add_server_cluster(cluster_id)

        for cluster_id in descriptor.output_clusters:
            ep.add_client_cluster(cluster_id)

    async def send_packet(self, packet):
        _LOGGER.info("Sending packet %s", packet)
        if packet.dst.addr_mode in (t.AddrMode.Broadcast, t.AddrMode.Group):
            ieee_broadcast = True
        else:
            ieee_broadcast = False

        self.state.network_info.network_key.tx_counter += 1

        frame_802154 = zigbee.IEEE802154Frame(
            frame_control=zigbee.IEEE802154FrameControl(
                frame_type=zigbee.IEEE802154FrameType.Data,
                security_enabled=False,
                frame_pending=False,
                ack_request=True,
                pan_id_compression=True,
                reserved=0b0,
                sequence_number_suppression=False,
                information_elements_present=False,
                dest_addr_mode=zigbee.IEEE802154AddressingMode.Short,
                frame_version=0b00,
                src_addr_mode=zigbee.IEEE802154AddressingMode.Short,
            ),
            sequence_number=t.uint8_t(packet.tsn),
            dest_pan_id=self.state.network_info.pan_id,
            dest_address=t.uint16_t(0xFFFF) if ieee_broadcast else packet.dst.address,
            src_pan_id=None,
            src_address=packet.src.address,
            payload=zigbee.DecryptedZigbeeNwkFrame(
                nwk_header=zigbee.ZigbeeNwkHeader(
                    frame_control=zigbee.ZigbeeNwkFrameControl(
                        frame_type=zigbee.ZigbeeNwkFrameType.Data,
                        protocol_version=2,
                        discover_route=zigbee.ZigbeeNwkRouteDiscovery.Suppress,
                        multicast=False,
                        security=True,
                        source_route=False,
                        destination=False,
                        extended_source=False,
                        end_device_initiator=False,
                        reserved=0b00,
                    ),
                    destination=packet.dst.address,
                    source=packet.src.address,
                    radius=t.uint8_t(packet.radius or 30),
                    sequence_number=t.uint8_t(packet.tsn),
                    destination_ieee=None,
                    source_ieee=None,
                    multicast_control=None,
                    source_route_relay_index=None,
                    source_route=None,
                ),
                aux_header=zigbee.ZigbeeNwkAuxHeader(
                    security_control=zigbee.ZigbeeNwkSecurityHeaderControlField(
                        security_level=0,
                        key_id=zigbee.ZigbeeNwkSecurityHeaderKeyId.NetworkKey,
                        extended_nonce=True,
                        reserved=0b00,
                    ),
                    frame_counter=t.uint32_t(
                        self.state.network_info.network_key.tx_counter
                    ),
                    extended_source=self.state.node_info.ieee,
                    key_sequence_number=t.uint8_t(
                        self.state.network_info.network_key.seq
                    ),
                ),
                payload=zigbee.ZigbeeApsFrame(
                    frame_control=zigbee.ZigbeeApsFrameControl(
                        frame_type=zigbee.ZigbeeApsFrameType.Data,
                        delivery_mode=zigbee.ZigbeeApsDeliveryMode.Unicast,
                        reserved=0,
                        security=0,
                        ack_request=t.Bool(t.TransmitOptions.ACK in packet.tx_options),
                        extended_header=0,
                    ),
                    destination_endpoint=t.uint8_t(packet.dst_ep),
                    cluster_id=t.uint16_t(packet.cluster_id),
                    profile_id=t.uint16_t(packet.profile_id),
                    source_endpoint=t.uint8_t(packet.src_ep),
                    counter=t.uint8_t(packet.tsn),
                    asdu=packet.data.serialize(),
                ).serialize(),
            )
            .encrypt(self.state.network_info.network_key.key.serialize())
            .serialize(),
            fcs=None,
        )

        await self._send_spinel_frame(frame_802154)

    async def _send_spinel_frame(self, frame, *, attempts: int = 5):
        for attempt in range(attempts):
            self._debug_tx_counter += 1
            frame_num = self._debug_tx_counter

            if attempt > 0:
                _LOGGER.debug(
                    "Sending frame %d, attempt %d: %s",
                    frame_num,
                    attempt + 1,
                    frame,
                )
            else:
                _LOGGER.debug("Sending frame %d: %s", frame_num, frame)

            data = frame.serialize()

            start_time = time.time()
            rsp_prop_id, rsp_data = await self._spinel.set_property(
                PropertyID.STREAM_RAW,
                (
                    t.uint16_t(len(data)).serialize()
                    + data
                    + t.uint8_t(self.state.network_info.channel).serialize()
                    + t.uint8_t(1).serialize()  # CCA backoff attempts
                    + t.uint8_t(4).serialize()  # CCA retries
                    + t.Bool.true.serialize()  # enable CSMA-CA
                    + t.Bool.true.serialize()  # mIsHeaderUpdated
                    + t.Bool.false.serialize()  # mIsARetx
                    + t.Bool.true.serialize()  # mIsSecurityProcessed
                    + t.uint8_t(0).serialize()  # mTxDelay
                    + t.uint8_t(0).serialize()  # mTxDelayBaseTime
                    + t.uint8_t(
                        self.state.network_info.channel
                    ).serialize()  # RX channel after TX done
                ),
            )
            delta = time.time() - start_time

            assert rsp_prop_id == PropertyID.LAST_STATUS
            status_code = Status(rsp_data[0])
            rest = rsp_data[1:]

            if attempt > 0:
                _LOGGER.debug(
                    "Spinel frame status for frame %d, attempt %d, after %0.4f: %r (%r)",
                    frame_num,
                    attempt + 1,
                    delta,
                    status_code,
                    rest,
                )
            else:
                _LOGGER.debug(
                    "Spinel frame status for frame %d after %0.4f: %r (%r)",
                    frame_num,
                    delta,
                    status_code,
                    rest,
                )

            if status_code == Status.NO_ACK:
                await asyncio.sleep(random.uniform(0, 0.1))
                continue

            return status_code

    async def _spinel_packet_callback(self, _, value: bytes):
        frame_len, data = zigpy.types.uint16_t.deserialize(value)
        frame = data[:frame_len]
        _metadata = data[frame_len:]

        ieee_frame = zigbee.IEEE802154Frame.from_bytes(frame)
        _LOGGER.debug("Parsed frame %s", ieee_frame)

        if ieee_frame.frame_control.frame_type != zigbee.IEEE802154FrameType.Data:
            _LOGGER.debug(
                "Ignoring frame, invalid type: %s",
                ieee_frame.frame_control.frame_type,
            )
            return

        if ieee_frame.dest_pan_id != self.state.network_info.pan_id:
            _LOGGER.debug("Ignoring frame, invalid PAN ID: %s", ieee_frame.dest_pan_id)
            return

        if (
            ieee_frame.frame_control.dest_addr_mode
            == zigbee.IEEE802154AddressingMode.Short
            and ieee_frame.dest_address < 0xFF00
            and ieee_frame.dest_address != self.state.node_info.nwk
        ):
            return

        zigbee_nwk_frame = zigbee.ZigbeeNwkFrame.from_bytes(ieee_frame.payload)

        if isinstance(zigbee_nwk_frame, zigbee.EncryptedZigbeeNwkFrame):
            decrypted_zigbee_nwk_frame = zigbee_nwk_frame.decrypt(
                self.state.network_info.network_key.key.serialize()
            )
        else:
            decrypted_zigbee_nwk_frame = zigbee_nwk_frame

        _LOGGER.debug("Parsed Zigbee %s", decrypted_zigbee_nwk_frame)

        if (
            decrypted_zigbee_nwk_frame.nwk_header.frame_control.frame_type
            == zigbee.ZigbeeNwkFrameType.Command
            and decrypted_zigbee_nwk_frame.payload[0] == 0x01
        ):
            _LOGGER.debug("Received a route request")
            self.state.network_info.network_key.tx_counter += 1
            await self._send_spinel_frame(
                zigbee.IEEE802154Frame(
                    frame_control=zigbee.IEEE802154FrameControl(
                        frame_type=zigbee.IEEE802154FrameType.Data,
                        security_enabled=False,
                        frame_pending=False,
                        ack_request=True,
                        pan_id_compression=True,
                        reserved=0b0,
                        sequence_number_suppression=False,
                        information_elements_present=False,
                        dest_addr_mode=zigbee.IEEE802154AddressingMode.Short,
                        frame_version=0b00,
                        src_addr_mode=zigbee.IEEE802154AddressingMode.Short,
                    ),
                    sequence_number=t.uint8_t(ieee_frame.sequence_number),
                    dest_pan_id=ieee_frame.dest_pan_id,
                    dest_address=ieee_frame.src_address,
                    src_pan_id=None,
                    src_address=ieee_frame.dest_address,
                    payload=(
                        zigbee.DecryptedZigbeeNwkFrame(
                            nwk_header=zigbee.ZigbeeNwkHeader(
                                frame_control=zigbee.ZigbeeNwkFrameControl(
                                    frame_type=zigbee.ZigbeeNwkFrameType.Command,
                                    protocol_version=2,
                                    discover_route=zigbee.ZigbeeNwkRouteDiscovery.Suppress,
                                    multicast=False,
                                    security=True,
                                    source_route=False,
                                    destination=True,
                                    extended_source=True,
                                    end_device_initiator=False,
                                    reserved=0b00,
                                ),
                                destination=zigbee_nwk_frame.nwk_header.source,
                                source=self.state.node_info.nwk,
                                radius=t.uint8_t(30),
                                sequence_number=zigbee_nwk_frame.nwk_header.sequence_number,
                                destination_ieee=zigbee_nwk_frame.nwk_header.source_ieee,
                                source_ieee=self.state.node_info.ieee,
                                multicast_control=None,
                                source_route_relay_index=None,
                                source_route=None,
                            ),
                            aux_header=zigbee.ZigbeeNwkAuxHeader(
                                security_control=zigbee.ZigbeeNwkSecurityHeaderControlField(
                                    security_level=0,
                                    key_id=zigbee.ZigbeeNwkSecurityHeaderKeyId.NetworkKey,
                                    extended_nonce=True,
                                    reserved=0b00,
                                ),
                                frame_counter=t.uint32_t(
                                    self.state.network_info.network_key.tx_counter
                                ),
                                extended_source=self.state.node_info.ieee,
                                key_sequence_number=t.uint8_t(
                                    self.state.network_info.network_key.seq
                                ),
                            ),
                            payload=(
                                bytes([0x02, 0x00, 0x12])
                                + self.state.node_info.nwk.serialize()
                                + self.state.node_info.nwk.serialize()
                                + t.uint8_t(1).serialize()
                            ),
                        )
                        .encrypt(self.state.network_info.network_key.key.serialize())
                        .serialize()
                    ),
                    fcs=None,
                )
            )

            return

        if (
            decrypted_zigbee_nwk_frame.nwk_header.frame_control.frame_type
            != zigbee.ZigbeeNwkFrameType.Data
        ):
            return

        zigbee_aps_frame = zigbee.ZigbeeApsFrame.from_bytes(
            decrypted_zigbee_nwk_frame.payload
        )

        if zigbee_aps_frame.frame_control.frame_type != zigbee.ZigbeeApsFrameType.Data:
            return

        if zigbee_aps_frame.frame_control.ack_request:
            _LOGGER.debug("Sending an APS ACK")
            self.state.network_info.network_key.tx_counter += 1
            await self._send_spinel_frame(
                zigbee.IEEE802154Frame(
                    frame_control=zigbee.IEEE802154FrameControl(
                        frame_type=zigbee.IEEE802154FrameType.Data,
                        security_enabled=False,
                        frame_pending=False,
                        ack_request=True,
                        pan_id_compression=True,
                        reserved=0b0,
                        sequence_number_suppression=False,
                        information_elements_present=False,
                        dest_addr_mode=zigbee.IEEE802154AddressingMode.Short,
                        frame_version=0b00,
                        src_addr_mode=zigbee.IEEE802154AddressingMode.Short,
                    ),
                    sequence_number=t.uint8_t(ieee_frame.sequence_number),
                    dest_pan_id=ieee_frame.dest_pan_id,
                    dest_address=ieee_frame.src_address,
                    src_pan_id=None,
                    src_address=ieee_frame.dest_address,
                    payload=(
                        zigbee.DecryptedZigbeeNwkFrame(
                            nwk_header=zigbee.ZigbeeNwkHeader(
                                frame_control=zigbee.ZigbeeNwkFrameControl(
                                    frame_type=zigbee.ZigbeeNwkFrameType.Data,
                                    protocol_version=2,
                                    discover_route=zigbee.ZigbeeNwkRouteDiscovery.Suppress,
                                    multicast=False,
                                    security=True,
                                    source_route=False,
                                    destination=False,
                                    extended_source=False,
                                    end_device_initiator=False,
                                    reserved=0b00,
                                ),
                                destination=zigbee_nwk_frame.nwk_header.source,
                                source=zigbee_nwk_frame.nwk_header.destination,
                                radius=t.uint8_t(
                                    zigbee_nwk_frame.nwk_header.radius - 1
                                ),
                                sequence_number=zigbee_nwk_frame.nwk_header.sequence_number,
                                destination_ieee=None,
                                source_ieee=None,
                                multicast_control=None,
                                source_route_relay_index=None,
                                source_route=None,
                            ),
                            aux_header=zigbee.ZigbeeNwkAuxHeader(
                                security_control=zigbee.ZigbeeNwkSecurityHeaderControlField(
                                    security_level=0,
                                    key_id=zigbee.ZigbeeNwkSecurityHeaderKeyId.NetworkKey,
                                    extended_nonce=True,
                                    reserved=0b00,
                                ),
                                frame_counter=t.uint32_t(
                                    self.state.network_info.network_key.tx_counter
                                ),
                                extended_source=self.state.node_info.ieee,
                                key_sequence_number=t.uint8_t(
                                    self.state.network_info.network_key.seq
                                ),
                            ),
                            payload=zigbee.ZigbeeApsFrame(
                                frame_control=zigbee.ZigbeeApsFrameControl(
                                    frame_type=zigbee.ZigbeeApsFrameType.Ack,
                                    delivery_mode=zigbee.ZigbeeApsDeliveryMode.Unicast,
                                    reserved=0,
                                    security=0,
                                    ack_request=0,
                                    extended_header=0,
                                ),
                                destination_endpoint=zigbee_aps_frame.source_endpoint,
                                cluster_id=zigbee_aps_frame.cluster_id,
                                profile_id=zigbee_aps_frame.profile_id,
                                source_endpoint=zigbee_aps_frame.destination_endpoint,
                                counter=zigbee_aps_frame.counter,
                                asdu=b"",
                            ).serialize(),
                        )
                        .encrypt(self.state.network_info.network_key.key.serialize())
                        .serialize()
                    ),
                    fcs=None,
                ),
                attempts=1,
            )

        packet = t.ZigbeePacket(
            src=t.AddrModeAddress(
                addr_mode=t.AddrMode.NWK,
                address=decrypted_zigbee_nwk_frame.nwk_header.source,
            ),
            src_ep=zigbee_aps_frame.source_endpoint,
            dst=t.AddrModeAddress(
                addr_mode=t.AddrMode.NWK,
                address=decrypted_zigbee_nwk_frame.nwk_header.destination,
            ),
            dst_ep=zigbee_aps_frame.destination_endpoint,
            tsn=zigbee_aps_frame.counter,
            profile_id=zigbee_aps_frame.profile_id,
            cluster_id=zigbee_aps_frame.cluster_id,
            data=t.SerializableBytes(zigbee_aps_frame.asdu),
            tx_options=t.TransmitOptions.NONE,
            radius=decrypted_zigbee_nwk_frame.nwk_header.radius,
            lqi=0,
            rssi=0,
        )
        _LOGGER.info("Received a packet %s", packet)

        self.packet_received(packet)

    async def permit_ncp(self, time_s: int = 60) -> None:
        if time_s == 0:
            self._reset_permit_ncp()
            return

        if self._permit_reset_task is not None:
            self._permit_reset_task.cancel()
            self._permit_reset_task = None

        self._permitting_joins = True
        self._permit_reset_task = asyncio.get_running_loop().call_later(
            time_s, self._reset_permit_ncp
        )

    def _reset_permit_ncp(self):
        self._permitting_joins = False
        self._permit_reset_task = None

    async def permit_with_link_key(
        self, node: t.EUI64, link_key: t.KeyData, time_s: int = 60
    ) -> None:
        """Permit a node to join with the provided link key."""

    async def write_network_info(
        self,
        *,
        network_info: zigpy.state.NetworkInfo,
        node_info: zigpy.state.NodeInfo,
    ) -> None:
        # :)
        self.state.network_info = network_info
        self.state.node_info = node_info

    async def load_network_info(self, *, load_devices: bool = False) -> None:
        frame_counter = int(pathlib.Path("frame_counter.json").read_text())

        backup = zigpy.backups.NetworkBackup.from_dict(
            {
                "version": 1,
                "backup_time": "2024-05-10T18:40:59.996177+00:00",
                "network_info": {
                    "extended_pan_id": "94:06:26:02:d2:5a:4b:d0",
                    "pan_id": "9F0D",
                    "nwk_update_id": 0,
                    "nwk_manager_id": "0000",
                    "channel": 20,
                    "channel_mask": [
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                        17,
                        18,
                        19,
                        20,
                        21,
                        22,
                        23,
                        24,
                        25,
                        26,
                    ],
                    "security_level": 5,
                    "network_key": {
                        "key": "3e:38:3b:ad:1c:31:d7:21:3b:9c:b3:3f:92:f3:76:93",
                        "tx_counter": frame_counter + 1000,
                        "rx_counter": 0,
                        "seq": 0,
                        "partner_ieee": "00:12:4b:00:1c:a1:b8:46",
                    },
                    "tc_link_key": {
                        "key": "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39",
                        "tx_counter": 0,
                        "rx_counter": 0,
                        "seq": 0,
                        "partner_ieee": "00:12:4b:00:1c:a1:b8:46",
                    },
                    "key_table": [],
                    "children": [],
                    "nwk_addresses": {},
                    "stack_specific": {},
                    "metadata": {},
                    "source": None,
                },
                "node_info": {
                    "nwk": "0000",
                    "ieee": "00:12:4b:00:1c:a1:b8:46",
                    "logical_type": "coordinator",
                    "model": "nRF52840",
                    "manufacturer": "Nordic Semiconductor",
                    "version": "0.0.0.1 (stack 3.11.3.0)",
                },
            }
        )

        self.state.network_info = backup.network_info
        self.state.node_info = backup.node_info

    async def reset_network_info(self) -> None:
        pass

    def _persist_coordinator_model_strings_in_db(self):
        pass

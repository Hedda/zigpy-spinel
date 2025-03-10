from __future__ import annotations

import dataclasses
import pathlib
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import zigpy.types as t


class DecryptionFailure(BaseException):
    pass


class ParsingError(BaseException):
    pass


class IEEE802154FrameType(t.enum3):
    Beacon = 0b000
    Data = 0b001
    Command = 0b011
    Ack = 0b010


class IEEE802154AddressingMode(t.enum2):
    None_ = 0b00
    Short = 0b10
    Long = 0b11


class IEEE802154FrameControl(t.Struct):
    frame_type: IEEE802154FrameType
    security_enabled: t.uint1_t
    frame_pending: t.uint1_t
    ack_request: t.uint1_t
    pan_id_compression: t.uint1_t
    reserved: t.uint1_t
    sequence_number_suppression: t.uint1_t
    information_elements_present: t.uint1_t
    dest_addr_mode: IEEE802154AddressingMode
    frame_version: t.uint2_t
    src_addr_mode: IEEE802154AddressingMode


class IEEE802154CommandId(t.enum8):
    NotAMacCommand = 0x00
    AssociationRequest = 0x01
    AssociationResponse = 0x02
    DisassociationNotification = 0x03
    DataRequest = 0x04
    PanIdConflictNotification = 0x05
    OrphanNotification = 0x06
    BeaconRequest = 0x07
    CoordinatorRealignment = 0x08
    GtsRequest = 0x09


class IEEE802154BeaconSuperframeSpec(t.Struct):
    beacon_interval: t.uint4_t
    superframe_interval: t.uint4_t
    final_cap_slot: t.uint4_t
    battery_extension: t.uint1_t
    pan_coordinator: t.uint1_t
    association_permit: t.uint1_t


class IEEE802154BeaconGts(t.Struct):
    gts_descriptor_count: t.uint8_t
    gts_permit: t.uint8_t

    beacon_interval: t.uint4_t
    superframe_interval: t.uint4_t
    final_cap_slot: t.uint4_t
    battery_extension: t.uint1_t
    pan_coordinator: t.uint1_t
    association_permit: t.uint1_t


@dataclasses.dataclass(frozen=True, kw_only=True)
class IEEE802154Frame:
    frame_control: IEEE802154FrameControl
    sequence_number: t.uint8_t | None
    dest_pan_id: t.NWK | None
    dest_address: t.NWK | t.EUI64 | None
    src_pan_id: t.NWK | None
    src_address: t.NWK | t.EUI64 | None
    payload: bytes
    fcs: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        fcs = data[-2:]

        # if cls._compute_fcs(data[:-2]) != fcs:
        #    raise ParsingError("Invalid FCS")

        frame_control, data = IEEE802154FrameControl.deserialize(data)

        if frame_control.sequence_number_suppression:
            sequence_number = None
        else:
            sequence_number, data = t.uint8_t.deserialize(data)

        if frame_control.dest_addr_mode == IEEE802154AddressingMode.Short:
            dest_pan_id, data = t.uint16_t.deserialize(data)
            dest_address, data = t.NWK.deserialize(data)
        elif frame_control.dest_addr_mode == IEEE802154AddressingMode.Long:
            dest_pan_id, data = t.uint16_t.deserialize(data)
            dest_address, data = t.EUI64.deserialize(data)
        else:
            dest_pan_id = None
            dest_address = None

        if frame_control.pan_id_compression:
            src_pan_id = dest_pan_id
        elif frame_control.frame_type in (
            IEEE802154FrameType.Data,
            IEEE802154FrameType.Command,
        ):
            src_pan_id, data = t.uint16_t.deserialize(data)
        else:
            src_pan_id = None

        if frame_control.src_addr_mode == IEEE802154AddressingMode.Short:
            src_address, data = t.NWK.deserialize(data)
        elif frame_control.src_addr_mode == IEEE802154AddressingMode.Long:
            src_address, data = t.EUI64.deserialize(data)
        else:
            src_address = None

        payload = data[:-2]

        return cls(
            frame_control=frame_control,
            sequence_number=sequence_number,
            dest_pan_id=dest_pan_id,
            dest_address=dest_address,
            src_pan_id=src_pan_id,
            src_address=src_address,
            payload=payload,
            fcs=fcs,
        )

    def serialize(self) -> bytes:
        data = self.frame_control.serialize()

        if not self.frame_control.sequence_number_suppression:
            data += self.sequence_number.serialize()

        if self.frame_control.dest_addr_mode == IEEE802154AddressingMode.Short:
            data += self.dest_pan_id.serialize()
            data += self.dest_address.serialize()
        elif self.frame_control.dest_addr_mode == IEEE802154AddressingMode.Long:
            data += self.dest_pan_id.serialize()
            data += self.dest_address.serialize()

        if (
            not self.frame_control.pan_id_compression
            and self.frame_control.frame_type
            in (
                IEEE802154FrameType.Data,
                IEEE802154FrameType.Command,
            )
        ):
            if not (
                self.frame_control.frame_type == IEEE802154FrameType.Command
                and self.payload == b"\x07"
            ):
                data += self.src_pan_id.serialize()

        if self.frame_control.src_addr_mode == IEEE802154AddressingMode.Short:
            data += self.src_address.serialize()
        elif self.frame_control.src_addr_mode == IEEE802154AddressingMode.Long:
            data += self.src_address.serialize()

        data += self.payload

        return data + self._compute_fcs(data)

    @staticmethod
    def _compute_fcs(data: bytes) -> bytes:
        crc = 0x0000

        for c in data:
            q = (crc ^ c) & 15  # Do low-order 4 bits
            crc = (crc // 16) ^ (q * 0x1081)

            q = (crc ^ (c // 16)) & 15  # And high 4 bits
            crc = (crc // 16) ^ (q * 0x1081)

        return crc.to_bytes(2, "little")


class ZigbeeNwkFrameType(t.enum2):
    Data = 0b00
    Command = 0b01


class ZigbeeNwkRouteDiscovery(t.enum2):
    Suppress = 0b00
    Enable = 0b01
    WithMulticast = 0b10


class ZigbeeNwkFrameControl(t.Struct):
    frame_type: ZigbeeNwkFrameType
    protocol_version: t.uint4_t
    discover_route: ZigbeeNwkRouteDiscovery
    multicast: t.uint1_t
    security: t.uint1_t
    source_route: t.uint1_t
    destination: t.uint1_t
    extended_source: t.uint1_t
    end_device_initiator: t.uint1_t
    reserved: t.uint2_t


@dataclasses.dataclass(frozen=True, kw_only=True)
class ZigbeeNwkHeader:
    frame_control: ZigbeeNwkFrameControl
    destination: t.NWK
    source: t.NWK
    radius: t.uint8_t
    sequence_number: t.uint8_t
    destination_ieee: t.EUI64 | None = None
    source_ieee: t.EUI64 | None = None
    multicast_control: t.uint8_t | None = None
    source_route_relay_index: t.uint8_t = None
    source_route: list[t.NWK] | None = None

    @classmethod
    def deserialize(cls, data: bytes):
        frame_control, data = ZigbeeNwkFrameControl.deserialize(data)
        destination, data = t.NWK.deserialize(data)
        source, data = t.NWK.deserialize(data)
        radius, data = t.uint8_t.deserialize(data)
        sequence_number, data = t.uint8_t.deserialize(data)

        destination_ieee = None
        source_ieee = None
        multicast_control = None
        source_route_relay_index = None
        source_route = None

        if frame_control.destination:
            destination_ieee, data = t.EUI64.deserialize(data)

        if frame_control.extended_source:
            source_ieee, data = t.EUI64.deserialize(data)

        if frame_control.multicast:
            multicast_control, data = t.uint8_t.deserialize(data)

        if frame_control.source_route:
            relay_count, data = t.uint8_t.deserialize(data)
            source_route_relay_index, data = t.uint8_t.deserialize(data)
            source_route = []

            for i in range(relay_count):
                nwk, data = t.NWK.deserialize(data)
                source_route.append(nwk)

        return (
            cls(
                frame_control=frame_control,
                destination=destination,
                source=source,
                radius=radius,
                sequence_number=sequence_number,
                destination_ieee=destination_ieee,
                source_ieee=source_ieee,
                multicast_control=multicast_control,
                source_route_relay_index=source_route_relay_index,
                source_route=source_route,
            ),
            data,
        )

    def serialize(self) -> bytes:
        data = (
            self.frame_control.serialize()
            + self.destination.serialize()
            + self.source.serialize()
            + self.radius.serialize()
            + self.sequence_number.serialize()
        )

        if self.destination_ieee is not None:
            data += self.destination_ieee.serialize()

        if self.source_ieee is not None:
            data += self.source_ieee.serialize()

        if self.multicast_control is not None:
            data += self.multicast_control.serialize()

        if self.source_route is not None:
            data += t.uint8_t(len(self.source_route)).serialize()
            data += t.uint8_t(self.source_route_relay_index).serialize()

            for nwk in self.source_route:
                data += nwk.serialize()

        return data


class ZigbeeNwkSecurityHeaderKeyId(t.enum2):
    DataKey = 0x00
    NetworkKey = 0x01
    KeyTransportKey = 0x02
    KeyLoadKey = 0x03


class ZigbeeNwkSecurityLevel(t.enum3):
    NO_SECURITY = 0x00
    AES_CBC_MAC_32 = 0x01
    AES_CBC_MAC_64 = 0x02
    AES_CBC_MAC_128 = 0x03
    AES_CTR = 0x04
    AES_CCM_32 = 0x05
    AES_CCM_64 = 0x06
    AES_CCM_128 = 0x07


class ZigbeeNwkSecurityHeaderControlField(t.Struct):
    security_level: ZigbeeNwkSecurityLevel
    key_id: ZigbeeNwkSecurityHeaderKeyId
    extended_nonce: t.uint1_t
    reserved: t.uint2_t


@dataclasses.dataclass(frozen=True, kw_only=True)
class ZigbeeNwkAuxHeader:
    security_control: ZigbeeNwkSecurityHeaderControlField
    frame_counter: t.uint32_t
    extended_source: t.EUI64 | None
    key_sequence_number: t.uint8_t

    @classmethod
    def deserialize(cls, data: bytes):
        security_control, data = ZigbeeNwkSecurityHeaderControlField.deserialize(data)
        frame_counter, data = t.uint32_t.deserialize(data)

        if security_control.extended_nonce:
            extended_source, data = t.EUI64.deserialize(data)
        else:
            extended_source = None

        key_sequence_number, data = t.uint8_t.deserialize(data)

        return (
            cls(
                security_control=security_control,
                frame_counter=frame_counter,
                extended_source=extended_source,
                key_sequence_number=key_sequence_number,
            ),
            data,
        )

    def get_nonce(self) -> bytes:
        return (
            self.extended_source.serialize()
            + self.frame_counter.serialize()
            + self.security_control.serialize()
        )

    def serialize(self) -> bytes:
        return (
            self.security_control.serialize()
            + self.frame_counter.serialize()
            + self.extended_source.serialize()
            + self.key_sequence_number.serialize()
        )


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b, strict=True)])


def pad_to_multiple_of_16(data: bytes) -> bytes:
    if len(data) % 16 != 0:
        data += b"\x00" * (16 - (len(data) % 16))

    return data


@dataclasses.dataclass(frozen=True, kw_only=True)
class ZigbeeNwkFrame:
    nwk_header: ZigbeeNwkHeader
    aux_header: ZigbeeNwkAuxHeader | None
    payload: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        nwk_header, data = ZigbeeNwkHeader.deserialize(data)
        aux_header = None

        if nwk_header.frame_control.security:
            aux_header, data = ZigbeeNwkAuxHeader.deserialize(data)

        return EncryptedZigbeeNwkFrame(
            nwk_header=nwk_header,
            aux_header=aux_header,
            payload=data,
        )

    def serialize(self) -> bytes:
        data = self.nwk_header.serialize()

        if self.aux_header is not None:
            data += self.aux_header.serialize()

        data += self.payload

        return data

    def get_modified_aux_header(
        self, security_level=ZigbeeNwkSecurityLevel.AES_CCM_32
    ) -> ZigbeeNwkAuxHeader:
        assert self.aux_header is not None
        if self.aux_header.security_control.security_level == security_level:
            return self.aux_header

        # XXX: overwrite the security level with the value contained in the NIB!!!
        security_control = self.aux_header.security_control.replace(
            security_level=security_level
        )
        return dataclasses.replace(self.aux_header, security_control=security_control)

    def _get_encryption_l_m(self) -> tuple[int, int]:
        if self.aux_header is None:
            raise ValueError("No security header present, cannot decrypt payload.")

        # TODO: pull this from the security level
        return (2, 4)

    def _get_nonce(self, aux_header: ZigbeeNwkAuxHeader) -> bytes:
        # XXX: AUX header's source takes priority over the NWK source!
        source = aux_header.extended_source or self.nwk_header.source_ieee
        return (
            source.serialize()
            + aux_header.frame_counter.serialize()
            + aux_header.security_control.serialize()
        )

    def _compute_mac(
        self,
        L: int,
        M: int,
        key: bytes,
        plaintext: bytes,
        aux_header: ZigbeeNwkAuxHeader,
        nonce: bytes,
    ) -> bytes:
        auth_data = self.nwk_header.serialize() + aux_header.serialize()
        added_auth_data = pad_to_multiple_of_16(
            len(auth_data).to_bytes(L, "big") + auth_data
        )

        cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
        encryptor = cipher.encryptor()

        B0 = bytes([0b0_1_001_001]) + nonce + len(plaintext).to_bytes(L, "big")
        X = encryptor.update(B0 + pad_to_multiple_of_16(added_auth_data + plaintext))
        encryptor.finalize()

        mac_tag = X[-16 : -16 + M]

        return mac_tag

    def _encrypt(
        self,
        L: int,
        M: int,
        key: bytes,
        nonce: bytes,
        mac_tag: bytes,
        plaintext: bytes,
    ) -> tuple[bytes, bytes]:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()

        # A nonstandard counter scheme is used so we have to manually implement CTR mode
        tagged_plaintext = pad_to_multiple_of_16(mac_tag) + pad_to_multiple_of_16(
            plaintext
        )
        tagged_ciphertext = b""

        for block_num in range(len(tagged_plaintext) // 16):
            counter = bytes([0b0_0_000_001]) + nonce + block_num.to_bytes(L, "big")
            tagged_plaintext_block = tagged_plaintext[
                16 * block_num : 16 * (block_num + 1)
            ]
            tagged_ciphertext += xor(encryptor.update(counter), tagged_plaintext_block)

        encryptor.finalize()
        encrypted_mac_tag = tagged_ciphertext[:M]
        ciphertext = tagged_ciphertext[16 : 16 + len(plaintext)]

        return encrypted_mac_tag, ciphertext


@dataclasses.dataclass(frozen=True, kw_only=True)
class EncryptedZigbeeNwkFrame(ZigbeeNwkFrame):
    def decrypt(self, key: bytes) -> DecryptedZigbeeNwkFrame:
        L, M = self._get_encryption_l_m()
        aux_header = self.get_modified_aux_header()
        nonce = self._get_nonce(aux_header)
        ciphertext = self.payload[:-M]
        encrypted_mac_tag = self.payload[-M:]

        provided_mac_tag, plaintext = self._encrypt(
            L=L,
            M=M,
            key=key,
            nonce=nonce,
            mac_tag=encrypted_mac_tag,
            plaintext=ciphertext,
        )
        mac_tag = self._compute_mac(
            L=L,
            M=M,
            key=key,
            plaintext=plaintext,
            aux_header=aux_header,
            nonce=nonce,
        )

        # Just for the sake of it, let's use a constant time compare
        if not secrets.compare_digest(provided_mac_tag, mac_tag):
            raise DecryptionFailure("Invalid MAC tag")

        return DecryptedZigbeeNwkFrame(
            nwk_header=self.nwk_header,
            aux_header=self.aux_header,
            payload=plaintext,
        )


@dataclasses.dataclass(frozen=True, kw_only=True)
class DecryptedZigbeeNwkFrame(ZigbeeNwkFrame):
    def encrypt(self, key: bytes) -> EncryptedZigbeeNwkFrame:
        L, M = self._get_encryption_l_m()
        aux_header = self.get_modified_aux_header()
        nonce = self._get_nonce(aux_header)
        plaintext = self.payload

        mac_tag = self._compute_mac(
            L=L,
            M=M,
            key=key,
            plaintext=plaintext,
            aux_header=aux_header,
            nonce=nonce,
        )
        encrypted_mac_tag, ciphertext = self._encrypt(
            L=L,
            M=M,
            key=key,
            nonce=nonce,
            mac_tag=mac_tag,
            plaintext=plaintext,
        )

        return EncryptedZigbeeNwkFrame(
            nwk_header=self.nwk_header,
            aux_header=self.aux_header,
            payload=ciphertext + encrypted_mac_tag,
        )


class ZigbeeApsFrameType(t.enum2):
    Data = 0b00
    Ack = 0b10


class ZigbeeApsDeliveryMode(t.enum2):
    Unicast = 0b00
    Broadcast = 0b10


class ZigbeeApsFrameControl(t.Struct):
    frame_type: ZigbeeApsFrameType
    delivery_mode: ZigbeeApsDeliveryMode
    reserved: t.uint1_t
    security: t.uint1_t
    ack_request: t.uint1_t
    extended_header: t.uint1_t


@dataclasses.dataclass(frozen=True, kw_only=True)
class ZigbeeApsFrame:
    frame_control: ZigbeeApsFrameControl
    destination_endpoint: t.uint8_t
    cluster_id: t.uint16_t
    profile_id: t.uint16_t
    source_endpoint: t.uint8_t
    counter: t.uint8_t
    asdu: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        frame_control, data = ZigbeeApsFrameControl.deserialize(data)
        destination_endpoint, data = t.uint8_t.deserialize(data)
        cluster_id, data = t.uint16_t.deserialize(data)
        profile_id, data = t.uint16_t.deserialize(data)
        source_endpoint, data = t.uint8_t.deserialize(data)
        counter, data = t.uint8_t.deserialize(data)
        asdu = data

        return cls(
            frame_control=frame_control,
            destination_endpoint=destination_endpoint,
            cluster_id=cluster_id,
            profile_id=profile_id,
            source_endpoint=source_endpoint,
            counter=counter,
            asdu=asdu,
        )

    def serialize(self) -> bytes:
        data = self.frame_control.serialize()
        data += self.destination_endpoint.serialize()
        data += self.cluster_id.serialize()
        data += self.profile_id.serialize()
        data += self.source_endpoint.serialize()
        data += self.counter.serialize()
        data += self.asdu

        return data


if __name__ == "__main__":
    import ast
    import sys

    from dpkt.pcap import UniversalReader

    network_keys = {}

    for line in (
        pathlib.Path("~/.config/wireshark/zigbee_pc_keys")
        .expanduser()
        .read_text()
        .splitlines()
    ):
        if line.startswith('"'):
            key_hex, _, name = ast.literal_eval("(" + line + ")")
            network_keys[name] = bytes.fromhex(key_hex.replace(":", ""))

    for filename in sys.argv[1:]:
        print("Parsing", filename)

        with open(filename, "rb") as f:
            for index, (timestamp, packet) in enumerate(UniversalReader(f)):
                ieee_frame = IEEE802154Frame.from_bytes(packet)
                assert ieee_frame.serialize() == packet

                if ieee_frame.frame_control.frame_type != IEEE802154FrameType.Data:
                    continue

                zigbee_nwk_frame = ZigbeeNwkFrame.from_bytes(ieee_frame.payload)

                if isinstance(zigbee_nwk_frame, EncryptedZigbeeNwkFrame):
                    try:
                        for key_index, (name, key) in enumerate(network_keys.items()):
                            try:
                                decrypted_zigbee_nwk_frame = zigbee_nwk_frame.decrypt(
                                    key
                                )
                                break
                            except DecryptionFailure:
                                if key_index == len(network_keys) - 1:
                                    raise
                    except DecryptionFailure:
                        continue

                    # Bump the most-recent key to the top
                    network_keys = {name: key, **network_keys}

                    assert (
                        decrypted_zigbee_nwk_frame.encrypt(key).payload
                        == zigbee_nwk_frame.payload
                    )
                else:
                    decrypted_zigbee_nwk_frame = zigbee_nwk_frame

                if (
                    decrypted_zigbee_nwk_frame.nwk_header.frame_control.frame_type
                    != ZigbeeNwkFrameType.Data
                ):
                    continue

                print("Parsing frame", index + 1, decrypted_zigbee_nwk_frame)

                zigbee_aps_frame = ZigbeeApsFrame.from_bytes(
                    decrypted_zigbee_nwk_frame.payload
                )

                print("\t", zigbee_aps_frame)
                print()

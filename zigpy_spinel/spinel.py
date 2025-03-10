from __future__ import annotations

import asyncio
import dataclasses
import logging
import typing
from collections import defaultdict

import async_timeout

from .common import SerialProtocol, Version
from .spinel_types import (
    CommandID,
    HDLCSpecial,
    PropertyID,
    ResetReason,
    PackedUInt21,
    HDLCLiteFrame,
    SpinelHeader,
    SpinelFrame,
    Status,
)

_LOGGER = logging.getLogger(__name__)


class SpinelProtocol(SerialProtocol):
    def __init__(self) -> None:
        super().__init__()
        self._transaction_id: int = 1
        self._pending_frames: dict[int, asyncio.Future] = {}
        self._property_listeners: defaultdict[PropertyID, list[typing.callable]] = (
            defaultdict(list)
        )

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

        if frame.command_id == CommandID.PROP_VALUE_IS:
            prop_id, data = PackedUInt21.deserialize(frame.data)
            prop_id = PropertyID(prop_id)

            for listener in self._property_listeners[prop_id]:
                try:
                    listener(data)
                except Exception:
                    _LOGGER.warning(
                        "Error calling property listener for %r: %r",
                        prop_id,
                        listener,
                        exc_info=True,
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
    ) -> None: ...

    @typing.overload
    async def send_frame(
        self,
        frame: SpinelFrame,
        *,
        wait_response: typing.Literal[False],
        retries: int,
        timeout: float,
        retry_delay: float,
    ) -> SpinelFrame: ...

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
        await self.reset(ResetReason.BOOTLOADER)

    async def set_property(
        self, property_id: PropertyID, value, *, timeout=1
    ) -> tuple[PropertyID, bytes]:
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
        _LOGGER.info(
            "Setting %s=%s, result %s=%r", property_id, orig_value, rsp_prop_id, rest
        )

        return rsp_prop_id, rest

    def add_property_listener(
        self, property_id: PropertyID, callback: typing.Callable
    ) -> None:
        self._property_listeners[property_id].append(callback)

    def remove_property_listener(
        self, property_id: PropertyID, callback: typing.Callable
    ) -> None:
        self._property_listeners[property_id].remove(callback)

    async def iter_property_changes(
        self, property_id: PropertyID
    ) -> typing.AsyncIterator:
        queue = asyncio.Queue()

        try:
            self.add_property_listener(property_id, queue.put_nowait)

            while True:
                item = await queue.get()
                yield item
        finally:
            self.remove_property_listener(property_id, queue.put_nowait)

    async def wait_for_property(self, property_id: PropertyID, value: bytes) -> None:
        async for changed_value in self.iter_property_changes(property_id):
            if changed_value == value:
                return

    async def reset(
        self,
        reset_type: ResetReason = ResetReason.STACK,
    ) -> None:
        await self.send_command(
            CommandID.RESET,
            reset_type.serialize(),
            wait_response=False,
        )

        if reset_type == ResetReason.BOOTLOADER:
            # A small delay is necessary when switching baudrates
            await asyncio.sleep(0.5)
            return

        await self.wait_for_property(
            PropertyID.LAST_STATUS, Status.RESET_POWER_ON.serialize()
        )

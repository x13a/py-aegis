from __future__ import annotations

import hmac
import itertools
import struct
from collections.abc import (
    Iterator,
)

from aegis.aes import Block as AesBlock

AEGIS128L_KEY_LENGTH = 16
AEGIS128L_NONCE_LENGTH = 16
AEGIS128L_TAG_LENGTH = 16

AEGIS256_KEY_LENGTH = 32
AEGIS256_NONCE_LENGTH = 32
AEGIS256_TAG_LENGTH = 16

C1 = (
    0xdb, 0x3d, 0x18, 0x55, 
    0x6d, 0xc2, 0x2f, 0xf1, 
    0x20, 0x11, 0x31, 0x42, 
    0x73, 0xb5, 0x28, 0xdd,
)

C2 = (
    0x00, 0x01, 0x01, 0x02, 
    0x03, 0x05, 0x08, 0x0d, 
    0x15, 0x22, 0x37, 0x59, 
    0x90, 0xe9, 0x79, 0x62,
)


class AuthenticationFailed(Exception):
    pass


class State128L:
    size = 32

    _blocks: list[AesBlock, 8]

    def __init__(
        self, 
        key: bytes[AEGIS128L_KEY_LENGTH], 
        nonce: bytes[AEGIS128L_NONCE_LENGTH],
    ) -> None:
        c1 = AesBlock.from_bytes(bytes(C1))
        c2 = AesBlock.from_bytes(bytes(C2))
        key_block = AesBlock.from_bytes(key)
        nonce_block = AesBlock.from_bytes(nonce)
        self._blocks = [
            key_block ^ nonce_block,
            c1, 
            c2, 
            c1, 
            key_block ^ nonce_block,
            key_block ^ c2,
            key_block ^ c1,
            key_block ^ c2,
        ]
        for _ in itertools.repeat(None, 10):
            self.update(nonce_block, key_block)

    def update(self, d1: AesBlock, d2: AesBlock) -> None:
        blocks = self._blocks
        tmp = blocks[7]
        for i in range(7, 0, -1):
            blocks[i] = blocks[i - 1].encrypt(blocks[i])
        blocks[0] = tmp.encrypt(blocks[0]) ^ d1
        blocks[4] ^= d2
    
    def enc(self, src: bytes[size]) -> bytes[size]:
        blocks = self._blocks
        msg0 = AesBlock.from_bytes(src[:16])
        msg1 = AesBlock.from_bytes(src[16:])
        tmp0 = msg0 ^ blocks[6] ^ blocks[1] ^ (blocks[2] & blocks[3])
        tmp1 = msg1 ^ blocks[2] ^ blocks[5] ^ (blocks[6] & blocks[7])
        self.update(msg0, msg1)
        out = bytearray(self.size)
        tmp0.into_bytes(out)
        tmp1.into_bytes(out, 16)
        return bytes(out)

    def dec(self, src: bytes[size]) -> bytes[size]:
        blocks = self._blocks
        msg0 = AesBlock.from_bytes(src[:16]) ^ blocks[6] ^ blocks[1] ^ (blocks[2] & blocks[3])
        msg1 = AesBlock.from_bytes(src[16:]) ^ blocks[2] ^ blocks[5] ^ (blocks[6] & blocks[7])
        self.update(msg0, msg1)
        out = bytearray(self.size)
        msg0.into_bytes(out)
        msg1.into_bytes(out, 16)
        return bytes(out)

    def mac(self, ad_len: int, data_len: int) -> bytes[AEGIS128L_TAG_LENGTH]:
        assert ad_len >= 0
        assert data_len >= 0
        blocks = self._blocks
        tmp = AesBlock.from_bytes(struct.pack('<QQ', ad_len << 3, data_len << 3)) ^ blocks[2]
        for _ in itertools.repeat(None, 7):
            self.update(tmp, tmp)
        return (
            blocks[0] ^ blocks[1] ^ 
            blocks[2] ^ blocks[3] ^ 
            blocks[4] ^ blocks[5] ^ 
            blocks[6]
        ).to_bytes()
    

class State256:
    size = 16

    _blocks: list[AesBlock, 6]

    def __init__(
        self, 
        key: bytes[AEGIS256_KEY_LENGTH], 
        nonce: bytes[AEGIS256_NONCE_LENGTH],
    ) -> None:
        c1 = AesBlock.from_bytes(bytes(C1))
        c2 = AesBlock.from_bytes(bytes(C2))
        key_block1 = AesBlock.from_bytes(key[:16])
        key_block2 = AesBlock.from_bytes(key[16:])
        kxn1 = key_block1 ^ AesBlock.from_bytes(nonce[:16])
        kxn2 = key_block2 ^ AesBlock.from_bytes(nonce[16:])
        self._blocks = [
            kxn1, 
            kxn2,
            c1, 
            c2,
            key_block1 ^ c2, 
            key_block2 ^ c1,
        ]
        for _ in itertools.repeat(None, 4):
            self.update(key_block1)
            self.update(key_block2)
            self.update(kxn1)
            self.update(kxn2)

    def update(self, d: AesBlock) -> None:
        blocks = self._blocks
        tmp = blocks[5].encrypt(blocks[0])
        for i in range(5, 0, -1):
            blocks[i] = blocks[i - 1].encrypt(blocks[i])
        blocks[0] = tmp ^ d

    def enc(self, src: bytes[size]) -> bytes[size]:
        blocks = self._blocks
        msg = AesBlock.from_bytes(src)
        tmp = msg ^ blocks[5] ^ blocks[4] ^ blocks[1] ^ (blocks[2] & blocks[3])
        self.update(msg)
        return tmp.to_bytes()

    def dec(self, src: bytes[size]) -> bytes[size]:
        blocks = self._blocks
        msg = AesBlock.from_bytes(src) ^ blocks[5] ^ blocks[4] ^ blocks[1] ^ (blocks[2] & blocks[3])
        self.update(msg)
        return msg.to_bytes()

    def mac(self, ad_len: int, data_len: int) -> bytes[AEGIS256_TAG_LENGTH]:
        assert ad_len >= 0
        assert data_len >= 0
        blocks = self._blocks
        tmp = AesBlock.from_bytes(struct.pack('<QQ', ad_len << 3, data_len << 3)) ^ blocks[3]
        for _ in itertools.repeat(None, 7):
            self.update(tmp)
        return (
            blocks[0] ^ blocks[1] ^ 
            blocks[2] ^ blocks[3] ^ 
            blocks[4] ^ blocks[5]
        ).to_bytes()


def _make(
    key_length_: int,
    nonce_length_: int,
    tag_length_: int,
    state_class: type,
) -> type:

    class Aegis:
        key_length = key_length_
        nonce_length = nonce_length_
        tag_length = tag_length_

        @staticmethod
        def iter_encrypt(
            data: bytes,
            key: bytes[key_length],
            nonce: bytes[nonce_length],
            ad: bytes | None = None,
        ) -> Iterator[bytes]:
            if isinstance(data, (bytes, bytearray)):
                data = memoryview(data)
            data_len = len(data)
            state = state_class(key, nonce)
            size = state.size
            src = bytearray(size)
            ad = ad or b''
            if isinstance(ad, (bytes, bytearray)):
                ad = memoryview(ad)
            ad_len = len(ad)
            i, j = 0, size
            while j <= ad_len:
                state.enc(ad[i:j])
                i = j
                j += size
            ad_mod = ad_len % size
            if ad_mod != 0:
                src[:ad_mod] = ad[i:i + ad_mod]
                state.enc(src)
            i, j = 0, size
            while j <= data_len:
                yield state.enc(data[i:j])
                i = j
                j += size
            data_mod = data_len % size
            if data_mod != 0:
                src[data_mod:] = bytes(size - data_mod)
                src[:data_mod] = data[i:i + data_mod]
                yield state.enc(src)[:data_mod]
            yield state.mac(ad_len, data_len)

        @staticmethod
        def iter_decrypt(
            data: bytes,
            key: bytes[key_length],
            nonce: bytes[nonce_length],
            ad: bytes | None = None,
        ) -> Iterator[bytes]:
            assert len(data) >= tag_length_
            if isinstance(data, (bytes, bytearray)):
                data = memoryview(data)
            data_len = len(data) - tag_length_
            state = state_class(key, nonce)
            size = state.size
            src = bytearray(size)
            ad = ad or b''
            if isinstance(ad, (bytes, bytearray)):
                ad = memoryview(ad)
            ad_len = len(ad)
            i, j = 0, size
            while j <= ad_len:
                state.enc(ad[i:j])
                i = j
                j += size
            ad_mod = ad_len % size
            if ad_mod != 0:
                src[:ad_mod] = ad[i:i + ad_mod]
                state.enc(src)
            i, j = 0, size
            while j <= data_len:
                yield state.dec(data[i:j])
                i = j
                j += size
            data_mod = data_len % size
            if data_mod != 0:
                src[data_mod:] = bytes(size - data_mod)
                src[:data_mod] = data[i:i + data_mod]
                dst = bytearray(state.dec(src))
                yield dst[:data_mod]
                dst[:data_mod] = bytes(data_mod)
                blocks = state._blocks
                blocks[0] ^= AesBlock.from_bytes(dst[:16])
                if size == 32:
                    blocks[4] ^= AesBlock.from_bytes(dst[16:])
            tag = data[-tag_length_:]
            computed_tag = state.mac(ad_len, data_len)
            if not hmac.compare_digest(tag, computed_tag):
                raise AuthenticationFailed('invalid tag')

        @staticmethod
        def encrypt(
            data: bytes,
            key: bytes[key_length],
            nonce: bytes[nonce_length],
            ad: bytes | None = None,
        ) -> bytes:
            return b''.join(Aegis.iter_encrypt(data, key, nonce, ad))

        @staticmethod
        def decrypt(
            data: bytes,
            key: bytes[key_length],
            nonce: bytes[nonce_length],
            ad: bytes | None = None,
        ) -> bytes:
            return b''.join(Aegis.iter_decrypt(data, key, nonce, ad))

    return Aegis


Aegis128L = _make(AEGIS128L_KEY_LENGTH, AEGIS128L_NONCE_LENGTH, AEGIS128L_TAG_LENGTH, State128L)
Aegis256 = _make(AEGIS256_KEY_LENGTH, AEGIS256_NONCE_LENGTH, AEGIS256_TAG_LENGTH, State256)

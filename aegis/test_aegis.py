import unittest

from aegis.aegis import (
    Aegis128L,
    Aegis256,
    AuthenticationFailed,
)


class AegisTestCase(unittest.TestCase):
    def test_aegis128l_1(self):
        key = bytes([0x10, 0x01] + [0x00] * 14)
        nonce = bytes([0x10, 0x00, 0x02] + [0x00] * 13)
        ad = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        data = bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ])

        out1 = Aegis128L.encrypt(data, key, nonce, ad)
        out2 = Aegis128L.decrypt(out1, key, nonce, ad)
        self.assertEqual(data, out2)

        data = out1[:-Aegis128L.tag_length]
        tag = out1[-Aegis128L.tag_length:]

        self.assertEqual(
            '79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84', 
            data.hex(),
        )
        self.assertEqual('cc6f3372f6aa1bb82388d695c3962d9a', tag.hex())

        data = bytearray(data)
        data[0] = (data[0] + 1) & 0xff
        with self.assertRaises(AuthenticationFailed):
            Aegis128L.decrypt(bytes(data) + tag, key, nonce, ad)
        
        data[0] = (data[0] - 1) & 0xff
        tag = bytearray(tag)
        tag[0] = (tag[0] + 1) & 0xff
        with self.assertRaises(AuthenticationFailed):
            Aegis128L.decrypt(bytes(data + tag), key, nonce, ad)
    
    def test_aegis128l_2(self):
        key = bytes(Aegis128L.key_length)
        nonce = bytes(Aegis128L.nonce_length)
        ad = None
        data = bytes(16)

        out1 = Aegis128L.encrypt(data, key, nonce, ad)
        out2 = Aegis128L.decrypt(out1, key, nonce, ad)
        self.assertEqual(data, out2)

        self.assertEqual('41de9000a7b5e40e2d68bb64d99ebb19', out1[:-Aegis128L.tag_length].hex())
        self.assertEqual('f4d997cc9b94227ada4fe4165422b1c8', out1[-Aegis128L.tag_length:].hex())
    
    def test_aegis128l_3(self):
        key = bytes(Aegis128L.key_length)
        nonce = bytes(Aegis128L.nonce_length)
        ad = None
        data = b''

        out1 = Aegis128L.encrypt(data, key, nonce, ad)
        out2 = Aegis128L.decrypt(out1, key, nonce, ad)
        self.assertEqual(data, out2)
        self.assertEqual('83cc600dc4e3e7e62d4055826174f149', out1[-Aegis128L.tag_length:].hex())

    def test_aegis256_1(self):
        key = bytes([0x10, 0x01] + [0x00] * 30)
        nonce = bytes([0x10, 0x00, 0x02] + [0x00] * 29)
        ad = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        data = bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ])

        out1 = Aegis256.encrypt(data, key, nonce, ad)
        out2 = Aegis256.decrypt(out1, key, nonce, ad)
        self.assertEqual(data, out2)

        data = out1[:-Aegis128L.tag_length]
        tag = out1[-Aegis128L.tag_length:]

        self.assertEqual(
            'f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711', 
            data.hex(),
        )
        self.assertEqual('8d86f91ee606e9ff26a01b64ccbdd91d', tag.hex())

        data = bytearray(data)
        data[0] = (data[0] + 1) & 0xff
        with self.assertRaises(AuthenticationFailed):
            Aegis256.decrypt(bytes(data) + tag, key, nonce, ad)
        
        data[0] = (data[0] - 1) & 0xff
        tag = bytearray(tag)
        tag[0] = (tag[0] + 1) & 0xff
        with self.assertRaises(AuthenticationFailed):
            Aegis256.decrypt(bytes(data + tag), key, nonce, ad)

    def test_aegis256_2(self):
        key = bytes(Aegis256.key_length)
        nonce = bytes(Aegis256.nonce_length)
        ad = None
        data = bytes(16)

        out1 = Aegis256.encrypt(data, key, nonce, ad)
        out2 = Aegis256.decrypt(out1, key, nonce, ad)
        self.assertEqual(data, out2)

        self.assertEqual('b98f03a947807713d75a4fff9fc277a6', out1[:-Aegis256.tag_length].hex())
        self.assertEqual('478f3b50dc478ef7d5cf2d0f7cc13180', out1[-Aegis256.tag_length:].hex())

    def test_aegis256_3(self):
        key = bytes(Aegis256.key_length)
        nonce = bytes(Aegis256.nonce_length)
        ad = None
        data = b''

        out1 = Aegis256.encrypt(data, key, nonce, ad)
        out2 = Aegis256.decrypt(out1, key, nonce, ad)
        self.assertEqual(data, out2)
        self.assertEqual('f7a0878f68bd083e8065354071fc27c3', out1[-Aegis256.tag_length:].hex())

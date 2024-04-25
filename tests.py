import unittest
from block_cipher import BlockCipherAES, BlockCipherDES
from crypto_system import RSACryptosystem
from hashing import Hasher


class TestCryptoModules(unittest.TestCase):
    def setUp(self):
        # Initialize the crypto objects with keys
        self.aes = BlockCipherAES(key="myverystrongkey123")
        self.des = BlockCipherDES(key="weakkey")
        self.rsa = RSACryptosystem()
        self.message = "Hello, World!"

    def test_aes_encryption_decryption(self):
        # Test AES encryption and decryption
        encrypted = self.aes.encrypt(self.message)
        decrypted = self.aes.decrypt(encrypted)
        self.assertEqual(decrypted, self.message, "AES decryption failed")

    def test_des_encryption_decryption(self):
        # Test DES encryption and decryption
        encrypted = self.des.encrypt(self.message)
        decrypted = self.des.decrypt(encrypted)
        self.assertEqual(decrypted, self.message, "DES decryption failed")

    def test_rsa_encryption_decryption(self):
        # Test RSA encryption and decryption
        encrypted = self.rsa.encrypt(self.message)
        decrypted = self.rsa.decrypt(encrypted)
        self.assertEqual(decrypted, self.message, "RSA decryption failed")

    def test_sha256_hash(self):
        # Test SHA-256 hashing
        hash_result = Hasher.hash_sha256(self.message)
        self.assertEqual(len(hash_result), 64, "SHA-256 hash length is incorrect")
        self.assertIsInstance(hash_result, str, "SHA-256 hash is not a string")

    def test_md5_hash(self):
        # Test MD5 hashing
        hash_result = Hasher.hash_md5(self.message)
        self.assertEqual(len(hash_result), 32, "MD5 hash length is incorrect")
        self.assertIsInstance(hash_result, str, "MD5 hash is not a string")


if __name__ == "__main__":
    unittest.main()

from Crypto.Cipher import AES, DES
import base64


class BlockCipherAES:
    def __init__(self, key):
        # Adjust key to ensure it is one of the valid AES key lengths (16, 24, 32 bytes)
        key_bytes = key.encode("utf-8")
        key_length = len(key_bytes)
        if key_length <= 16:
            # Pad key to 16 bytes
            key_bytes = key_bytes.ljust(16, b"\0")
        elif key_length <= 24:
            # Pad to 24 bytes
            key_bytes = key_bytes.ljust(24, b"\0")
        else:
            # Pad to 32 bytes
            key_bytes = key_bytes.ljust(32, b"\0")
        self.key = key_bytes

    @staticmethod
    def pad(message, block_size=16):
        return message + (block_size - len(message) % block_size) * chr(
            block_size - len(message) % block_size
        )

    @staticmethod
    def unpad(message):
        return message[: -ord(message[len(message) - 1])]

    def encrypt(self, plain_text):
        plain_text = self.pad(plain_text)
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_text = cipher.encrypt(plain_text.encode("utf-8"))
        return base64.b64encode(encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = base64.b64decode(encrypted_text)
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted_text = cipher.decrypt(encrypted_text)
        return self.unpad(decrypted_text.decode("utf-8"))


class BlockCipherDES:
    def __init__(self, key):
        self.key = key.encode("utf-8").ljust(8)[:8]  # Ensure DES key is 8 bytes

    @staticmethod
    def pad(message, block_size=8):
        return message + (block_size - len(message) % block_size) * chr(
            block_size - len(message) % block_size
        )

    @staticmethod
    def unpad(message):
        return message[: -ord(message[len(message) - 1])]

    def encrypt(self, plain_text):
        plain_text = self.pad(plain_text)
        cipher = DES.new(self.key, DES.MODE_ECB)
        encrypted_text = cipher.encrypt(plain_text.encode("utf-8"))
        return base64.b64encode(encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = base64.b64decode(encrypted_text)
        cipher = DES.new(self.key, DES.MODE_ECB)
        decrypted_text = cipher.decrypt(encrypted_text)
        return self.unpad(decrypted_text.decode("utf-8"))

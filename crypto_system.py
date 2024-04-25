from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


class RSACryptosystem:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey().export_key()
        self.private_key = self.key.export_key()

    def encrypt(self, message):
        recipient_key = RSA.import_key(self.public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_message = cipher_rsa.encrypt(message.encode("utf-8"))
        return binascii.hexlify(encrypted_message).decode("utf-8")

    def decrypt(self, encrypted_message):
        key = RSA.import_key(self.private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        encrypted_message = binascii.unhexlify(encrypted_message)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message.decode("utf-8")

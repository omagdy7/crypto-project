from block_cipher import BlockCipherAES, BlockCipherDES
from crypto_system import RSACryptosystem
from hashing import Hasher


def main():
    # Test AES and DES encryption/decryption
    aes_cipher = BlockCipherAES(key="myverystrongkey123")
    des_cipher = BlockCipherDES(key="weakkey")

    message = "Hello, World!"
    print("Original message:", message)

    # AES Encryption/Decryption
    aes_encrypted = aes_cipher.encrypt(message)
    aes_decrypted = aes_cipher.decrypt(aes_encrypted)
    print("AES Encrypted:", aes_encrypted)
    print("AES Decrypted:", aes_decrypted)

    # DES Encryption/Decryption
    des_encrypted = des_cipher.encrypt(message)
    des_decrypted = des_cipher.decrypt(des_encrypted)
    print("DES Encrypted:", des_encrypted)
    print("DES Decrypted:", des_decrypted)

    # RSA Encryption/Decryption
    rsa_system = RSACryptosystem()
    rsa_encrypted = rsa_system.encrypt(message)
    rsa_decrypted = rsa_system.decrypt(rsa_encrypted)
    print("RSA Encrypted:", rsa_encrypted)
    print("RSA Decrypted:", rsa_decrypted)

    # Hashing with SHA-256 and MD5
    sha256_hash = Hasher.hash_sha256(message)
    md5_hash = Hasher.hash_md5(message)
    print("SHA-256 Hash:", sha256_hash)
    print("MD5 Hash:", md5_hash)


if __name__ == "__main__":
    main()

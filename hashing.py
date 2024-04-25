import hashlib


class Hasher:
    @staticmethod
    def hash_sha256(message):
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_md5(message):
        return hashlib.md5(message.encode("utf-8")).hexdigest()

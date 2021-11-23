from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Chacha:

    def __init__(self, data, key, nonce, aad):
        self.__chacha = ChaCha20Poly1305(key)
        self.__data = data
        self.__nonce = nonce
        self.__aad = aad

    def encrypt(self):
        ct = self.__chacha.encrypt(self.__nonce, self.__data, self.__aad)
        return ct

    def decrypt(self):
        ct = self.__chacha.decrypt(self.__nonce, self.__data, self.__aad)
        return ct


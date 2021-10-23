from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Chacha():

    def __init__(self, data, key, nonce, aad):
        self.__chacha = ChaCha20Poly1305(key)
        self.__data = data
        self.__nonce = nonce
        self.__aad = aad

    def encrypt(self, data, nonce, aad):
        ct = self.__chacha.encrypt(nonce, data, aad)
        return ct

    def decrypt(self, data, nonce, aad):
        self.__chacha.decrypt(nonce, data, aad)
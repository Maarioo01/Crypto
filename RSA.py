from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class RSA:

    def __init__(self):
        pass

    @staticmethod
    def generate_private_key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key

    @staticmethod
    def generate_public_key(private_key):
        public_key = private_key.public_key()
        return public_key

    @staticmethod
    def serialization_private(private_key):
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes("password", encoding="utf-8"))
        )
        return pem_private

    @staticmethod
    def serialization_public(public_key):
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_public

    @staticmethod
    def deserialization_private(pem_private_key):
        private_key = serialization.load_pem_private_key(
            pem_private_key,
            password=bytes("password", encoding="utf-8"),
        )
        return private_key

    @staticmethod
    def deserialization_public(pem_public_key):
        public_key = serialization.load_pem_public_key(pem_public_key)
        return public_key

    @staticmethod
    def sign_document(data, private_key):
        signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    @staticmethod
    def verify_document(data, signature, public_key):
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True


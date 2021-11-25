from RSA import RSA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
import base64
# from main import App no se puede hacer


class CSR:

    def __init__(self):
        pass

    @staticmethod
    def byte_to_str(file):
        # b64_string = file.decode('utf-8').strip
        b64_bytes = base64.urlsafe_b64encode(file)
        b64_string = b64_bytes.decode("ascii")
        return b64_string

    @staticmethod
    def str_to_byte(file):
        # bytes_bis = file.encode('utf-8').strip
        b64_bytes_bis = file.encode("ascii")
        bytes_bis = base64.urlsafe_b64decode(b64_bytes_bis)
        return bytes_bis

    @staticmethod
    def generate_csr(key):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(u"mysite.com"),
                x509.DNSName(u"www.mysite.com"),
                x509.DNSName(u"subdomain.mysite.com"),
            ]),
            critical=False,
            # Sign the CSR with our private key.
        ).sign(key, hashes.SHA256())
        return csr


def main3():
    csr = CSR()
    rsa = RSA()
    with open("C:\\Users\\Mario\\PycharmProjects\\Crypto\\clave_private.txt", "r") as file:
        private_key = file.read()
    private_key = csr.str_to_byte(private_key)
    private_key = rsa.deserialization_private(private_key)
    certificate = csr.generate_csr(private_key)
    with open("C:\\Users\\Mario\\PycharmProjects\\Crypto\\csr.pem", "wb") as file:
        file.write(certificate.public_bytes(serialization.Encoding.PEM))


main3()

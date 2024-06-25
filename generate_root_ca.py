from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Generate Root CA private key
root_ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Save Root CA private key to PEM file
with open("root_ca_private_key.pem", "wb") as f:
    f.write(root_ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Generate Root CA certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "myrootca.com"),
])

root_ca_certificate = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    root_ca_private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).sign(root_ca_private_key, hashes.SHA256())

# Save Root CA certificate to PEM file
with open("root_ca_certificate.pem", "wb") as f:
    f.write(root_ca_certificate.public_bytes(serialization.Encoding.PEM))

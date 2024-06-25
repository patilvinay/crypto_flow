from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Generate signing private key
signing_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Save signing private key to PEM file
with open("signing_private_key.pem", "wb") as f:
    f.write(signing_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# load the root CA private key
with open("root_ca_private_key.pem", "rb") as f:
    root_ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
    )
# load the root CA certificate
with open("root_ca_certificate.pem", "rb") as f:
    root_ca_certificate = x509.load_pem_x509_certificate(f.read())

# Generate signing certificate request
signing_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "mycompany.com"),
])

signing_certificate_request = x509.CertificateSigningRequestBuilder().subject_name(
    signing_subject
).sign(signing_private_key, hashes.SHA256())

# Sign the request with the Root CA
from cryptography import x509
import datetime

# Assuming root_ca_certificate and root_ca_private_key are defined elsewhere

signing_certificate = x509.CertificateBuilder().subject_name(
    signing_certificate_request.subject
).issuer_name(
    root_ca_certificate.subject  # root_ca_certificate is now defined
).public_key(
    signing_certificate_request.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True,
).sign(root_ca_private_key, hashes.SHA256())

# Save signing certificate to PEM file
with open("signing_certificate.pem", "wb") as f:
    f.write(signing_certificate.public_bytes(serialization.Encoding.PEM))

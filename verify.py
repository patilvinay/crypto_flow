import asn1crypto.cms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

# Load the DER file
with open("signed_data_with_attrs.der", "rb") as f:
    der_data = f.read()

# Parse the DER data
cms_content_info = asn1crypto.cms.ContentInfo.load(der_data)
signed_data = cms_content_info['content']

# Print the parsed CMS structure
print(signed_data)

# Data to be verified (provided separately)
data_to_verify = b"This is the data to be signed."

# Extract the signer information
signer_info = signed_data['signer_infos'][0]
digest_algorithm = signer_info['digest_algorithm']['algorithm'].native

# Extract the signed attributes
signed_attrs = signer_info['signed_attrs']

# Find the message_digest attribute
message_digest = None
for attr in signed_attrs:
    if attr['type'].native == 'message_digest':
        message_digest = attr['values'][0].native
        break

if message_digest is None:
    raise ValueError("message_digest attribute not found in signed attributes")

# Verify the message digest
hasher = hashes.Hash(hashes.SHA256())
hasher.update(data_to_verify)
hashed_data = hasher.finalize()

if hashed_data != message_digest:
    print("Message digest verification failed!")
else:
    print("Message digest verification succeeded!")

# Extract the signing certificate
signing_certificate = signed_data['certificates'][0].chosen

# Convert the asn1crypto certificate to a DER format
signing_cert_der = signing_certificate.dump()
signing_cert = x509.load_der_x509_certificate(signing_cert_der)

# Get the public key from the signing certificate
public_key = signing_cert.public_key()

# Hash the data to be verified using the same algorithm
hash_algorithm = hashes.SHA256()
hasher = hashes.Hash(hash_algorithm)
hasher.update(data_to_verify)
hashed_data = hasher.finalize()

# Print the expected hash of the data
print("Expected hash of the data:", hashed_data.hex())

# Verify the signature
signature = signer_info['signature'].native
try:
    public_key.verify(
        signature,
        hashed_data,
        padding.PKCS1v15(),
        hash_algorithm
    )
    print("Signature is valid.")
except Exception as e:
    print(f"Signature verification failed: {e}")


# Load Root CA certificate
with open("root_ca_certificate.pem", "rb") as f:
    pem_root_ca_certificate = f.read()
root_ca_cert = x509.load_pem_x509_certificate(pem_root_ca_certificate)

# Verify the signing certificate against the Root CA certificate
try:
    root_ca_cert.public_key().verify(
        signing_cert.signature,
        signing_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        signing_cert.signature_hash_algorithm
    )
    print("Signing certificate is valid and trusted by the Root CA.")
except Exception as e:
    print(f"Signing certificate verification failed: {e}")

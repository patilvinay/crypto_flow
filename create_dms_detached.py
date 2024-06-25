import asn1crypto.cms
import asn1crypto.pem
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from datetime import datetime
from asn1crypto import algos, core, cms, x509

# Load signing private key
with open("signing_private_key.pem", "rb") as f:
    signing_private_key = serialization.load_pem_private_key(f.read(), password=None)

# Load signing certificate
with open("signing_certificate.pem", "rb") as f:
    pem_signing_certificate = f.read()

# Convert PEM to DER
if asn1crypto.pem.detect(pem_signing_certificate):
    _, _, der_signing_certificate = asn1crypto.pem.unarmor(pem_signing_certificate)
else:
    der_signing_certificate = pem_signing_certificate

# Convert the signing certificate to a CMS object
signing_cert = asn1crypto.x509.Certificate.load(der_signing_certificate)

# Data to be signed (not encapsulated)
data_to_sign = b"This is the data to be signed."

# Hash the data to be signed
hasher = hashes.Hash(hashes.SHA256())
hasher.update(data_to_sign)
content_hash = hasher.finalize()

# Print the hash of the content data
print("Hash of the content data:", content_hash.hex())

# Create signed attributes
signed_attrs = cms.CMSAttributes([
    cms.CMSAttribute({
        'type': 'content_type',
        'values': [cms.ContentType('data')]
    }),
    cms.CMSAttribute({
        'type': 'signing_time',
        'values': [core.UTCTime(datetime.utcnow().strftime('%y%m%d%H%M%SZ'))]
    }),
    cms.CMSAttribute({
        'type': 'message_digest',
        'values': [content_hash]
    })
])

# Create the SignedData structure for detached signature
signed_data = cms.SignedData({
    'version': 'v1',
    'digest_algorithms': [
        {'algorithm': 'sha256'}
    ],
    'encap_content_info': {
        'content_type': 'data'
    },
    'certificates': [signing_cert],
    'signer_infos': [{
        'version': 'v1',
        'sid': asn1crypto.cms.SignerIdentifier({
            'issuer_and_serial_number': {
                'issuer': signing_cert.issuer,
                'serial_number': signing_cert.serial_number
            }
        }),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signing_private_key.sign(
            content_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    }]
})

# Wrap the SignedData structure in a ContentInfo structure
cms_content_info = cms.ContentInfo({
    'content_type': 'signed_data',
    'content': signed_data
})

# Print the signature
print("Signature:", bytes(signed_data['signer_infos'][0]['signature']).hex())

# Save the CMS file in DER format
with open("signed_data_with_attrs.der", "wb") as f:
    f.write(cms_content_info.dump())

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from CertificationAuthority import CertificationAuthority
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import util

# 1. generate RSA key
rsa_key=util.generate_ras_key()

# 2. create certificate sign request and sign with client private key
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"client1.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName(u"mysite.com"),
        x509.DNSName(u"www.mysite.com"),
        x509.DNSName(u"subdomain.mysite.com"),
    ]),
    critical=False,
# Sign the CSR with our private key. is applicant's private key
).sign(rsa_key, hashes.SHA256())

# 3. send to certificate authority,  the data param name corresond fastapi parameter
response = requests.post(" http://127.0.0.1:8000/issue_cert",files={'csr_file':csr.public_bytes(serialization.Encoding.PEM)})
cert = x509.load_pem_x509_certificate(response.content)
print("applicant: "+cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
print("issuer: "+cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
print(cert.not_valid_before)
print(cert.not_valid_after)

# 4.getting ca public key which in SubjectPublicKeyInfo format
response = requests.post(" http://127.0.0.1:8000/get_CA_public_key")
ca_pub=serialization.load_pem_public_key(response.content)
print("validate: "+ str(util.verify_cert_signature(cert,ca_pub)))

#revoke cert
print("========revoke cert =======")
print("check status before revoke")
response = requests.post(" http://127.0.0.1:8000/revoke_cert_status",files={'crt_file':cert.public_bytes(serialization.Encoding.PEM)})
print(response.content)
print()
response = requests.post(" http://127.0.0.1:8000/revoke_cert",files={'crt_file':cert.public_bytes(serialization.Encoding.PEM)})
print(response.status_code)
print(response.content)
print('# revoke again #')
print(response.status_code)
response = requests.post(" http://127.0.0.1:8000/revoke_cert",files={'crt_file':cert.public_bytes(serialization.Encoding.PEM)})
print(response.content)
print()

print("check status after revoke")
response = requests.post(" http://127.0.0.1:8000/revoke_cert_status",files={'crt_file':cert.public_bytes(serialization.Encoding.PEM)})
print(response.content)

# user cert to sign another cert


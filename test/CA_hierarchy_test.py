from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from CertificationAuthority import CertificationAuthority
import datetime
import util
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

#root ca will create self sign cert
root_CA=CertificationAuthority(name='root',type='root')
root_public_key=serialization.load_pem_public_key(root_CA.get_public_key())

# ca1 sign by root
CA1=CertificationAuthority(name='CA1',type="intermediate")
ca1_public_key=serialization.load_pem_public_key(CA1.get_public_key())
ca1_csr=CA1.create_CSR()
ca1_cert_byte=root_CA.issue_certificate(ca1_csr)
CA1.save_cert(ca1_cert_byte)
ca1_cert=x509.load_pem_x509_certificate(ca1_cert_byte)

ca1_cert=CA1.get_CA_cert()


# client1
rsa_key=util.generate_ras_key()
rsa_key.public_key()
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
# Sign the CSR with our private key. is applicant private key
).sign(rsa_key, hashes.SHA256())

cert_public_byte=CA1.issue_certificate(csr)

#reconstruct from cert public byte
client1_cert = x509.load_pem_x509_certificate(cert_public_byte)
util.save_X509_cert(util.client_data_path,"client1",client1_cert)
print("applicant: "+client1_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
print("issuer: "+client1_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
print(client1_cert.not_valid_before)
print(client1_cert.not_valid_after)

# verify cert chain
print("\n =======verify cert chain ===========")
print('client 1 cert verify with root public key')
print("validate: "+ str(util.verify_cert_signature(client1_cert,root_public_key)))
print('client 1 cert verify with CA1 public key')
print("validate: "+ str(util.verify_cert_signature(client1_cert,ca1_public_key)))
print('CA1 cert verify with root public key')
print("validate: "+ str(util.verify_cert_signature(ca1_cert,root_public_key)))
print('revoke CA1 cert in root')

#
print()
root_CA.revocate_certificate(ca1_cert)
print("is client1 revoke: "+str(CA1.check_certificate_revoke_status(client1_cert)))
print("is ca1 revoke: "+str(root_CA.check_certificate_revoke_status(ca1_cert)))



# port 8000 is root, port 80001 is ca1
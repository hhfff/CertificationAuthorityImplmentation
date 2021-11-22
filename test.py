from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from CertificationAuthority import CertificationAuthority

import util
'''
You generate a private/public key pair.
You create a request for a certificate, which is signed by your key (to prove that you own that key).
You give your CSR to a CA (but not the private key).
The CA validates that you own the resource (e.g. domain) you want a certificate for.
The CA gives you a certificate, signed by them, which identifies your public key, and the resource you are authenticated for.
You configure your server to use that certificate, combined with your private key, to server traffic.

'''
# rsa_key=util.generate_ras_key()
# util.save_rsa_private_key('key',rsa_key,util.CA_key_path)
#rsa_key=util.load_rsa_private_key('key')
# get rsa public key
#print(rsa_key.public_key())



from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
root_CA=CertificationAuthority('root')

rsa_key=util.generate_ras_key()
rsa_key.public_key()
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
# Sign the CSR with our private key. is applicant private key
).sign(rsa_key, hashes.SHA256())

cert_pub=root_CA.issue_certificate(csr)

#reconstruct from cert public byte
cert = x509.load_pem_x509_certificate(cert_pub)
print(cert.not_valid_after)
# verify signature
ca_public_key=root_CA.get_public_key()

print(util.verify_cert_signature(cert,ca_public_key))



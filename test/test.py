from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from CertificationAuthority import CertificationAuthority
import datetime
import util
import os

#export CA_NAME="root"
#export CA_TYPE="root"
# for key in os.environ:
#     print(key, '=>', os.environ[key])
# print(os.environ['CA_NAME'])
# print(os.environ['CA_TYPE'])

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







# #================client 1=============
# print("client 1")
# rsa_key=util.generate_ras_key()
# rsa_key.public_key()
# csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
#     # Provide various details about who we are.
#     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
#     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
#     x509.NameAttribute(NameOID.COMMON_NAME, u"client1.com"),
# ])).add_extension(
#     x509.SubjectAlternativeName([
#         # Describe what sites we want this certificate for.
#         x509.DNSName(u"mysite.com"),
#         x509.DNSName(u"www.mysite.com"),
#         x509.DNSName(u"subdomain.mysite.com"),
#     ]),
#     critical=False,
# # Sign the CSR with our private key. is applicant private key
# ).sign(rsa_key, hashes.SHA256())

# cert_pub=root_CA.issue_certificate(csr)

# #reconstruct from cert public byte
# cert = x509.load_pem_x509_certificate(cert_pub)
# print("applicant: "+cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
# print("issuer: "+cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
# print(cert.not_valid_before)
# print(cert.not_valid_after)

# # verify signature
# ca_public_key=serialization.load_pem_public_key(root_CA.get_public_key())
# print("validate: "+ str(util.verify_cert_signature(cert,ca_public_key)))

# #================client 2=============
# print("client 2")
# rsa_key2=util.generate_ras_key()
# rsa_key2.public_key()
# csr2 = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
#     # Provide various details about who we are.
#     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
#     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
#     x509.NameAttribute(NameOID.COMMON_NAME, u"client2.com"),
# ])).add_extension(
#     x509.SubjectAlternativeName([
#         # Describe what sites we want this certificate for.
#         x509.DNSName(u"mysite.com"),
#         x509.DNSName(u"www.mysite.com"),
#         x509.DNSName(u"subdomain.mysite.com"),
#     ]),
#     critical=False,
# # Sign the CSR with our private key. is applicant private key
# ).sign(rsa_key2, hashes.SHA256())

# cert_pub2=root_CA.issue_certificate(csr2)

# #reconstruct from cert byte
# cert2 = x509.load_pem_x509_certificate(cert_pub2)
# print("applicant: "+cert2.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
# print("issuer: "+cert2.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
# print(cert2.not_valid_before)
# print(cert2.not_valid_after)

# # verify signature
# ca_public_key2=serialization.load_pem_public_key(root_CA.get_public_key())
# print("validate: "+ str(util.verify_cert_signature(cert2,ca_public_key2)))

# # revoke
# print("both not revoke")
# print("is cert1 revoke? "+str(root_CA.check_certificate_revoke_status(cert)))
# print("is cert2 revoke? "+str(root_CA.check_certificate_revoke_status(cert2)))

# print("cert 2 revoke")
# root_CA.revocate_certificate(cert2)
# print("is cert1 revoke? "+str(root_CA.check_certificate_revoke_status(cert)))
# print("is cert2 revoke? "+str(root_CA.check_certificate_revoke_status(cert2)))


# #==========================
# #test using cert to sign another cert
# print("client 3 sign by client 2 cert")
# print("client 3")
# rsa_key2=util.generate_ras_key()
# csr3 = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
#     # Provide various details about who we are.
#     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
#     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"client3.com"),
#     x509.NameAttribute(NameOID.COMMON_NAME, u"client3.com"),
# ])).add_extension(
#     x509.SubjectAlternativeName([
#         # Describe what sites we want this certificate for.
#         x509.DNSName(u"mysite.com"),
#         x509.DNSName(u"www.mysite.com"),
#         x509.DNSName(u"subdomain.mysite.com"),
#     ]),
#     critical=False,
# # Sign the CSR with our private key. is applicant private key
# ).sign(rsa_key2, hashes.SHA256())

# cert3 = x509.CertificateBuilder().subject_name(
#                 csr3.subject
#             ).issuer_name(
#                 cert2.subject
#             ).public_key(
#                 cert2.public_key()
#             ).serial_number(
#                 x509.random_serial_number()
#             ).not_valid_before(
#                 datetime.datetime.utcnow()
#             ).not_valid_after(
#                 # Our certificate will be valid for 10 days
#                  datetime.datetime.utcnow() + datetime.timedelta(days=10)
#             # Sign cleint2  private key
#             ).sign(rsa_key2, hashes.SHA256())
# print("applicant: "+cert3.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
# print("issuer: "+cert3.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
# print("validate: "+ str(util.verify_cert_signature(cert3,rsa_key2.public_key())))
# util.save_X509_cert(util.client_data_path,"client2",cert2)
# util.save_X509_cert(util.client_data_path,"client3",cert3)

# for ext in cert2.extensions:
#     print(ext)
# for ext in cert3.extensions:
#     print(ext)
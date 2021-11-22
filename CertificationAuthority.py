import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import util

#root CA is called root
#level 1 ca is called CA1,  if has multiple CA in this level , then is CA1_1, CA1_2 
#level 2 ca called CA2, if has multiple CA in this level  CA2_1, CA2_2
class CertificationAuthority():
    #if top CA is None, it is root CA
    def __init__(self,name,top_CA=None) -> None:
        self.name=name
        self.issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"ingapore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{name}".format(name=self.name)), #only this line different for different CA
            x509.NameAttribute(NameOID.COMMON_NAME, u"ntu.com"),
        ])
        if os.path.isfile(f"{util.CA_data_path}{name}.key"):
            print("load")
            self.rsa_private_key=util.load_rsa_private_key(util.CA_data_path,name)
            # load certificate
            self.ca_cert=util.load_X509_cert(util.CA_data_path,name)
        elif top_CA is None:
            #need generate own rsa key becasue key file not exist, this is for the root, which is self sign
            print("self sign")
            self.self_sign_cert()
        else:
            #intermideiate CA, ask 1 level above to sign, which is top_ca
            print("intermediate")
            pass


    #csr is CSR certificate object 
    def issue_certificate(self,csr):
        #cert is X.509 Certificate Object¶
        cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                self.issuer
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                 datetime.datetime.utcnow() + datetime.timedelta(days=10)
            # Sign our certificate with our private key
            ).sign(self.rsa_private_key, hashes.SHA256())

        #public byteThe data that can be written to a file or sent over the network to be verified by clients.
        return cert.public_bytes(serialization.Encoding.PEM)
        
    def revocate_certificate(self):
        pass
    def verify_certificate(self):
        pass

    def get_public_key(self):
        return self.rsa_private_key.public_key()


    #for root server only
    def self_sign_cert(self):
        self.rsa_private_key=util.generate_ras_key()
        util.save_rsa_private_key(util.CA_data_path,self.name,self.rsa_private_key)
        subject = self.issuer

        self.cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.issuer
            ).public_key(
                self.rsa_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
        # Sign our certificate with our private key, which is CA private key
        ).sign(self.rsa_private_key, hashes.SHA256())
        # Write our certificate out to disk.
        util.save_X509_cert(util.CA_data_path,self.name,self.cert)
    
        

        



    


        
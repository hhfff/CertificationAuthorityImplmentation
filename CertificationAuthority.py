import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import exceptions, x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import util

#root CA is called root
#level 1 ca is called CA1,  if has multiple CA in this level , then is CA1_1, CA1_2 
#level 2 ca called CA2, if has multiple CA in this level  CA2_1, CA2_2
class CertificationAuthority():
    #if top CA is None, it is root CA
    # type is root, intermediate, end 
    def __init__(self,name,type="root") -> None:
        self.name=name
        self.issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{name}".format(name=self.name)), 
            x509.NameAttribute(NameOID.COMMON_NAME, u"{name}".format(name=self.name)),
        ])

        # loading key and cert
        if os.path.isfile(f"{util.CA_data_path}{name}.key"):
            # print("load")
            # load private key
            self.rsa_private_key=util.load_rsa_private_key(util.CA_data_path,name)
            # load certificate
            self.ca_cert=util.load_X509_cert(util.CA_data_path,name)
        elif type == 'root':
            #need generate own rsa key becasue key file not exist, this is for the root, which is self sign
            #print("self sign")
            self.self_sign_cert()
        elif type == 'intermediate':
            #intermideiate CA, ask 1 level above to sign, which is top_ca
            #print("intermediate")
            pass
        else:
            raise exceptions


    def load_crl(self):
        #by right should be in memory
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.issuer)
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.now())
        crl=None
        if os.path.isfile(f"{util.CA_data_path}{self.name}.crl"):
            crl=util.load_cert_revocation_list(self.name)
            # add crl certificates from file to the new crl object
            for i in range(0,len(crl)):    
                builder = builder.add_revoked_certificate(crl[i])
        else:
            #create a empty crl if file not exist
            crl = builder.sign(private_key=self.rsa_private_key, algorithm=hashes.SHA256())
            util.save_cert_revocation_list(crl,self.name)
        return (crl,builder)

    #csr is CSR certificate object 
    def issue_certificate(self,csr):
        #cert is X.509 Certificate Object¶
        builder = x509.CertificateBuilder().subject_name(
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
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
        
        cert=builder.sign(self.rsa_private_key, hashes.SHA256())

        #public byte: The data that can be written to a file or sent over the network to be verified by clients.
        return cert.public_bytes(serialization.Encoding.PEM)
        
    def revocate_certificate(self,cert_to_revoke):
        crl,builder=self.load_crl()
        ret = crl.get_revoked_certificate_by_serial_number(cert_to_revoke.serial_number)
        #if not revoke then add to revoke list
        if not isinstance(ret, x509.RevokedCertificate):  
            revoked_cert = x509.RevokedCertificateBuilder()\
            .serial_number(cert_to_revoke.serial_number)\
            .revocation_date(datetime.datetime.now()).build()
            builder=builder.add_revoked_certificate(revoked_cert)
            crl = builder.sign(private_key=self.rsa_private_key, algorithm=hashes.SHA256())
            util.save_cert_revocation_list(crl,self.name)
            return True
        else:
            return False
        
    def check_certificate_revoke_status(self,cert_to_check):
        crl,builder=self.load_crl()
        ret = crl.get_revoked_certificate_by_serial_number(cert_to_check.serial_number)
        #if not revoke then add to revoke list
        if not isinstance(ret, x509.RevokedCertificate):  
            return False
        else:
            return True
        

    def get_public_key(self):
        return self.rsa_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,

                #SubjectPublicKeyInfo format
                #-----BEGIN PUBLIC KEY-----
                #-----END PUBLIC KEY-----
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def get_CA_cert(self):
        return self.ca_cert
    
    def create_CSR(self):
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
            ).sign(self.rsa_private_key, hashes.SHA256())
        return csr


    #for root server only
    def self_sign_cert(self):
        self.rsa_private_key=util.generate_ras_key()
        util.save_rsa_private_key(util.CA_data_path,self.name,self.rsa_private_key)
        subject = self.issuer

        self.ca_cert = x509.CertificateBuilder().subject_name(
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
                # a path_length of 1 means the certificate can sign a subordinate CA, 
                # but the subordinate CA is not allowed to create subordinates with ca set to true
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
        # Sign our certificate with our private key, which is CA private key
        ).sign(self.rsa_private_key, hashes.SHA256())
        # Write our certificate out to disk.
        util.save_X509_cert(util.CA_data_path,self.name,self.ca_cert)
    


    
        

        



    


        
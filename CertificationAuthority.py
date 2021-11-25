import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import exceptions, x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import requests
import util

#root CA is called root
#level 1 ca is called CA1,  if has multiple CA in this level , then is CA1, CA2
#next level called if CA1_1, CA1_2,      CA2_1  CA2_2
class CertificationAuthority():
    #if top CA is None, it is root CA
    # type is root, intermediate, end 
    #cur_env: [code, server], the server need provide port so can go ask top CA to issue cert
    def __init__(self,name,type="root",cur_env="code",top_CA_name=None) -> None:
        self.name=name
        self.type=type
        self.top_CA_name=top_CA_name
        self.cur_env=cur_env
        self.issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{name}".format(name=self.name)), 
            x509.NameAttribute(NameOID.COMMON_NAME, u"{name}".format(name=self.name)),
        ])

        
            
        
    def load_key_file(self):
        # loading key and cert
        if os.path.isfile(f"{util.CA_data_path}{self.name}.key"):
            # print("load")
            # load private key
            self.rsa_private_key=util.load_rsa_private_key(util.CA_data_path,self.name)
        else:
            self.rsa_private_key=util.generate_ras_key()
            util.save_rsa_private_key(util.CA_data_path,self.name,self.rsa_private_key)
    
    def load_cert_file(self):
        #load certificate
        if os.path.isfile(f"{util.CA_data_path}{self.name}.crt"):
            self.ca_cert=util.load_X509_cert(util.CA_data_path,self.name)
        elif self.type == 'root':
            #need generate own rsa key becasue key file not exist, this is for the root, which is self sign
            #print("self sign")
            self.self_sign_cert()
        elif self.type == 'intermediate':
            #intermideiate CA, ask 1 level above to sign, which is top_ca
            #print("intermediate")
            # need use request library to send api request to get cert sign, now eveything is in local machine, actual will use domain name
            if self.cur_env=="server":
                print(f'getting cert from {self.top_CA_name}')
                url=f"http://{self.top_CA_name}:80/issue_cert"
                response = requests.post(url,files={'csr_file':self.create_CSR().public_bytes(serialization.Encoding.PEM)})
                self.save_cert(response.content)
                print(f'cert saved')

                self.ca_cert=x509.load_pem_x509_certificate(response.content)

        else:
            pass


    def load_crl(self):
        #by right should be in memory
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer)
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.today())
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
        # f=open("./CA_data/issue.log","a")
        # f.write("issue")
        # f.close()

        #verify applicant signaure against public key
        # if not csr.is_signature_valid():
        #     pass
        self.load_key_file()
        self.load_cert_file()

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
            )
        if self.type =="root":
            builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
        elif self.type=="intermediate":
            # client set ca to false
            builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )

        cert=builder.sign(self.rsa_private_key, hashes.SHA256())
        
        #public byte: The data that can be written to a file or sent over the network to be verified by clients.
        return cert.public_bytes(serialization.Encoding.PEM)
        
    def revocate_certificate(self,cert_to_revoke):
        #check cert issuer same as this ca
        cert_issuer=cert_to_revoke.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cert_issuer!= self.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
            return False, f"The certificate was not issue by this server, the issuer is {cert_issuer}"
        # verify cert signature
        self.load_key_file()
        self.load_cert_file()
        if not util.verify_cert_signature(cert_to_revoke,self.rsa_private_key.public_key()):
            return False, "Wrong certificate signature"

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
            return True, 'Revoke successful'
        else:
            return False, 'Already revoke'
        
    def check_certificate_revoke_status(self,cert_to_check):
        #check cert issuer same as this ca
        cert_issuer=cert_to_check.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cert_issuer!= self.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
            return False, f"The certificate was not issue by this server, the issuer is {cert_issuer}"
        # verify cert signature
        self.load_key_file()
        #self.load_cert_file()
        if not util.verify_cert_signature(cert_to_check,self.rsa_private_key.public_key()):
            return False, "Wrong certificate signature"

        crl,builder=self.load_crl()
        ret = crl.get_revoked_certificate_by_serial_number(cert_to_check.serial_number)
        #if not revoke then add to revoke list
        if not isinstance(ret, x509.RevokedCertificate):  
            return False, 'Not revoke'
        else:
            return True, 'Already revoke'
        

    def get_public_key(self):
        self.load_key_file()
        return self.rsa_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,

                #SubjectPublicKeyInfo format
                #-----BEGIN PUBLIC KEY-----
                #-----END PUBLIC KEY-----
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

    #always return a cert, if dont have, crreate a new one
    def get_CA_cert(self):
        # if not os.path.isfile(f"{util.CA_data_path}{self.name}.crt"):
        #     return False,"No certificate file exist"
        self.load_cert_file()
        return True, self.ca_cert

    
    def create_CSR(self):
        self.load_key_file()
        csr = x509.CertificateSigningRequestBuilder().subject_name(self.issuer).add_extension(
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
    
    def save_cert(self,cert_public_byte):
        cert = x509.load_pem_x509_certificate(cert_public_byte)
        util.save_X509_cert(util.CA_data_path,self.name,cert)


    #for root server only
    def self_sign_cert(self):
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

    def delete_ca_key(self):
        # need remove  cert file too?, key is gone, why retain cert file
        try:
            print("try delete key file")
            os.remove(util.CA_data_path+self.name+".key")
            print("Key file deleted")
            #self.revocate_certificate()
        except  FileNotFoundError:
            return False, "Key file not found error"
        return True, "Success delete key file, will get new key on next request"

    def revoke_ca_cert(self):
        # if self.type == "root":
        #     return False,"Can't revoke root certificate"
        if self.top_CA_name is None:
            return False,"Can't revoke root certificate"
        
        if not os.path.isfile(f"{util.CA_data_path}{self.name}.crt"):
            return False,"No certificate file exist"
        self.load_cert_file()

        url=f"http://{self.top_CA_name}:80/revoke_cert"
        response = requests.post(url,files={'crt_file':self.ca_cert.public_bytes(serialization.Encoding.PEM)})
        if response.status_code ==200:
            #successfule revoke, deletecert file
            print("revoke ca cert success")
            try:
                print("try delete cert file")
                os.remove(util.CA_data_path+self.name+".crt")
                print("Cert file delete")
            except  FileNotFoundError:
                return False, "Cert file not found error"
            return True,"CA cert revoked, will get new cert on next request"
        return False,f"Error when revoke cert from {self.top_CA_name}, {response.content}"



        


    
        

        



    


        
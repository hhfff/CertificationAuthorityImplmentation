from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

password_for_save_key=b"E_*v\<@*6:CmTn+<[~Tr;73c)7ew*c**E*,&S#;!=AZ_t$P^_Hbdnzqa?cVW&V7%_nrZJhvrPT_HpsA='9-S[uPYpUeQ$Z_7["
filename_server_master_key="server_master_key.pem"

def save_pem_key_file(key,file_name,mode='wb',password=password_for_save_key):
    with open(file_name, mode) as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password_for_save_key),
        ))
def load_pem_key_file():
    pass

def generate_private_key(exponent=65537,key_size=2048):
    key=rsa.generate_private_key(public_exponent=exponent,key_size=key_size)
    return key

def generate_server_master_key(exponent,key_size):
    key=rsa.generate_private_key(exponent,key_size)
    #save master key to a file
    save_pem_key_file(key,filename_server_master_key)
    


# Information about our public key (including a signature of the entire body).
# Information about who we are.
# Information about what domains this certificate is for.
def certificate_signing_request():
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ntu"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ntu.com"),  #domain
    ]))
    csr.add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"mysite.com"),
            #x509.DNSName(u"www.mysite.com"),
            #x509.DNSName(u"subdomain.mysite.com"),
        ]),
        critical=False,
        
    )
    #load server rsa key, the key should be private key of owner, not server/CA key
    master_key_file_binary_data = open(f"{filename_server_master_key}", "rb")
    key=serialization.load_pem_private_key(data=master_key_file_binary_data,password=password_for_save_key)

    # Sign the CSR with our private key.
    csr.sign(key, hashes.SHA256())



key=generate_private_key()
print(key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL))
#generate_server_master_key(65537,2048)

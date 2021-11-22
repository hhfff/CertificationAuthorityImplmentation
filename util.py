
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding


# can use rsa private key to get public key, so only save private key
CA_data_path='./CA_data/'
client_data_path='./client_data/'


def generate_ras_key():
    return rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


#Write our key to disk for safe keeping
def save_rsa_private_key(dir,name,key):
    with open(f"{dir}{name}_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()    #dont want use password
            #encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),  #here is password  
        ))

def load_rsa_private_key(dir,name):
    key = open(f"{dir}{name}_key.pem", "rb")
    key=serialization.load_pem_private_key(data=key.read(),password=None)
    #key=serialization.load_pem_private_key(data=key.read(),password=b"passphrase")

    return key

def save_X509_cert(dir,name,cert):
    with open(f"{dir}{name}_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_X509_cert(dir,name):
    f=open(f"{dir}{name}_cert.pem","rb")
    cert = x509.load_pem_x509_certificate(f.read())
    return cert

def verify_cert_signature(cert, public_key):
    try:
        #if want to test, just change second argument to anything in byte, eg   b'ssss', if not valid, it raise exception
        public_key.verify(cert.signature,cert.tbs_certificate_bytes, padding.PKCS1v15(),cert.signature_hash_algorithm)
        return True
    except InvalidSignature:
        return False



#load key
#from cryptography.hazmat.primitives.serialization import load_pem_private_key
# from cryptography.hazmat.primitives import serialization

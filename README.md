# Motivation
Through this project, we hope to understand more about Certification Authority (CA), use case of digital certificates and also why is digital certificates an important pillar in the internet infrastructure today. 

Key objectives of this project:

- Background study on CA and digital certificates

- Building a X509 digital certificate that support certification and revocation of submitted public keys, and api for certificate verification

- Also supports Hierarchical Certificate Issue and Revocation, and public key generation

# Research
Certification Authority (CA) are credible entities that issues digital certificates. Digital certificates contains the identity of an entity online and this identity is validated by a CA. The role of a CA is important as it allows trusted transactions to happen on the internet. The easiest way for users to identify if they are visiting an official website is to look at the issued certificate of the particular website.

One of the widely used certificate is known as the X509 certificate. X509 certificate is a type of public key certificate where is links the information of an entity and public key using a digital signature. There are mainly two types of X509 certificate, a CA certificate and a end entity certificate. At the highest level is a Root CA certificate followed by one/many Intermediate CA certificate and ending with one/many end entity certificate. The Root CA certificate will first self-sign their own certificate before it issues one/many certificate to the Intermediate CA. The Intermediate CA after it gets the certificate from the Root CA/ other Intermediate CA, it can then issue certificates to end entity certificates/ other Intermediate CA. The end entity cannot issue certificates and can only request certificate from Intermediate CA.

When a entity wants a signed certificate, they have to request from a CA using a Certificate Signing Request (CSR). The entity have to first generate a private and public key pair. The entity will then use the private key to sign the CSR. The CSR contains the public key of the entity, entity information, Distinguished Name (DN) of the entity. Once the CA receives the CSR, it will then validate it using a Registration Authority (RA), this includes signing the certificate using the CA's private key. The CA then issues the signed certificate that has the entity's DN and public key and CA's DN.

![Chain Of Trust](https://upload.wikimedia.org/wikipedia/commons/0/02/Chain_Of_Trust.svg)
File:Chain Of Trust.svg - Wikimedia Commons. (2020). Retrieved 24 November 2021, from https://commons.wikimedia.org/wiki/File:Chain_Of_Trust.svg

# Design
The certificate authority use 3-tier hierarchy, there is a root CA and two levels of intermediate CAs, in which the lowest layer will issue certificate to end entities.

![Screenshot from 2021-11-24 12-12-43](https://user-images.githubusercontent.com/7097606/143174026-dfc7c921-7582-4cf2-82c8-0cfbc98232a7.png)

This project use docker-compose to deploy all server in a standalone machine, to mimic the actual server deployment, but we are using port instead of domain name. Each server  communicate to each other in the ca_network by using http://hostname:80. The hostname refer to ca_root, ca1  indicate in the image above. 


To get certificate, all client , include intermediate CA, must create certificate sign request(CSR) and sign with their private key. Usually, the certificate issue and revoke require staff to review , but here we just issue and revoke the cert when request.

**The intermediate CA will generate RSA key and get certificate from 1 level above when first time called, and save for later use. Only ca_root use self signed certificate when first time called.**

Intemediate server will get certificate from level above automaticatlly. The endpoint /revoke_ca_cert used by the intermediat CA to revoke it's certificate. Cert file deleted after revoke, but the server will get a new certficate at next request if cert file not found.


During testing, call the REST API using url http://127.0.0.1:**port**, the port is 8000 for ca_root, 8001 for ca1 and so on. Use http://127.0.0.1:8000/docs to get all API endpoint, all server has same API endpoints.

## File extension
All the encoding for file is PEM for storage and transmission, with their hostname as file name, eg ca1.key, ca1.crl,ca1.crt. 
- key: *.key
- certificate: *.crt
- certificate revocation list: *.crl

## Asymmetric algorithm 
For this demo, we using the RSA algorithm only, with public exponent=65537, key size=2048. But it is possible to change to others such as Elliptic curve, DSA, Ed25519,Ed448. Some of them are use for Diffie-Hellman key exchange.


# Development
These are the library we use, all specfic in requirtment.txt
- [pyca/cryptography](https://cryptography.io/en/latest/) for X.509 and all cryptography algorithm
- [FastAPI](https://fastapi.tiangolo.com/) with unicorn for REST endpoint
- [python-multipart](https://pypi.org/project/python-multipart/) for certificate and CSR upload to CA server
- [requests](https://docs.python-requests.org/en/latest/) for testing API endpoints in python code

This demo using the docker-compose to deploy the CA hierarchy in the image.



# Use of the code
## Project setup

### Create a virtual python and download necessary dependencies defne in requirement.txt, for local development and test
```
$ python3 -m venv venv/
$ source venv/bin/activate  
$ pip install -r requirement.txt
```
### (optional) To run the project if want local testing on your own server, only root server is created
```
$ uvicorn main:app
```

### Use swagger API for manually test
```
http://127.0.0.1:8000/docs
```
## Use docker to create CA servers
**Need install docker first**

In the projetc folder, build docker image using dockerfile, and create ca_network

**Make sure the folder CA_data doesn't contain any .key .crt and .crl file, if not, they will copy and use this file in docker instead to generate a new file**
```
$ docker build -t cav1 .
$ docker network create ca_network
```
Run all servers, define in docker-compose.yml

use ctl-c to stop.
```
$ docker-compose up 
```
delete the container if dont want it anymore or reset
```
$ docker-compose rm
```
delete docker image if have change in source code or want complete remove from own system
```
$ docker rmi cav1
```
check container status and use container uterminal
1. use docker ps to get container id or name
2. replace container-name with id or name
```
$ docker ps
$ docker exec -it container-name sh
```
### (optional) docker swarm, create multiple instance for each server
```
```
### Manually run each container 
run container using the builded image cav1

-p host:docker  port bind
```
$ docker run --name ca_root -e CA_NAME=root -e CA_TYPE=root -e CA_CUR_ENV=server -e CA_TOP_PORT=nil -p 8000:80 -d cav1:latest
$ docker run --name ca1 -e CA_NAME=ca1 -e CA_TYPE=intermediate -e CA_CUR_ENV=server -e CA_TOP_PORT=8000 -p 8001:80 -d cav1:latest
```

# Motivation
Certificate Authority (CA) verifies websites (and other entities) so that you know who you’re communicating with online


# Research

# Design
The certificate authority use 3-tier hierarchy, there is a root CA and two levels of intermediate CAs, in which the lowest layer will issue certificate to end entities.

![Screenshot from 2021-11-24 12-12-43](https://user-images.githubusercontent.com/7097606/143174026-dfc7c921-7582-4cf2-82c8-0cfbc98232a7.png)
This project use docker-compose to deploy all server in a standalone machine, to mimic the actual server deployment, but we are using port instead of domain name. Each server  communicate to each other in the ca_network by using http://hostname:80. The hostname refer to ca_root, ca1  indicate in the image above. 

**The intermediate CA will generate RSA key and get certificate from 1 level above when first time called, and save for later use. Only ca_root use self signed certificate when first time called.**

To get certificate, all client , include intermediate CA, must create certificate sign request(CSR) and sign with their private key. Usually, the certificate issue and revoke require staff to review , but here we just issue and revoke the cert once request.


During testing, call the REST API using url http://127.0.0.1:**port**, the port is 8000 for ca_root, 8001 for ca1 and so on. Use http://127.0.0.1:8000/docs to get all API endpoint, all server has same API endpoints.

## File extension
All the encoding for file is PEM for storage and transmission, with their hostname as file name, eg ca1.key, ca1.crl,ca1.crt. 
- key: *.key
- certificate: *.crt
- certificate revocation list: *.crl

## Asymmetric algorithm 
For this demo, we using the RSA algorithm only, with public exponent=65537, key size=2048. But it is possible to change to others such as Elliptic curve, DSA, Ed25519,Ed448, X25519, X448. Some of them are use for Diffie-Hellman key exchange.


# Development
These are the library we use, all specfic in requirtment.txt
- [pyca/cryptography](https://cryptography.io/en/latest/) for X.509 and all cryptography algorithm
- [FastAPI](https://fastapi.tiangolo.com/) with unicorn for REST endpoint
- [python-multipart](https://pypi.org/project/python-multipart/) for certificate and CSR upload to CA server
- [requests](https://docs.python-requests.org/en/latest/) for testing API endpoints in python code

Docker allow us build, share and run any app, anywhere



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

check container status and use container uterminal
1. use docker ps to get container id or name
2. replace container-name with id or name
```
$ docker ps
$ docker exec -it container-name sh
```
(optional) docker swarm, create multiple instance for each server
```
```
### Manually run each container 
run container using the builded image cav1

-p host:docker  port bind
```
$ docker run --name ca_root -e CA_NAME=root -e CA_TYPE=root -e CA_CUR_ENV=server -e CA_TOP_PORT=nil -p 8000:80 -d cav1:latest
$ docker run --name ca1 -e CA_NAME=ca1 -e CA_TYPE=intermediate -e CA_CUR_ENV=server -e CA_TOP_PORT=8000 -p 8001:80 -d cav1:latest
```

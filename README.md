# Description
Certificate Authority (CA) verifies websites (and other entities) so that you know who you’re communicating with online

# Project setup

### Create a virtual python and download necessary dependencies defne in requirement.txt
```
$ python3 -m venv venv/
$ source venv/bin/activate  
$ pip install -r requirement.txt
```
### To run the project
```
$ uvicorn main:app
```

### Use swagger API for manually test
```
http://127.0.0.1:8000/docs
```
### docker
In the projetc folder, build docker image using dockerfile, and create ca_network
```
$ docker build -t cav1 .
$ docker network create ca_network
```
Run the 2 server ca_root and ca1, define in docker-compose.yml   
use ctl-c to stop.
```
$ docker-compose up 

delete the container if dont want it anymore
```
$ docker-compose rm
```

check container status, 
1. use docker ps to get container id or name
2. replace container-name with id or name
```
$ docker ps
$ docker exec -it container-name sh
```
(optional)docker warm
```
```
#### manually run 
run container using the builded image
-p host:docker  port bind
```
$ docker run --name ca_root -e CA_NAME=root -e CA_TYPE=root -e CA_CUR_ENV=server -e CA_TOP_PORT=nil -p 8000:80 -d cav1:latest
$ docker run --name ca1 -e CA_NAME=ca1 -e CA_TYPE=intermediate -e CA_CUR_ENV=server -e CA_TOP_PORT=8000 -p 8001:80 -d cav1:latest
```



sudo docker build -t cav1 . && sudo docker run --name ca_root -e CA_NAME=root -e CA_TYPE=root -e CA_CUR_ENV=server -e CA_TOP_PORT=nil -p 8000:80 -d cav1:latest && sudo docker run --name ca1 -e CA_NAME=ca1 -e CA_TYPE=intermediate -e CA_CUR_ENV=server -e CA_TOP_PORT=8000 -p 8001:80 -d cav1:latest

sudo docker stop $(docker ps -a -q) && sudo docker rm $(docker ps -a -q) && sudo docker image rm cav1

sudo docker stop ca1 && sudo docker stop ca_root && sudo docker rm ca1 && sudo docker rm ca_root && sudo docker rmi cav1
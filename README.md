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



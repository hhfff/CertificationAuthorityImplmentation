#   uvicorn main:app --reload
from fastapi import FastAPI,File, UploadFile
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from CertificationAuthority import CertificationAuthority
from pydantic import BaseModel
from cryptography import exceptions, x509
from fastapi.encoders import jsonable_encoder
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization


CA_name="root"
CA_type="root"
app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/issue_cert")
async def issue_cert(csr_file: UploadFile = File(...)):
    #print(data.file.read())
    ca=CertificationAuthority(CA_name,type=CA_type)
    csr=x509.load_pem_x509_csr(csr_file.file.read())
    cert_data=ca.issue_certificate(csr)
    return PlainTextResponse(cert_data,media_type="text/plain")

    #return StreamingResponse(cert_data,media_type="text/plain")

@app.post("/revoke_cert")
async def revoke_cert(crt_file: UploadFile = File(...)):
    cert=x509.load_pem_x509_certificate(crt_file.file.read())
    ca=CertificationAuthority(CA_name,type=CA_type)
    result=ca.revocate_certificate(cert)
    if result:
        return JSONResponse(content={'msg':'success'},status_code=200)
    else:
        return JSONResponse(content={'msg':'Already revoke'},status_code=200)

@app.post("/revoke_cert_status",)
async def revoke_cert_status(crt_file: UploadFile = File(...)):
    cert=x509.load_pem_x509_certificate(crt_file.file.read())
    ca=CertificationAuthority(CA_name,type=CA_type)
    result=ca.check_certificate_revoke_status(cert)
    if result:
        return JSONResponse(content={'msg':'Already revoke'},status_code=200)
    else:
        return JSONResponse(content={'msg':'Not revoke'},status_code=200)


# todo havent test
@app.post("/get_CA_cert")
async def ca_cert():
    ca=CertificationAuthority(CA_name,type=CA_type)
    cert_data=ca.get_CA_cert().public_bytes(serialization.Encoding.PEM) #in bytes format
    return PlainTextResponse(cert_data,media_type="text/plain")

@app.post("/get_CA_public_key")
async def revoke_cert_status():
    ca=CertificationAuthority(CA_name,type=CA_type)

    #convert to bytes
    return PlainTextResponse(ca.get_public_key(),media_type="text/plain")
    



from fastapi import FastAPI

app = FastAPI(title="DevSecOps Demo API", version="1.0.0")

@app.get("/")
def home():
    return {"message": "DevSecOps demo API is running"}

@app.get("/health")
def health():
    return {"status": "ok"}

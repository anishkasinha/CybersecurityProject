from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import joblib

app = FastAPI(title="Cybersecurity Backend",
              description="Unified API for network intrusion and phishing detection")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Load models
try:
    network_model = joblib.load('networkAnalyser.pkl')
except Exception:
    network_model = None

try:
    phishing_model = joblib.load('phishing/phishing_model.pkl')
    phishing_vectorizer = joblib.load('phishing/tfidf_vectorizer.pkl')
except Exception:
    phishing_model = None
    phishing_vectorizer = None


class NetworkTraffic(BaseModel):
    dur: float = 0.0
    proto: str = "tcp"
    service: str = "http"
    state: str = "FIN"
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0
    rate: float = 0.0
    sttl: int = 64
    dttl: int = 64
    sload: float = 0.0
    dload: float = 0.0
    sloss: int = 0
    dloss: int = 0
    sinpkt: float = 0.0
    dinpkt: float = 0.0
    sjit: float = 0.0
    djit: float = 0.0
    swin: int = 0
    stcpb: int = 0
    dtcpb: int = 0
    dwin: int = 0
    tcprtt: float = 0.0
    synack: float = 0.0
    ackdat: float = 0.0
    smean: float = 0.0
    dmean: float = 0.0
    trans_depth: int = 0
    response_body_len: int = 0
    ct_srv_src: int = 0
    ct_state_ttl: int = 0
    ct_dst_ltm: int = 0
    ct_src_dport_ltm: int = 0
    ct_dst_sport_ltm: int = 0
    ct_dst_src_ltm: int = 0
    is_ftp_login: int = 0
    ct_ftp_cmd: int = 0
    ct_flw_http_mthd: int = 0
    ct_src_ltm: int = 0
    ct_srv_dst: int = 0
    is_sm_ips_ports: int = 0


class EmailRequest(BaseModel):
    email_text: str


@app.get("/")
def index():
    return {
        "message": "Cybersecurity backend running",
        "network_model_loaded": network_model is not None,
        "phishing_model_loaded": phishing_model is not None
    }


@app.get("/health")
def health():
    return {
        "network_model_loaded": network_model is not None,
        "phishing_model_loaded": phishing_model is not None
    }


@app.post("/network/predict")
def network_predict(traffic: NetworkTraffic):
    if network_model is None:
        raise HTTPException(status_code=500, detail="Network model not loaded")
    df = pd.DataFrame([traffic.dict()])
    pred = int(network_model.predict(df)[0])
    proba = network_model.predict_proba(df)[0]
    return {
        "prediction": pred,
        "probabilities": [float(x) for x in proba]
    }


@app.post("/phishing/predict")
def phishing_predict(req: EmailRequest):
    if phishing_model is None or phishing_vectorizer is None:
        raise HTTPException(status_code=500, detail="Phishing model not loaded")
    vect = phishing_vectorizer.transform([req.email_text])
    pred = int(phishing_model.predict(vect)[0])
    proba = phishing_model.predict_proba(vect)[0]
    return {
        "prediction": pred,
        "confidence": {
            "safe": float(proba[0]),
            "phishing": float(proba[1])
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

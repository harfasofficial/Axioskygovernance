from fastapi import FastAPI
import uvicorn

app = FastAPI()


@app.get("/watchlist/{customer_id}")
def check_watchlist(customer_id: str):
    return {"watchlist_result": customer_id == "CUST_BLACKLIST_001"}


@app.get("/credit/{customer_id}")
def get_credit_score(customer_id: str):
    scores = {
        "CUST_001": 750,
        "CUST_002": 620,
        "CUST_BLACKLIST_001": 300,
    }
    return {"credit_score": scores.get(customer_id, 700)}


@app.post("/escalation-webhook")
def receive_escalation(payload: dict):
    print(f"ESCALATION RECEIVED: {payload.get('escalation_id')}")
    print(f"Approve: {payload.get('approve_url')}")
    print(f"Reject: {payload.get('reject_url')}")
    print(f"Signature: {payload.get('headers', {}).get('X-Axiosky-Signature', 'NOT SIGNED')}")
    return {"received": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)  # nosec B104

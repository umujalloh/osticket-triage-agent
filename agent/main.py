from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/webhook/ticket")
async def receive_ticket(request: Request):
    payload = await request.json()
    print("Received ticket webhook:", payload)
    return {"status": "received"}

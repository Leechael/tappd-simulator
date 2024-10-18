from typing import Optional

import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel

from .quote import Quote


class VerificationResponse(BaseModel):
    success: bool
    quote: Optional[Quote] = None


app = FastAPI()

@app.get('/')
def home():
    return PlainTextResponse('hello world')


@app.post('/api/attestations/verify')
async def verify(file: UploadFile = File(...)):
    content = await file.read()
    succeed, quote = Quote.safeParse(content)
    record = VerificationResponse(success=succeed, quote=quote)
    return JSONResponse(content=record.dict())


async def main():
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

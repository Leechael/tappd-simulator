from typing import Optional

import uvicorn
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import crud
from .quote import Quote
from .database import get_db


class VerificationResponse(BaseModel):
    success: bool
    quote: Optional[Quote] = None
    checksum: Optional[str] = None


app = FastAPI()

@app.get('/')
def home():
    return PlainTextResponse('hello world')


@app.post('/api/attestations/verify')
async def verify(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    succeed, quote = Quote.safeParse(content)
    record = VerificationResponse(success=succeed, quote=quote)
    if record.success:
        row = crud.create_quote(db, quote)
        record.checksum = row.checksum
    return JSONResponse(content=record.dict())

@app.get('/api/attestations/recent')
async def recent(db: Session = Depends(get_db), skip: int = 0, limit: int = 20):
    rows = crud.get_quotes(db, skip, limit)
    return JSONResponse(content=[{
        "checksum": row.checksum,
        "created_at": row.created_at.isoformat(),
    } for row in rows])
    
@app.get('/api/attestations/view/{checksum}')
async def view(checksum: str, db: Session = Depends(get_db)):
    row = crud.get_quote(db, checksum)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    print(row.to_instance())
    return JSONResponse(content=row.to_instance().dict())

from typing import Optional

import uvicorn
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from . import crud
from .quote import Quote
from .database import get_db
from .verify import verify_quote_with_collateral


class VerificationResponse(BaseModel):
    success: bool
    quote: Optional[Quote] = None
    checksum: Optional[str] = None
    can_download: Optional[bool] = None
    uploaded_at: Optional[str] = None


app = FastAPI(root_path='/api/attestations')

@app.post('/verify')
async def verify(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    succeed, quote = Quote.safeParse(content)
    record = VerificationResponse(success=succeed, quote=quote)
    if record.success:
        quote.verified = verify_quote_with_collateral(content)
        row = crud.create_quote(db, quote)
        crud.save_raw_quote(db, row, content)
        record.checksum = row.checksum
    return JSONResponse(content=record.dict())

@app.get('/recent')
async def recent(db: Session = Depends(get_db), skip: int = 0, limit: int = 20):
    rows = crud.get_quotes(db, skip, limit)
    return JSONResponse(content=[{
        "checksum": row.checksum,
        "verified": row.verified,
        "created_at": row.created_at.isoformat(),
    } for row in rows])
    
@app.get('/view/{checksum}')
async def view(checksum: str, db: Session = Depends(get_db)):
    row = crud.get_quote(db, checksum)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    d = row.to_instance().dict()
    d['uploaded_at'] = row.created_at.isoformat()
    d['checksum'] = row.checksum
    d['can_download'] = row.has_raw_quote
    return JSONResponse(content=d)


@app.get('/raw/{checksum}')
async def get_raw(checksum: str, db: Session = Depends(get_db)):
    row = crud.get_raw_quote(db, checksum)
    if not row:
        raise HTTPException(status_code=404, detail='Not found')
    return Response(
        content=row.content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename={checksum}.bin",
            "Content-Length": str(len(row.content))
        }
    )

@app.head("/raw/{checksum}")
async def check_raw_file(checksum: str, db: Session = Depends(get_db)):
    row = crud.get_raw_quote(db, checksum)
    if not row:
        raise HTTPException(status_code=404, detail='Not found')
    return Response(
        content=None,
        headers={
            "Content-Length": str(len(row.content))
        }
    )


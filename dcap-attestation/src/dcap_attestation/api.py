from typing import Optional
import json

import asyncio
import httpx
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

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


class QuoteCollateralV3(BaseModel):
    tcb_info_issuer_chain: str
    tcb_info: str
    tcb_info_signature: str
    qe_identity_issuer_chain: str
    qe_identity: str
    qe_identity_signature: str


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

@app.get('/collateral/{checksum}')
async def get_collateral(checksum: str, db: Session = Depends(get_db)):
    row = crud.get_quote(db, checksum)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    quote = row.to_instance()

    async def get_tcb_from_fmspc(fmspc):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f'https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={fmspc}')
            tcb_info_issuer_chain = resp.headers.get('TCB-Info-Issuer-Chain')
            return (tcb_info_issuer_chain, resp.json())

    async def get_qe_identity():
        async with httpx.AsyncClient() as client:
            resp = await client.get('https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity')
            qe_identity_issuer_chain = resp.headers.get('SGX-Enclave-Identity-Issuer-Chain')
            return (qe_identity_issuer_chain, resp.json())

    ((tcb_info_issuer_chain, tcb_info), (qe_identity_issuer_chain, qe_identity)) = await asyncio.gather(
        get_tcb_from_fmspc(quote.certificate_chain[0].sgx_extensions.fmspc),
        get_qe_identity()
    )

    collateral = QuoteCollateralV3(
        tcb_info_issuer_chain=tcb_info_issuer_chain,
        tcb_info=json.dumps(tcb_info.get('tcbInfo')),
        tcb_info_signature=tcb_info.get('signature'),
        qe_identity_issuer_chain=qe_identity_issuer_chain,
        qe_identity=json.dumps(qe_identity.get('enclaveIdentity')),
        qe_identity_signature=qe_identity.get('signature'),
    )

    return JSONResponse(
        content=collateral.model_dump(),
        headers={
            'Cache-Control': 'public, max-age=86400',  # 1 day
        }
    )

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


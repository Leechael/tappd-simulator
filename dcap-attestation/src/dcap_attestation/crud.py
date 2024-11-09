from sqlalchemy.orm import Session
import hashlib
from . import models, quote as schemas

def create_quote(db: Session, quote: schemas.Quote):
    checksum = hashlib.sha256(str(quote.dict()).encode()).hexdigest()
    exists = db.query(models.QuoteModel).filter(models.QuoteModel.checksum == checksum).first()
    if exists:
        if exists.verified != quote.verified:
            exists.verified = quote.verified
            db.add(exists)
            db.commit()
            db.refresh(exists)
        return exists
    db_quote = models.QuoteModel(
        version=quote.header.version,
        ak_type=quote.header.ak_type.name,
        tee_type=quote.header.tee_type.name,
        qe_vendor=quote.header.qe_vendor,
        user_data=quote.header.user_data,
        tee_tcb_svn=quote.body.tee_tcb_svn,
        mrseam=quote.body.mrseam,
        mrsignerseam=quote.body.mrsignerseam,
        seamattributes=quote.body.seamattributes,
        tdattributes=quote.body.tdattributes,
        xfam=quote.body.xfam,
        mrtd=quote.body.mrtd,
        mrconfig=quote.body.mrconfig,
        mrowner=quote.body.mrowner,
        mrownerconfig=quote.body.mrownerconfig,
        rtmr0=quote.body.rtmr0,
        rtmr1=quote.body.rtmr1,
        rtmr2=quote.body.rtmr2,
        rtmr3=quote.body.rtmr3,
        reportdata=quote.body.reportdata,
        cert_data=quote.cert_data,
        verified=quote.verified
    )
    db_quote.checksum = checksum
    db.add(db_quote)
    db.commit()
    db.refresh(db_quote)
    return db_quote

def get_quote(db: Session, checksum: str):
    return db.query(models.QuoteModel).filter(models.QuoteModel.checksum == checksum).first()

def get_quotes(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.QuoteModel).order_by(models.QuoteModel.created_at.desc()).offset(skip).limit(limit).all()


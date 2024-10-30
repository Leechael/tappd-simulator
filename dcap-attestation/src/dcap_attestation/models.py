from sqlalchemy import Column, Integer, String, BLOB, DateTime, Enum, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import enum

from .quote import Quote, QuoteHeader, QuoteBody, AttestationKeyType as AKT, TeeType as TT

Base = declarative_base()

class AttestationKeyType(enum.Enum):
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_P384 = "ECDSA_P384"

    def to_instance(self):
        if self == AttestationKeyType.ECDSA_P256:
            return AKT.ECDSA_P256
        elif self == AttestationKeyType.ECDSA_P384:
            return AKT.ECDSA_P384

class TeeType(enum.Enum):
    TEE_TDX = "TDX"
    TEE_SGX = "SGX"

    def to_instance(self):
        if self == TeeType.TEE_TDX:
            return TT.TEE_TDX
        elif self == TeeType.TEE_SGX:
            return TT.TEE_SGX

class QuoteModel(Base):
    __tablename__ = "quotes"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(Integer)
    ak_type = Column(Enum(AttestationKeyType))
    tee_type = Column(Enum(TeeType))
    qe_vendor = Column(BLOB)
    user_data = Column(BLOB)
    tee_tcb_svn = Column(String)
    mrseam = Column(BLOB)
    mrsignerseam = Column(BLOB)
    seamattributes = Column(BLOB)
    tdattributes = Column(BLOB)
    xfam = Column(BLOB)
    mrtd = Column(BLOB)
    mrconfig = Column(BLOB)
    mrowner = Column(BLOB)
    mrownerconfig = Column(BLOB)
    rtmr0 = Column(BLOB)
    rtmr1 = Column(BLOB)
    rtmr2 = Column(BLOB)
    rtmr3 = Column(BLOB)
    reportdata = Column(BLOB)
    cert_data = Column(Text, nullable=True)
    checksum = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_instance(self):
        header = QuoteHeader(
            version=self.version,
            ak_type=self.ak_type.to_instance(),
            tee_type=self.tee_type.to_instance(),
            qe_vendor=self.qe_vendor,
            user_data=self.user_data,
        )
        body = QuoteBody(
            tee_tcb_svn=self.tee_tcb_svn,
            mrseam=self.mrseam,
            mrsignerseam=self.mrsignerseam,
            seamattributes=self.seamattributes,
            tdattributes=self.tdattributes,
            xfam=self.xfam,
            mrtd=self.mrtd,
            mrconfig=self.mrconfig,
            mrowner=self.mrowner,
            mrownerconfig=self.mrownerconfig,
            rtmr0=self.rtmr0,
            rtmr1=self.rtmr1,
            rtmr2=self.rtmr2,
            rtmr3=self.rtmr3,
            reportdata=self.reportdata,
        )
        return Quote(
            header=header,
            cert_data=self.cert_data,
            body=body
        )
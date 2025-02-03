from typing import Optional

from pydantic import BaseModel, field_serializer
from evidence_api.tdx.quote import TdxQuote, AttestationKeyType, TeeType

from .cert import parse_certificate_chain

"""
Wrap TdxQuote into Human-friendly & serializable object for Web
"""

class QuoteHeader(BaseModel):
    version: int
    ak_type: AttestationKeyType
    tee_type: TeeType
    qe_vendor: bytes
    user_data: bytes

    @field_serializer('ak_type', 'tee_type')
    def serialize_enum(self, value):
        return value.name

    @field_serializer('qe_vendor', 'user_data')
    def serialize_bytes(self, value):
        return '0x' + value.hex()


class QuoteBody(BaseModel):
    tee_tcb_svn: str
    mrseam: bytes
    mrsignerseam: bytes
    seamattributes: bytes
    tdattributes: bytes
    xfam: bytes
    mrtd: bytes
    mrconfig: bytes
    mrowner: bytes
    mrownerconfig: bytes
    rtmr0: bytes
    rtmr1: bytes
    rtmr2: bytes
    rtmr3: bytes
    reportdata: bytes

    @field_serializer('mrseam', 'mrsignerseam', 'seamattributes', 'tdattributes', 'xfam',
                      'mrtd', 'mrconfig', 'mrowner', 'mrownerconfig', 'rtmr0', 'rtmr1',
                      'rtmr2', 'rtmr3', 'reportdata')
    def serialize_bytes(self, value):
        return '0x' + value.hex()


class Quote(BaseModel):
    header: QuoteHeader
    cert_data: Optional[str]
    body: QuoteBody
    verified: Optional[bool] = False

    @staticmethod
    def safeParse(raw):
        try:
            tdxQuote = TdxQuote(raw)
            header = QuoteHeader(
                version=tdxQuote.header.ver,
                ak_type=tdxQuote.header.ak_type,
                tee_type=tdxQuote.header.tee_type,
                qe_vendor=tdxQuote.header.qe_vendor,
                user_data=tdxQuote.header.user_data,
            )
            try:
                cert_data = tdxQuote.sig.qe_cert.cert_data.qe_cert_data.cert_data
                if cert_data[-1] == 0:
                    cert_data = cert_data[:-1]
                cert_data = cert_data.decode('utf8')
            except:
                cert_data = None
            body = QuoteBody(
                tee_tcb_svn=tdxQuote.body.tee_tcb_svn.data.hex(),
                mrseam=tdxQuote.body.mrseam,
                mrsignerseam=tdxQuote.body.mrsignerseam,
                seamattributes=tdxQuote.body.seamattributes,
                tdattributes=tdxQuote.body.tdattributes,
                xfam=tdxQuote.body.xfam,
                mrtd=tdxQuote.body.mrtd,
                mrconfig=tdxQuote.body.mrconfig,
                mrowner=tdxQuote.body.mrowner,
                mrownerconfig=tdxQuote.body.mrownerconfig,
                rtmr0=tdxQuote.body.rtmr0,
                rtmr1=tdxQuote.body.rtmr1,
                rtmr2=tdxQuote.body.rtmr2,
                rtmr3=tdxQuote.body.rtmr3,
                reportdata=tdxQuote.body.reportdata
            )
            rec = Quote(
                header=header,
                cert_data=cert_data,
                body=body
            )
            return (True, rec)
        except Exception as err:
            print(err)
            return (False, None)

    @property
    def certificate_chain(self):
        return parse_certificate_chain(self.cert_data)
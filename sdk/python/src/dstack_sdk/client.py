from typing import Optional, List, Union
import json
import hashlib

from pydantic import BaseModel
import httpx


class DeriveKeyResponse(BaseModel):
    key: str
    certificate_chain: List[str]


class TdxQuoteResponse(BaseModel):
    quote: str
    event_log: str


def sha384_hex(input: Union[str, bytes]) -> str:
    if isinstance(input, str):
        input = input.encode()
    return hashlib.sha384(input).hexdigest()


class BaseClient:
    def __init__(self, socket_path: Optional[str] = '/var/run/tappd.sock'):
        self.socket_path = socket_path
        self.base_url = f"http://localhost"


class TappdClient(BaseClient):
    def __init__(self, socket_path: str = None):
        super().__init__(socket_path)
        self.transport = httpx.HTTPTransport(uds=socket_path)

    def _send_rpc_request(self, path, payload):
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            response = client.post(
                path,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

    def derive_key(self, path: str, subject: str) -> DeriveKeyResponse:
        result = self._send_rpc_request("/prpc/Tappd.DeriveKey", {"path": path, "subject": subject})
        return DeriveKeyResponse(**result)

    def tdx_quote(self, report_data: Union[str, bytes]) -> TdxQuoteResponse:
        result = self._send_rpc_request("/prpc/Tappd.TdxQuote", {"report_data": sha384_hex(report_data)})
        return TdxQuoteResponse(**result)


class AsyncTappdClient(BaseClient):
    def __init__(self, socket_path=None):
        super().__init__(socket_path)
        self.transport = httpx.AsyncHTTPTransport(uds=socket_path)

    async def _send_rpc_request(self, path, payload):
        async with httpx.AsyncClient(transport=self.transport, base_url=self.base_url) as client:
            response = await client.post(
                path,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

    async def derive_key(self, path: str, subject: str) -> DeriveKeyResponse:
        result = await self._send_rpc_request("/prpc/Tappd.DeriveKey", {"path": path, "subject": subject})
        return DeriveKeyResponse(**result)

    async def tdx_quote(self, report_data: Union[str, bytes]) -> TdxQuoteResponse:
        result = await self._send_rpc_request("/prpc/Tappd.TdxQuote", {"report_data": sha384_hex(report_data)})
        return TdxQuoteResponse(**result)

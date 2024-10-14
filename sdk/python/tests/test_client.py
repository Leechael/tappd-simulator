import pytest
from dstack_sdk import TappdClient, AsyncTappdClient

SOCKET_PATH = '../../tappd.sock'

def test_sync_client_derive_key():
    client = TappdClient(SOCKET_PATH)
    result = client.derive_key('/', 'test')
    assert 'key' in result
    assert 'certificate_chain' in result

def test_sync_client_tdx_quote():
    client = TappdClient(SOCKET_PATH)
    result = client.tdx_quote('test')
    assert 'quote' in result
    assert 'event_log' in result

@pytest.mark.asyncio
async def test_async_client_derive_key():
    client = AsyncTappdClient(SOCKET_PATH)
    result = await client.derive_key('/', 'test')
    assert 'key' in result
    assert 'certificate_chain' in result

@pytest.mark.asyncio
async def test_async_client_derive_key():
    client = AsyncTappdClient(SOCKET_PATH)
    result = await client.tdx_quote('test')
    assert 'quote' in result
    assert 'event_log' in result

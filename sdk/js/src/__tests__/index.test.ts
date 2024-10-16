import { expect, describe, it } from 'vitest'
import { TappdClient } from '../index'

describe('TappdClient', () => {
  it('should able to derive key', async () => {
    // const client = new TappdClient('../../tappd.sock')
    const client = new TappdClient('http://127.0.0.1:8090')
    const result = await client.deriveKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
  })

  it('should able to request tdx quote', async () => {
    // const client = new TappdClient('../../tappd.sock')
    const client = new TappdClient('http://127.0.0.1:8090')
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
  })
})

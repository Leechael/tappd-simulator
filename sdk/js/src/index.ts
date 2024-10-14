import net from 'net'
import crypto from 'crypto'

export interface DeriveKeyResponse {
  key: string
  certificate_chain: string[]
}

export type Hex = `0x${string}`

export interface TdxQuoteResponse {
  quote: Hex
  event_log: string
}

export function send_rpc_request<T = any>(socket_path: string, path: string, payload: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const abortController = new AbortController()
    const timeout = setTimeout(() => {
      abortController.abort()
      reject(new Error('Request timed out'))
    }, 30_000) // 30 seconds timeout

    const client = net.createConnection({ path: socket_path }, () => {
      client.write(`POST ${path} HTTP/1.1\r\n`)
      client.write(`Host: localhost\r\n`)
      client.write(`Content-Type: application/json\r\n`)
      client.write(`Content-Length: ${payload.length}\r\n`)
      client.write('\r\n')
      client.write(payload)
    })

    let data = ''
    let headers: Record<string, string> = {}
    let headersParsed = false
    let contentLength = 0
    let bodyData = ''

    client.on('data', (chunk) => {
      data += chunk
      if (!headersParsed) {
        const headerEndIndex = data.indexOf('\r\n\r\n')
        if (headerEndIndex !== -1) {
          const headerLines = data.slice(0, headerEndIndex).split('\r\n')
          headerLines.forEach(line => {
            const [key, value] = line.split(': ')
            if (key && value) {
              headers[key.toLowerCase()] = value
            }
          })
          headersParsed = true
          contentLength = parseInt(headers['content-length'] || '0', 10)
          bodyData = data.slice(headerEndIndex + 4)
        }
      } else {
        bodyData += chunk
      }

      if (headersParsed && bodyData.length >= contentLength) {
        client.end()
      }
    })

    client.on('end', () => {
      clearTimeout(timeout)
      try {
        const result = JSON.parse(bodyData.slice(0, contentLength))
        resolve(result as T)
      } catch (error) {
        reject(new Error('Failed to parse response'))
      }
    })

    client.on('error', (error) => {
      clearTimeout(timeout)
      reject(error)
    })

    abortController.signal.addEventListener('abort', () => {
      client.destroy()
      reject(new Error('Request aborted'))
    })
  })
}

export class TappdClient {
  private socketPath: string

  constructor(socketPath: string = '/var/run/tappd.sock') {
    this.socketPath = socketPath
  }

  async deriveKey(path: string, subject: string): Promise<DeriveKeyResponse> {
    const payload = JSON.stringify({ path, subject })
    const result = await send_rpc_request<DeriveKeyResponse>(this.socketPath, '/prpc/Tappd.DeriveKey', payload)
    return Object.freeze(result)
  }

  async tdxQuote(report_data: string | Buffer | Uint8Array): Promise<TdxQuoteResponse> {
    let hashInput: Buffer
    if (typeof report_data === 'string') {
      hashInput = Buffer.from(report_data)
    } else if (report_data instanceof Uint8Array) {
      hashInput = Buffer.from(report_data)
    } else {
      hashInput = report_data
    }
    const hash = crypto.createHash('sha384').update(hashInput).digest('hex')
    const payload = JSON.stringify({ report_data: `0x${hash}` })
    const result = await send_rpc_request<TdxQuoteResponse>(this.socketPath, '/prpc/Tappd.TdxQuote', payload)
    return Object.freeze(result)
  }
}

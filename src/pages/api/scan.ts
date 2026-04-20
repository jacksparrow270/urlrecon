import type { NextApiRequest, NextApiResponse } from 'next'
import http from 'node:http'
import https from 'node:https'
import tls from 'node:tls'

import type { ScanResult, Verdict } from '@/lib/types'

const SECURITY_HEADERS = [
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
]

const MAX_REDIRECTS = 10
const REQUEST_TIMEOUT_MS = 8000

type ApiResponse =
  | { results: ScanResult[] }
  | { error: string }

type ProbeResult = {
  statusCode: number | null
  finalUrl: string | null
  redirectChain: string[]
  responseTimeMs: number | null
  headers: Record<string, string | string[] | undefined>
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ApiResponse>,
) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'POST, OPTIONS')
    return res.status(204).end()
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS')
    return res.status(405).json({ error: 'POST only' })
  }

  try {
    const urls: unknown[] = Array.isArray(req.body?.urls) ? req.body.urls : []
    if (!urls.length) {
      return res.status(400).json({ error: 'No URLs provided' })
    }

    const results = await Promise.all(
      urls.slice(0, 10).map((url: unknown) => scanUrl(String(url))),
    )

    return res.status(200).json({ results })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    return res.status(500).json({ error: message })
  }
}

async function scanUrl(rawUrl: string): Promise<ScanResult> {
  const result: ScanResult = {
    url: rawUrl,
    valid: false,
    status_code: null,
    final_url: null,
    redirect_chain: [],
    response_time_ms: null,
    ssl_valid: null,
    ssl_days_left: null,
    ssl_issuer: null,
    missing_headers: [],
    present_headers: [],
    verdict: 'ERROR',
    error: null,
  }

  const validation = normalizeUrl(rawUrl)
  if (!validation.valid) {
    result.error = validation.error
    return result
  }

  result.valid = true
  result.url = validation.url

  try {
    const probe = await httpProbe(validation.url)
    result.status_code = probe.statusCode
    result.final_url = probe.finalUrl
    result.redirect_chain = probe.redirectChain
    result.response_time_ms = probe.responseTimeMs

    const headerNames = new Set(Object.keys(probe.headers).map((key) => key.toLowerCase()))
    for (const header of SECURITY_HEADERS) {
      if (headerNames.has(header.toLowerCase())) {
        result.present_headers.push(header)
      } else {
        result.missing_headers.push(header)
      }
    }

    if (result.final_url?.startsWith('https://')) {
      const sslInfo = await sslCheck(result.final_url)
      result.ssl_valid = sslInfo.sslValid
      result.ssl_days_left = sslInfo.sslDaysLeft
      result.ssl_issuer = sslInfo.sslIssuer
      if (sslInfo.error) {
        result.error = sslInfo.error
      }
    }

    result.verdict = classifyVerdict(result)
  } catch (error) {
    result.error = error instanceof Error ? error.message : 'Unknown error'
    result.verdict = 'ERROR'
  }

  return result
}

function normalizeUrl(raw: string) {
  const trimmed = raw.trim()
  if (!trimmed) {
    return { valid: false, url: trimmed, error: 'Empty URL' }
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`

  try {
    const parsed = new URL(candidate)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, url: candidate, error: `Unsupported scheme '${parsed.protocol.replace(':', '')}'` }
    }

    if (!parsed.hostname) {
      return { valid: false, url: candidate, error: 'Missing host' }
    }

    return { valid: true, url: parsed.toString(), error: null }
  } catch {
    return { valid: false, url: candidate, error: 'Malformed URL' }
  }
}

async function httpProbe(inputUrl: string): Promise<ProbeResult> {
  const redirectChain: string[] = []
  const start = Date.now()
  let currentUrl = inputUrl

  for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
    const response = await requestOnce(currentUrl)
    const statusCode = response.statusCode ?? null

    if (statusCode && statusCode >= 300 && statusCode < 400 && response.headers.location) {
      const nextUrl = new URL(response.headers.location, currentUrl).toString()
      redirectChain.push(currentUrl)
      currentUrl = nextUrl
      continue
    }

    return {
      statusCode,
      finalUrl: currentUrl,
      redirectChain,
      responseTimeMs: Number((Date.now() - start).toFixed(1)),
      headers: response.headers,
    }
  }

  throw new Error('Too many redirects')
}

function requestOnce(targetUrl: string): Promise<http.IncomingMessage> {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl)
    const client = url.protocol === 'https:' ? https : http

    const request = client.request(
      url,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'URLRecon/1.0 (security-scanner)',
        },
      },
      (response) => {
        response.resume()
        resolve(response)
      },
    )

    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error('Request timed out'))
    })

    request.on('error', reject)
    request.end()
  })
}

async function sslCheck(targetUrl: string) {
  const url = new URL(targetUrl)
  const host = url.hostname
  const port = url.port ? Number(url.port) : 443

  return new Promise<{
    sslValid: boolean | null
    sslDaysLeft: number | null
    sslIssuer: string | null
    error: string | null
  }>((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: true,
        timeout: REQUEST_TIMEOUT_MS,
      },
      () => {
        const cert = socket.getPeerCertificate()
        socket.end()

        if (!cert || !cert.valid_to) {
          resolve({
            sslValid: null,
            sslDaysLeft: null,
            sslIssuer: null,
            error: null,
          })
          return
        }

        const expiry = new Date(cert.valid_to)
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
        const issuerValue = typeof cert.issuer === 'object'
          ? cert.issuer.O ?? cert.issuer.CN ?? 'Unknown'
          : 'Unknown'
        const issuer = Array.isArray(issuerValue) ? issuerValue.join(', ') : issuerValue

        resolve({
          sslValid: daysLeft > 0,
          sslDaysLeft: daysLeft,
          sslIssuer: issuer,
          error: null,
        })
      },
    )

    socket.on('error', (error) => {
      resolve({
        sslValid: false,
        sslDaysLeft: null,
        sslIssuer: null,
        error: `SSL error: ${error.message}`,
      })
    })

    socket.on('timeout', () => {
      socket.destroy()
      resolve({
        sslValid: false,
        sslDaysLeft: null,
        sslIssuer: null,
        error: 'SSL error: Request timed out',
      })
    })
  })
}

function classifyVerdict(result: ScanResult): Verdict {
  if (result.status_code === null) {
    return 'ERROR'
  }

  let score = 0

  if (result.status_code >= 500) {
    score += 2
  } else if (result.status_code >= 400) {
    score += 1
  }

  if (result.ssl_valid === false) {
    score += 3
  } else if (result.ssl_days_left !== null && result.ssl_days_left < 30) {
    score += 2
  }

  score += result.missing_headers.length

  if (result.redirect_chain.length > 0 && result.final_url) {
    const originalHost = new URL(result.url).host
    const finalHost = new URL(result.final_url).host
    if (originalHost !== finalHost) {
      score += 2
    }
  }

  if (score === 0) {
    return 'CLEAN'
  }

  if (score <= 3) {
    return 'WARNING'
  }

  return 'CRITICAL'
}

export type Verdict = 'CLEAN' | 'WARNING' | 'CRITICAL' | 'ERROR' | 'UNKNOWN'

export interface ScanResult {
  url: string
  valid: boolean
  status_code: number | null
  final_url: string | null
  redirect_chain: string[]
  response_time_ms: number | null
  ssl_valid: boolean | null
  ssl_days_left: number | null
  ssl_issuer: string | null
  missing_headers: string[]
  present_headers: string[]
  verdict: Verdict
  error: string | null
}

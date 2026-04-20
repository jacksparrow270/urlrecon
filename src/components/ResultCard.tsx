import { useState } from 'react'
import type { ScanResult, Verdict } from '@/lib/types'
import styles from './ResultCard.module.css'

const VERDICT_CONFIG: Record<Verdict, { label: string; color: string; icon: string }> = {
  CLEAN:    { label: 'CLEAN',    color: 'var(--green)', icon: '◆' },
  WARNING:  { label: 'WARNING',  color: 'var(--amber)', icon: '▲' },
  CRITICAL: { label: 'CRITICAL', color: 'var(--red)',   icon: '✖' },
  ERROR:    { label: 'ERROR',    color: 'var(--red)',   icon: '✖' },
  UNKNOWN:  { label: 'UNKNOWN',  color: 'var(--text-dim)', icon: '?' },
}

function statusColor(code: number | null) {
  if (!code) return 'var(--text-dim)'
  if (code < 300) return 'var(--green)'
  if (code < 400) return 'var(--amber)'
  return 'var(--red)'
}

function certColor(days: number | null) {
  if (days === null) return 'var(--text-dim)'
  if (days < 0) return 'var(--red)'
  if (days < 30) return 'var(--amber)'
  return 'var(--green)'
}

interface Props {
  result: ScanResult
  index: number
}

export default function ResultCard({ result, index }: Props) {
  const [expanded, setExpanded] = useState(false)
  const verdict = VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.UNKNOWN
  const animDelay = `${index * 80}ms`

  return (
    <div
      className={styles.card}
      style={{ '--delay': animDelay, '--verdict-color': verdict.color } as React.CSSProperties}
    >
      {/* Header row */}
      <div className={styles.header} onClick={() => setExpanded(e => !e)}>
        <div className={styles.verdict} style={{ color: verdict.color }}>
          <span className={styles.verdictIcon}>{verdict.icon}</span>
          <span className={styles.verdictLabel}>{verdict.label}</span>
        </div>

        <div className={styles.url}>
          <span className={styles.urlText}>{result.url}</span>
          {result.final_url && result.final_url !== result.url && (
            <span className={styles.finalUrl}>→ {result.final_url}</span>
          )}
        </div>

        <div className={styles.metrics}>
          {result.status_code && (
            <span className={styles.metric} style={{ color: statusColor(result.status_code) }}>
              {result.status_code}
            </span>
          )}
          {result.ssl_valid !== null && (
            <span className={styles.metric} style={{ color: result.ssl_valid ? 'var(--green)' : 'var(--red)' }}>
              {result.ssl_valid ? 'TLS ✔' : 'TLS ✖'}
            </span>
          )}
          {result.ssl_days_left !== null && (
            <span className={styles.metric} style={{ color: certColor(result.ssl_days_left) }}>
              {result.ssl_days_left < 0 ? 'CERT EXPIRED' : `${result.ssl_days_left}d`}
            </span>
          )}
          {result.missing_headers.length > 0 && (
            <span className={styles.metric} style={{ color: 'var(--amber)' }}>
              {result.missing_headers.length} HDR
            </span>
          )}
          {result.response_time_ms && (
            <span className={styles.metric} style={{ color: 'var(--text-dim)' }}>
              {result.response_time_ms}ms
            </span>
          )}
        </div>

        <button className={styles.toggle}>
          {expanded ? '−' : '+'}
        </button>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className={styles.detail}>
          {result.error && (
            <div className={styles.detailSection}>
              <span className={styles.detailLabel}>ERROR</span>
              <span style={{ color: 'var(--red)' }}>{result.error}</span>
            </div>
          )}

          {result.redirect_chain.length > 0 && (
            <div className={styles.detailSection}>
              <span className={styles.detailLabel}>REDIRECT CHAIN</span>
              <div className={styles.chain}>
                {result.redirect_chain.map((url, i) => (
                  <span key={i}>{url}</span>
                ))}
                <span style={{ color: 'var(--cyan)' }}>↳ {result.final_url}</span>
              </div>
            </div>
          )}

          {result.ssl_issuer && (
            <div className={styles.detailSection}>
              <span className={styles.detailLabel}>ISSUER</span>
              <span>{result.ssl_issuer}</span>
            </div>
          )}

          {result.missing_headers.length > 0 && (
            <div className={styles.detailSection}>
              <span className={styles.detailLabel}>MISSING HEADERS</span>
              <div className={styles.headerList}>
                {result.missing_headers.map(h => (
                  <span key={h} className={styles.headerBadgeMissing}>{h}</span>
                ))}
              </div>
            </div>
          )}

          {result.present_headers.length > 0 && (
            <div className={styles.detailSection}>
              <span className={styles.detailLabel}>PRESENT HEADERS</span>
              <div className={styles.headerList}>
                {result.present_headers.map(h => (
                  <span key={h} className={styles.headerBadgePresent}>{h}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

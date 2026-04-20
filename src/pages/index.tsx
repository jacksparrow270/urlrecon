import { useEffect, useRef, useState } from 'react'
import Head from 'next/head'
import * as XLSX from 'xlsx'

import ResultCard from '@/components/ResultCard'
import type { ScanResult } from '@/lib/types'
import styles from '@/styles/Home.module.css'

const PLACEHOLDER = `https://example.com\nhttps://github.com\nhttps://yoursite.com`

const BOOT_LINES = [
  '> URLRECON v1.0 initialising...',
  '> loading probe modules... OK',
  '> TLS scanner ready',
  '> header inspector ready',
  '> awaiting target input_',
]

function createExportRows(results: ScanResult[]) {
  return results.map((result) => ({
    URL: result.url,
    Verdict: result.verdict,
    Valid: result.valid ? 'Yes' : 'No',
    'Status Code': result.status_code ?? '',
    'Final URL': result.final_url ?? '',
    'Response Time (ms)': result.response_time_ms ?? '',
    'SSL Valid': result.ssl_valid === null ? '' : result.ssl_valid ? 'Yes' : 'No',
    'SSL Days Left': result.ssl_days_left ?? '',
    'SSL Issuer': result.ssl_issuer ?? '',
    'Missing Headers Count': result.missing_headers.length,
    'Missing Headers': result.missing_headers.join(', '),
    'Present Headers': result.present_headers.join(', '),
    'Redirect Chain': result.redirect_chain.join(' -> '),
    Error: result.error ?? '',
  }))
}

export default function Home() {
  const [input, setInput] = useState('')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<ScanResult[]>([])
  const [error, setError] = useState<string | null>(null)
  const [bootLine, setBootLine] = useState(0)
  const [scanLog, setScanLog] = useState<string[]>([])
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (bootLine < BOOT_LINES.length) {
      const timeoutId = setTimeout(() => setBootLine((value) => value + 1), 280)
      return () => clearTimeout(timeoutId)
    }
  }, [bootLine])

  const parseUrls = (raw: string) =>
    raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))

  const addLog = (line: string) =>
    setScanLog((previous) => [...previous, `[${new Date().toISOString().slice(11, 19)}] ${line}`])

  const handleScan = async () => {
    const urls = parseUrls(input)
    if (!urls.length) return

    setScanning(true)
    setResults([])
    setError(null)
    setScanLog([])

    addLog(`initiating scan of ${urls.length} target(s)`)
    addLog('dispatching probe requests...')

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls }),
      })

      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(`Unexpected ${response.status} response from /api/scan`)
      }

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }

      addLog(`scan complete - ${data.results.length} result(s) received`)

      const sorted = [...data.results].sort((a: ScanResult, b: ScanResult) => {
        const order: Record<string, number> = { CRITICAL: 0, WARNING: 1, ERROR: 2, CLEAN: 3 }
        return (order[a.verdict] ?? 9) - (order[b.verdict] ?? 9)
      })

      setResults(sorted)

      const critical = sorted.filter((result) => result.verdict === 'CRITICAL').length
      const warning = sorted.filter((result) => result.verdict === 'WARNING').length
      const clean = sorted.filter((result) => result.verdict === 'CLEAN').length
      addLog(`verdict summary: ${critical} critical / ${warning} warning / ${clean} clean`)
    } catch (caughtError: unknown) {
      const message = caughtError instanceof Error ? caughtError.message : 'Unknown error'
      setError(message)
      addLog(`ERROR: ${message}`)
    } finally {
      setScanning(false)
    }
  }

  const handleDownloadExcel = () => {
    if (!results.length) return

    const worksheet = XLSX.utils.json_to_sheet(createExportRows(results))
    const workbook = XLSX.utils.book_new()

    XLSX.utils.book_append_sheet(workbook, worksheet, 'Scan Results')

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    XLSX.writeFile(workbook, `urlrecon-scan-results-${timestamp}.xlsx`)
  }

  const urlCount = parseUrls(input).length
  const hasResults = results.length > 0
  const critCount = results.filter((result) => result.verdict === 'CRITICAL').length
  const warnCount = results.filter((result) => result.verdict === 'WARNING').length
  const cleanCount = results.filter((result) => result.verdict === 'CLEAN').length

  return (
    <>
      <Head>
        <title>URLRecon - passive surface scanner</title>
      </Head>

      <div className={styles.page}>
        <header className={styles.header}>
          <div className={styles.logo}>
            <span className={styles.logoUrl}>URL</span>
            <span className={styles.logoRecon}>RECON</span>
            <span className={styles.logoBadge}>v1.0</span>
          </div>
          <p className={styles.tagline}>passive url surface scanner</p>
          <div className={styles.headerRule} />
        </header>

        <div className={styles.boot}>
          {BOOT_LINES.slice(0, bootLine).map((line, index) => (
            <div
              key={index}
              className={styles.bootLine}
              style={{ opacity: index < bootLine - 1 ? 0.4 : 1 }}
            >
              {line}
            </div>
          ))}
        </div>

        <main className={styles.main}>
          <div className={styles.inputPanel}>
            <div className={styles.panelHeader}>
              <span className={styles.panelTitle}>TARGET INPUT</span>
              <span className={styles.panelHint}>one URL per line - max 10</span>
            </div>

            <textarea
              ref={textareaRef}
              className={styles.textarea}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder={PLACEHOLDER}
              rows={5}
              spellCheck={false}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                  handleScan()
                }
              }}
            />

            <div className={styles.inputFooter}>
              <span className={styles.urlCount}>
                {urlCount > 0 ? `${urlCount} target${urlCount !== 1 ? 's' : ''} queued` : 'no targets'}
              </span>
              <div className={styles.actionGroup}>
                <button
                  type="button"
                  className={styles.downloadBtn}
                  onClick={handleDownloadExcel}
                  disabled={!hasResults}
                >
                  DOWNLOAD XLSX
                </button>
                <button
                  type="button"
                  className={styles.scanBtn}
                  onClick={handleScan}
                  disabled={scanning || urlCount === 0}
                >
                  {scanning ? <><span className={styles.spinner} />SCANNING...</> : <>INITIATE SCAN</>}
                </button>
              </div>
            </div>
          </div>

          {scanLog.length > 0 && (
            <div className={styles.logPanel}>
              {scanLog.map((line, index) => (
                <div key={index} className={styles.logLine}>
                  <span className={styles.logPrompt}>&gt;</span> {line}
                </div>
              ))}
            </div>
          )}

          {error && (
            <div className={styles.errorBox}>
              <span className={styles.errorIcon}>X</span>
              <span>{error}</span>
            </div>
          )}

          {hasResults && (
            <div className={styles.results}>
              <div className={styles.resultHeader}>
                <div className={styles.resultMeta}>
                  <span className={styles.panelTitle}>SCAN RESULTS</span>
                  <div className={styles.summary}>
                    {critCount > 0 && <span className={styles.sumCrit}>{critCount} CRITICAL</span>}
                    {warnCount > 0 && <span className={styles.sumWarn}>{warnCount} WARNING</span>}
                    {cleanCount > 0 && <span className={styles.sumClean}>{cleanCount} CLEAN</span>}
                  </div>
                </div>
              </div>

              {results.map((result, index) => (
                <ResultCard key={`${result.url}-${index}`} result={result} index={index} />
              ))}
            </div>
          )}
        </main>

        <footer className={styles.footer}>
          <span>URLRECON</span>
          <span className={styles.footerDim}>//</span>
          <span className={styles.footerDim}>passive scanner - no data stored - open source</span>
          <a
            href="https://github.com/jacksparrow270/urlrecon"
            target="_blank"
            rel="noopener noreferrer"
            className={styles.footerLink}
          >
            github
          </a>
        </footer>
      </div>
    </>
  )
}

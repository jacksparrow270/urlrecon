import { useState, useRef, useEffect } from 'react'
import Head from 'next/head'
import type { ScanResult } from '@/lib/types'
import ResultCard from '@/components/ResultCard'
import styles from '@/styles/Home.module.css'

const PLACEHOLDER = `https://example.com\nhttps://github.com\nhttps://yoursite.com`

const BOOT_LINES = [
  '> URLRECON v1.0 initialising...',
  '> loading probe modules... OK',
  '> TLS scanner ready',
  '> header inspector ready',
  '> awaiting target input_',
]

export default function Home() {
  const [input, setInput] = useState('')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<ScanResult[]>([])
  const [error, setError] = useState<string | null>(null)
  const [bootLine, setBootLine] = useState(0)
  const [scanLog, setScanLog] = useState<string[]>([])
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Boot animation
  useEffect(() => {
    if (bootLine < BOOT_LINES.length) {
      const t = setTimeout(() => setBootLine(b => b + 1), 280)
      return () => clearTimeout(t)
    }
  }, [bootLine])

  const parseUrls = (raw: string) =>
    raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))

  const addLog = (line: string) =>
    setScanLog(prev => [...prev, `[${new Date().toISOString().slice(11,19)}] ${line}`])

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
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls }),
      })

      const contentType = res.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(`Unexpected ${res.status} response from /api/scan`)
      }

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || `HTTP ${res.status}`)
      }

      const data = await res.json()
      addLog(`scan complete — ${data.results.length} result(s) received`)

      const sorted = [...data.results].sort((a, b) => {
        const order: Record<string, number> = { CRITICAL: 0, WARNING: 1, ERROR: 2, CLEAN: 3 }
        return (order[a.verdict] ?? 9) - (order[b.verdict] ?? 9)
      })

      setResults(sorted)

      const critical = sorted.filter(r => r.verdict === 'CRITICAL').length
      const warning  = sorted.filter(r => r.verdict === 'WARNING').length
      const clean    = sorted.filter(r => r.verdict === 'CLEAN').length
      addLog(`verdict summary: ${critical} critical / ${warning} warning / ${clean} clean`)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      setError(msg)
      addLog(`ERROR: ${msg}`)
    } finally {
      setScanning(false)
    }
  }

  const urlCount = parseUrls(input).length
  const hasResults = results.length > 0
  const critCount = results.filter(r => r.verdict === 'CRITICAL').length
  const warnCount = results.filter(r => r.verdict === 'WARNING').length
  const cleanCount = results.filter(r => r.verdict === 'CLEAN').length

  return (
    <>
      <Head>
        <title>URLRecon — passive surface scanner</title>
      </Head>

      <div className={styles.page}>
        {/* Header */}
        <header className={styles.header}>
          <div className={styles.logo}>
            <span className={styles.logoUrl}>URL</span>
            <span className={styles.logoRecon}>RECON</span>
            <span className={styles.logoBadge}>v1.0</span>
          </div>
          <p className={styles.tagline}>passive url surface scanner</p>
          <div className={styles.headerRule} />
        </header>

        {/* Boot terminal */}
        <div className={styles.boot}>
          {BOOT_LINES.slice(0, bootLine).map((line, i) => (
            <div key={i} className={styles.bootLine}
              style={{ opacity: i < bootLine - 1 ? 0.4 : 1 }}>
              {line}
            </div>
          ))}
        </div>

        {/* Main panel */}
        <main className={styles.main}>
          <div className={styles.inputPanel}>
            <div className={styles.panelHeader}>
              <span className={styles.panelTitle}>TARGET INPUT</span>
              <span className={styles.panelHint}>one URL per line · max 10</span>
            </div>

            <textarea
              ref={textareaRef}
              className={styles.textarea}
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={PLACEHOLDER}
              rows={5}
              spellCheck={false}
              onKeyDown={e => {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) handleScan()
              }}
            />

            <div className={styles.inputFooter}>
              <span className={styles.urlCount}>
                {urlCount > 0 ? `${urlCount} target${urlCount !== 1 ? 's' : ''} queued` : 'no targets'}
              </span>
              <button
                className={styles.scanBtn}
                onClick={handleScan}
                disabled={scanning || urlCount === 0}
              >
                {scanning
                  ? <><span className={styles.spinner} />SCANNING...</>
                  : <>◆ INITIATE SCAN</>
                }
              </button>
            </div>
          </div>

          {/* Scan log */}
          {scanLog.length > 0 && (
            <div className={styles.logPanel}>
              {scanLog.map((line, i) => (
                <div key={i} className={styles.logLine}>
                  <span className={styles.logPrompt}>&gt;</span> {line}
                </div>
              ))}
            </div>
          )}

          {/* Error */}
          {error && (
            <div className={styles.errorBox}>
              <span className={styles.errorIcon}>✖</span>
              <span>{error}</span>
            </div>
          )}

          {/* Results */}
          {hasResults && (
            <div className={styles.results}>
              <div className={styles.resultHeader}>
                <span className={styles.panelTitle}>SCAN RESULTS</span>
                <div className={styles.summary}>
                  {critCount > 0 && <span className={styles.sumCrit}>{critCount} CRITICAL</span>}
                  {warnCount > 0 && <span className={styles.sumWarn}>{warnCount} WARNING</span>}
                  {cleanCount > 0 && <span className={styles.sumClean}>{cleanCount} CLEAN</span>}
                </div>
              </div>

              {results.map((r, i) => (
                <ResultCard key={r.url + i} result={r} index={i} />
              ))}
            </div>
          )}
        </main>

        {/* Footer */}
        <footer className={styles.footer}>
          <span>URLRECON</span>
          <span className={styles.footerDim}>//</span>
          <span className={styles.footerDim}>passive scanner · no data stored · open source</span>
          <a
            href="https://github.com/yourusername/urlrecon"
            target="_blank"
            rel="noopener noreferrer"
            className={styles.footerLink}
          >
            github ↗
          </a>
        </footer>
      </div>
    </>
  )
}

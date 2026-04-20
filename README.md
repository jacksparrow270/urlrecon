# URLRecon

> Passive URL surface scanner — check HTTP status, TLS certificates, and security headers from the browser.

![URLRecon](https://img.shields.io/badge/status-live-00ff88?style=flat-square&labelColor=030a0f)
![Vercel](https://img.shields.io/badge/deployed-vercel-cyan?style=flat-square&labelColor=030a0f)

## What it does

Paste one or more URLs, hit scan. For each target it checks:

- **HTTP status** — live, redirect, client error, server error
- **Redirect chain** — full chain from original URL to final destination, cross-domain hops flagged
- **TLS/SSL** — certificate validity, days until expiry
- **Security headers** — audits for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- **Verdict** — `CLEAN`, `WARNING`, `CRITICAL`, or `ERROR` based on weighted scoring

## Stack

| Layer    | Tech                              |
|----------|-----------------------------------|
| Frontend | Next.js 14 + TypeScript           |
| API      | Python serverless (Vercel runtime)|
| Hosting  | Vercel                            |

## Local development

```bash
# Install JS dependencies
npm install

# Run dev server
npm run dev
```

The Python API runs as Vercel serverless functions. To test the API locally, use the Vercel CLI:

```bash
npm i -g vercel
vercel dev
```

## Deploy to Vercel

1. Push this repo to GitHub
2. Go to [vercel.com](https://vercel.com) → **Add New Project**
3. Import your GitHub repo
4. Vercel auto-detects Next.js — no config needed
5. Click **Deploy**

## Project structure

```
urlrecon/
├── api/
│   └── scan.py          # Python serverless scan endpoint
├── src/
│   ├── components/
│   │   ├── ResultCard.tsx
│   │   └── ResultCard.module.css
│   ├── lib/
│   │   └── types.ts
│   ├── pages/
│   │   ├── _app.tsx
│   │   ├── _document.tsx
│   │   └── index.tsx
│   └── styles/
│       ├── globals.css
│       └── Home.module.css
├── public/
├── requirements.txt     # Python deps for Vercel
├── vercel.json
├── next.config.js
├── tsconfig.json
└── package.json
```

## Verdict scoring

| Finding                        | Score |
|-------------------------------|-------|
| SSL certificate invalid        | +3    |
| Cross-domain redirect          | +2    |
| Cert expiring < 30 days        | +2    |
| 5xx server error               | +2    |
| Each missing security header   | +1    |
| 4xx client error               | +1    |

- **0** → CLEAN
- **1–3** → WARNING
- **4+** → CRITICAL

## License

MIT

# XSS Vulnerability Scanner

A Python tool that scans web pages for Cross-Site Scripting (XSS), injects payloads, and then actually **confirms** whether they execute in a real browser instead of trusting a plain string match.

## Why this exists

Most basic XSS scanners just check whether an injected payload comes back unescaped in the response and call that a "vulnerability." That produces a lot of false positives — a payload can reflect back completely harmless (wrong context, CSP blocking it, no special characters to escape in the first place).

This tool goes a step further: every candidate hit gets replayed in a real headless browser (via Playwright), and it's only reported as confirmed if an actual `alert()` fires.

## Installation

```bash
pip install requests beautifulsoup4 playwright pyfiglet
playwright install chromium
```

`pyfiglet` is only used for the startup banner — the tool works fine without it, just with a simpler banner.

## Basic usage

```bash
python3 xss_scanner.py http://target.com
python3 xss_scanner.py http://target.com --verify-dom
```

## All options

### Target & output

| Option | What it does |
|---|---|
| `url` | The target to scan. Required, always the first argument. |
| `--output`, `-o FILE` | Save the full report to a file instead of only printing the short summary. |
| `--format`, `-f {text,json}` | Report format when saved with `--output`. Default: `text`. |
| `--verbose`, `-v` | Show the full step-by-step detail (forms found, framework/CSP detection, payload-by-payload results table) instead of the short default output. |

### Scanning behavior

| Option | What it does |
|---|---|
| `--verify-dom` | The main feature: after the normal string-match scan, replay every candidate in a real headless browser and only report it if an `alert()` actually fires. Without this flag, the tool only does string-matching and never opens a browser. |
| `--dom-debug` | Shows a live, in-place-updating progress line while `--verify-dom` runs (`X/Y tested`), plus per-step detail (which field got filled, which button got clicked). Useful when a scan looks stuck or comes back empty and you want to see what it actually tried. |
| `--show-browser` | Opens a real, visible Chromium window instead of running headless, so you can watch the automation click and type in real time. Meant for debugging — pairs well with `--dom-debug`. |
| `--parallel` | Runs the HTTP-based checks (forms, URL params, stored-XSS, WAF detection) concurrently instead of one after another. Doesn't affect `--verify-dom`, which is always parallelized internally. |
| `--depth N` | How many links deep the crawler follows from the starting URL. Default: `1`. |
| `--max-payloads N` | Caps how many payloads get tried per injection point. Default: `20`. |
| `--detect-framework` | Sniffs the page for React/Vue/Angular and adds framework-specific payloads (template injection, `dangerouslySetInnerHTML` patterns, etc.) on top of the generic set. |
| `--no-csp` | Skips Content-Security-Policy analysis. By default the tool checks whether a detected CSP would block a payload before counting it as a real finding. |
| `--no-stored` | Skips the stored-XSS persistence check (submitting a payload, then checking with a fresh session whether it's still there). |

### Authentication

| Option | What it does |
|---|---|
| `--cookies "name=value; name2=value2"` | Import cookies directly — e.g. ones you copied out of your browser's dev tools. Lets the scanner test pages that require being logged in. |
| `--headers "Header1: value1, Header2: value2"` | Import custom request headers (e.g. a bearer token). |
| `--login-url URL` | Log in automatically before scanning. Must be used together with `--username` and `--password`. |
| `--username NAME` | Username for `--login-url`. |
| `--password PASS` | Password for `--login-url`. |
| `--clear-session` | Wipes any saved cookies/login state and exits without scanning. |
| `--session-file PATH` | Where session data gets saved between runs. Default: `scanner_session.pkl`. |

### Cosmetic

| Option | What it does |
|---|---|
| `--name TEXT` | Text shown in the big startup banner. Default: `IDENT`. |
| `--no-banner` | Skips the startup banner entirely. |

## What the output looks like

Default (quiet) mode:

```
[*] target: localhost:3000
[+] XSS: <img src=x onerror=alert('DOMXSS')>
[+] XSS: <iframe src="javascript:alert('DOMXSS')">
2 hits. 31 payloads. 31.6s.
```

`--verbose` shows every payload tried and whether it worked; `--dom-debug` shows a live progress line and per-step interaction detail while `--verify-dom` runs.

## Tested against

This wasn't built once and left alone — it was tested against three different real, intentionally-vulnerable targets, and every one exposed real bugs that had to be found and fixed:

- **[Google's XSS Game](https://xss-game.appspot.com/)** — used to build and verify the core payload set. Different levels needed genuinely different techniques: a single-quote attribute breakout, a JS-string-context breakout, a click-triggered link hijack, and a script-loader bypass using a `data:` URI.
- **[DVWA](https://github.com/digininja/DVWA)** — exposed a false-positive bug where the bot-detector flagged every page as CAPTCHA-protected (DVWA has an unrelated menu item literally called "Insecure CAPTCHA"), and a false-negative bug where the browser-verification step was silently checking pages while logged out, missing real vulnerabilities that were actually there.
- **[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** — a modern single-page app. Its search bug lives in a URL parameter hidden inside a hash-based route (`#/search?q=...`), which standard URL parsing can't see at all — had to add hash-fragment-aware parameter parsing to catch it. Also needed logic to reveal collapsed search boxes (icon-only until clicked) before the fill step could find the real input.

## Known limitations

- Only scans the single URL you give it — the crawler discovers other pages but doesn't currently test them
- Angular/Vue-specific payload wrapping can break on payloads that contain unescaped quotes
- Stored-XSS persistence checking uses a fresh, unauthenticated session, so it can miss anything that requires being logged in to view
- Framework detection can misidentify Vue vs. Angular on pages that share generic templating syntax
- No header-injection or file-upload-based XSS testing — only form fields, URL/hash parameters, and clickable links

## Legal

Only run this against targets you own or are explicitly authorized to test. Unauthorized scanning is illegal in most jurisdictions. Google's XSS Game, DVWA, and OWASP Juice Shop are all built specifically for this kind of testing.

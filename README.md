# PhishLens

An offline phishing email analyzer. Feed it a raw `.eml` file and it returns a 0-100 risk score, a plain-English explanation of every finding, and a visual HTML report. Nothing is sent over the network, so it is safe to run on suspicious emails.

## Quick start

```bash
python phishlens.py samples/phish_paypal.eml -o report.html   # needs Python 3.10+, no dependencies
python -m unittest                                            # run the tests
```

Open `report.html` in a browser. See `examples/phish_report.html` for a finished one.

## What it checks

| Area | Examples |
|---|---|
| Email authentication | SPF, DKIM and DMARC results from `Authentication-Results` |
| Sender identity | Reply-To / Return-Path mismatch, lookalike domains (`paypa1.com`), brand names in the display name |
| Links | Link text that doesn't match the real destination, raw IP links, URL shorteners, punycode, lookalike link domains |
| Language | Urgency pressure and credential-harvesting phrases |
| Attachments | Executable or macro files, double extensions like `invoice.pdf.exe` |
| Delivery path | The `Received` hops, oldest first |

Each finding adds points by severity (high, medium, low). The total is capped at 100: 70+ likely phishing, 40-69 suspicious, 15-39 low risk.

## How to get a raw .eml

Gmail: open the message, three-dot menu, "Download message". Outlook: drag the message to your desktop.

## Limitations

This is a heuristic tool for learning and triage, not a replacement for a mail security gateway. Brand matching uses a small built-in list, and results depend on the headers your mail server adds.

## Ideas to extend

Add more brands, check attachment hashes against a local list, add a batch mode for a folder of emails, or export findings as STIX.

# leakchex

Bulk breach lookup for email addresses against the [LeakCheck.io](https://leakcheck.io) Pro API (v2).

Feed it a list of addresses, get back a readable report of which ones appear in known data breaches, which sources they came from, and what fields were exposed. Pure Python standard library — no dependencies, no virtualenv, no `pip install`.

## Features

- **Bulk lookups** from a plain-text file, one address per line
- **Automatic input hygiene** — deduplicates, lowercases, skips comments and malformed lines
- **Rate-limit aware** — configurable delay plus exponential backoff on HTTP 429 and 5xx
- **Resilient** — retries transient network failures, fails fast on a bad key or exhausted quota
- **Incremental output** — the report is flushed as results arrive, so a `Ctrl-C` still leaves you a usable partial report
- **Machine-readable option** — `-j` dumps the raw API responses as JSON for further processing
- **Quota reporting** — shows remaining API credits in the summary

## Requirements

- Python 3.8 or newer
- A LeakCheck.io **Pro** API key ([leakcheck.io](https://leakcheck.io)) — the v2 query endpoint used here is not available on the free tier

## Installation

```bash
git clone https://github.com/sheimo/leakchex.git
cd leakchex
chmod +x leakchex.py
```

## Configuring your API key

The key is never stored in the script. It is resolved in this order:

1. `-k` / `--key` command-line argument
2. `LEAKCHECK_API_KEY` environment variable
3. `~/.leakcheck_key` — first line of the file

The environment variable or key file are recommended, since a key passed on the command line is visible in your shell history and in the process list.

```bash
# Option A: environment variable
export LEAKCHECK_API_KEY="your-api-key-here"

# Option B: key file
printf '%s\n' "your-api-key-here" > ~/.leakcheck_key
chmod 600 ~/.leakcheck_key
```

## Usage

```bash
python3 leakchex.py -i emails.list -o report.txt
```

Copy `emails.list.example` to get started:

```bash
cp emails.list.example emails.list
```

### Options

| Flag | Description |
| --- | --- |
| `-i`, `--input` | **Required.** File containing one email address per line |
| `-o`, `--output` | **Required.** Path for the human-readable report |
| `-k`, `--key` | API key (overrides the environment variable and key file) |
| `-j`, `--json FILE` | Also write the raw JSON API responses to `FILE` |
| `-r`, `--rate SECONDS` | Delay between requests (default `0.4`; Pro allows roughly 3 req/s) |
| `--clean-only` | Also list the addresses with no breach hits in the report summary |
| `-q`, `--quiet` | Suppress per-address progress output on the console |

### Examples

```bash
# Standard run
python3 leakchex.py -i emails.list -o report.txt

# Keep the raw JSON for later analysis
python3 leakchex.py -i emails.list -o report.txt -j results.json

# Slow it down and stay quiet, for a large list
python3 leakchex.py -i emails.list -o report.txt -r 1.0 -q

# Include clean addresses in the summary
python3 leakchex.py -i emails.list -o report.txt --clean-only
```

## Input format

```
# Comments and blank lines are ignored
alice@example.com
bob@example.org
BOB@EXAMPLE.ORG      # deduplicated against the line above
```

Surrounding quotes are stripped, addresses are lowercased, and anything that does not look like an email address is reported as skipped rather than sent to the API.

## Output

Progress is written to stderr as the run proceeds:

```
[*] Checking 3 unique address(es)...
[1/3] alice@example.com                     BREACHED (4)
[2/3] bob@example.org                       clean
[3/3] carol@example.net                     BREACHED (1)
```

The report file contains a block per breached address, followed by a summary:

```
========================================================================
[+] alice@example.com  --  4 record(s)
========================================================================
    1. ExampleForum  (2019-08)
       email           : alice@example.com
       username        : alice
       password        : ******
       ip              : 198.51.100.24
    2. SampleShop  (2021-03) [unverified]
       email           : alice@example.com
       fields          : email, password

========================================================================
SUMMARY
========================================================================
  checked : 3 / 3
  breached: 2
  clean   : 1
  errors  : 0
  quota remaining: 4931
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Run completed (including runs where individual lookups errored) |
| `1` | Startup problem — missing API key, missing input file, or no valid addresses |
| `2` | Fatal API error — invalid/expired key or exhausted quota |

## Handling the output safely

Reports contain plaintext credentials and personal data recovered from breaches. Treat them as sensitive:

- The included `.gitignore` excludes `*.list`, `*.output.txt`, and other likely report names — **verify your own filenames are covered before committing**
- Store reports on encrypted media and delete them when the engagement ends
- Never commit your API key, an input list, or a generated report

## Legal and ethical use

This tool is intended for **authorized** use only: checking your own accounts, monitoring addresses within your own organization, or breach exposure assessment during an engagement you have written permission to perform.

Querying third-party email addresses without authorization may violate privacy law (including the GDPR and CCPA), computer misuse law, and LeakCheck.io's terms of service. You are responsible for ensuring you have a lawful basis for every address you look up. The authors accept no liability for misuse.

## Contributing

Issues and pull requests are welcome. Please keep the script dependency-free — the standard library only.

## License

[MIT](LICENSE)

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by LeakCheck.io.

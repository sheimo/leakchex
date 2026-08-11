#!/usr/bin/env python3
"""
leakchex.py - bulk breach lookup against the LeakCheck.io Pro API (v2).

Usage:
    python3 leakchex.py -i emails.list -o leakchex.output.txt

API key resolution order:
    1. -k / --key argument
    2. LEAKCHECK_API_KEY environment variable
    3. ~/.leakcheck_key  (first line of the file)

Never hardcode your key in this file - it is tracked by git.

Stdlib only - no pip install required.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://leakcheck.io/api/v2/query/"
DEFAULT_RATE = 0.4          # seconds between requests (Pro allows ~3 req/s)
MAX_RETRIES = 4
TIMEOUT = 30

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def eprint(*a):
    print(*a, file=sys.stderr, flush=True)


def load_key(cli_key):
    if cli_key:
        return cli_key.strip()
    env = os.environ.get("LEAKCHECK_API_KEY")
    if env:
        return env.strip()
    path = os.path.expanduser("~/.leakcheck_key")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            line = fh.readline().strip()
            if line:
                return line
    return None


def load_targets(path):
    """Read the input file, dedupe while preserving order, drop junk."""
    seen, out, bad = set(), [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip().strip('"').strip("'")
            if not line or line.startswith("#"):
                continue
            line = line.lower()
            if not EMAIL_RE.match(line):
                bad.append(line)
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
    return out, bad


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

def query(email, api_key, verbose=False):
    """
    Returns (status, payload):
      status: "ok" | "notfound" | "error"
      payload: dict on ok, error string otherwise
    """
    url = API_URL + urllib.parse.quote(email, safe="") + "?type=email"
    req = urllib.request.Request(url, headers={
        "X-API-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "leakchex/1.0",
    })

    delay = 2
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
            if body.get("success"):
                return "ok", body
            # success:false -> "Not found" is the normal negative result
            err = str(body.get("error", "unknown error"))
            if "not found" in err.lower():
                return "notfound", body
            return "error", err

        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                body = json.loads(raw)
            except ValueError:
                body = {}
            err = str(body.get("error", raw[:200] or e.reason))

            if e.code == 404 or "not found" in err.lower():
                return "notfound", body
            if e.code == 429:
                if verbose:
                    eprint(f"  [!] rate limited, sleeping {delay}s")
                time.sleep(delay)
                delay *= 2
                continue
            low = err.lower()
            if e.code in (401, 403) or "api-key" in low or "api key" in low:
                return "fatal", f"HTTP {e.code}: {err} (bad, expired, or missing API key)"
            if "limit" in low and "reach" in low:      # quota exhausted
                return "fatal", f"HTTP {e.code}: {err}"
            if e.code >= 500:
                time.sleep(delay)
                delay *= 2
                continue
            return "error", f"HTTP {e.code}: {err}"

        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            if attempt == MAX_RETRIES:
                return "error", f"network/parse error: {e}"
            time.sleep(delay)
            delay *= 2

    return "error", "max retries exceeded"


# --------------------------------------------------------------------------- #
# formatting
# --------------------------------------------------------------------------- #

def format_hit(email, body):
    lines = []
    results = body.get("result") or []
    lines.append("=" * 72)
    lines.append(f"[+] {email}  --  {body.get('found', len(results))} record(s)")
    lines.append("=" * 72)

    for i, rec in enumerate(results, 1):
        src = rec.get("source") or {}
        name = src.get("name", "unknown")
        date = src.get("breach_date") or "unknown date"
        tags = []
        if src.get("unverified"):
            tags.append("unverified")
        if src.get("passwordless"):
            tags.append("passwordless")
        if src.get("compilation"):
            tags.append("compilation")
        tag = f" [{', '.join(tags)}]" if tags else ""

        lines.append(f"  {i:>3}. {name}  ({date}){tag}")

        for field in ("email", "username", "password", "hashed_password",
                      "phone", "name", "first_name", "last_name", "dob",
                      "address", "ip", "country", "origin"):
            val = rec.get(field)
            if val in (None, "", []):
                continue
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            lines.append(f"       {field:<16}: {val}")

        fields = rec.get("fields")
        if fields:
            lines.append(f"       {'fields':<16}: {', '.join(fields)}")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Bulk-check a list of emails against the LeakCheck.io Pro API.")
    ap.add_argument("-i", "--input", required=True, help="file with one email per line")
    ap.add_argument("-o", "--output", required=True, help="output report file")
    ap.add_argument("-k", "--key", help="LeakCheck API key (else env LEAKCHECK_API_KEY or ~/.leakcheck_key)")
    ap.add_argument("-j", "--json", metavar="FILE", help="also write raw JSON results here")
    ap.add_argument("-r", "--rate", type=float, default=DEFAULT_RATE,
                    help=f"seconds to sleep between requests (default {DEFAULT_RATE})")
    ap.add_argument("--clean-only", action="store_true",
                    help="also list emails with no breaches in the report")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress per-email console output")
    args = ap.parse_args()

    api_key = load_key(args.key)
    if not api_key:
        eprint("[!] No API key. Use -k, set $LEAKCHECK_API_KEY, "
               "or write it to ~/.leakcheck_key")
        sys.exit(1)

    if not os.path.isfile(args.input):
        eprint(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    targets, bad = load_targets(args.input)
    if bad:
        eprint(f"[!] Skipped {len(bad)} malformed line(s), e.g. {bad[:3]}")
    if not targets:
        eprint("[!] No valid email addresses in input.")
        sys.exit(1)

    eprint(f"[*] Checking {len(targets)} unique address(es)...")

    breached, clean, errors = [], [], []
    raw_results = {}
    quota = None
    total = len(targets)

    out = open(args.output, "w", encoding="utf-8")
    out.write("LeakCheck.io bulk breach report\n")
    out.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    out.write(f"Input: {args.input}   ({total} unique addresses)\n\n")
    out.flush()

    try:
        for n, email in enumerate(targets, 1):
            status, payload = query(email, api_key, verbose=not args.quiet)

            if status == "fatal":
                eprint(f"[!] {payload}")
                sys.exit(2)

            if status == "ok":
                found = payload.get("found", len(payload.get("result") or []))
                if payload.get("quota") is not None:
                    quota = payload["quota"]
                if found:
                    breached.append((email, found))
                    raw_results[email] = payload
                    out.write(format_hit(email, payload))
                    out.flush()
                    if not args.quiet:
                        eprint(f"[{n}/{total}] {email:<40} BREACHED ({found})")
                else:
                    clean.append(email)
                    if not args.quiet:
                        eprint(f"[{n}/{total}] {email:<40} clean")
            elif status == "notfound":
                clean.append(email)
                if not args.quiet:
                    eprint(f"[{n}/{total}] {email:<40} clean")
            else:
                errors.append((email, payload))
                if not args.quiet:
                    eprint(f"[{n}/{total}] {email:<40} ERROR: {payload}")

            if n < total:
                time.sleep(args.rate)

    except KeyboardInterrupt:
        eprint("\n[!] Interrupted - writing partial report.")

    # ---- summary -------------------------------------------------------- #
    summary = []
    summary.append("=" * 72)
    summary.append("SUMMARY")
    summary.append("=" * 72)
    summary.append(f"  checked : {len(breached) + len(clean) + len(errors)} / {total}")
    summary.append(f"  breached: {len(breached)}")
    summary.append(f"  clean   : {len(clean)}")
    summary.append(f"  errors  : {len(errors)}")
    if quota is not None:
        summary.append(f"  quota remaining: {quota}")
    summary.append("")

    if breached:
        summary.append("Breached addresses (records):")
        for email, cnt in sorted(breached, key=lambda x: -x[1]):
            summary.append(f"  {email:<45} {cnt}")
        summary.append("")

    if args.clean_only and clean:
        summary.append("Clean addresses:")
        summary.extend(f"  {e}" for e in clean)
        summary.append("")

    if errors:
        summary.append("Errors:")
        summary.extend(f"  {e}: {msg}" for e, msg in errors)
        summary.append("")

    text = "\n".join(summary)
    out.write(text)
    out.close()
    eprint("\n" + text)
    eprint(f"[*] Report written to {args.output}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(raw_results, fh, indent=2, ensure_ascii=False)
        eprint(f"[*] Raw JSON written to {args.json}")


if __name__ == "__main__":
    main()

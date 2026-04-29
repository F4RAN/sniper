# Sniper

`sniper` checks whether a domain can complete a TLS handshake from your network.

`sniper` resolves the domain, tries every returned IP for each configured port, and considers a port **allowed** when one IP completes TLS on that port.

## Quick Start

Check one domain:

```bash
sniper google.com
```

Check many domains from a file:

```bash
sniper -f domains.txt
```

Example `domains.txt`:

```text
google.com
hcaptcha.com
letsencrypt.org
```

Show blocked domains too:

```bash
sniper -f domains.txt -verbose
```

## What The Result Means

Example:

```text
google.com                     142.250.185.46     210ms allowed
```

This means:

- `google.com` is the domain you tested
- `142.250.185.46` is the IP that worked
- `210ms` is how long it took
- `allowed` means the TCP connection and TLS handshake worked

If it says `blocked`, the TCP connection or TLS handshake did not work.

## Common Examples

Check one domain with a shorter timeout:

```bash
sniper google.com -timeout 1s
```

Save results to a file:

```bash
sniper -f domains.txt -output results.txt
```

Probe several ports at once (comma-separated; overrides `-port` when set):

```bash
sniper -f domains.txt -ports 443,2053,8443
```

Use a shorter timeout:

```bash
sniper google.com -target 1.1.1.1
```

Check a list of domains on one specific IP:

```bash
sniper -f domains.txt -target 1.1.1.1
```

Check a list of domains on many IPs from a file:

```bash
sniper -f domains.txt -target-file ips.txt
```

Use a different HTTPS port:

```bash
sniper google.com -port 8443
```

## Main Flags

- `sniper google.com`
  Check one domain directly

- `-f domains.txt`
  Check many domains from a file

- `-verbose`
  Also print blocked domains

- `-timeout 1s`
  Change how long sniper waits before giving up

- `-output results.txt`
  Save result lines to a file

- `-f string` input file with domains, one per line
- `-port int` TLS port when `-ports` is not set, default `443`
- `-ports string` comma-separated TLS ports (e.g. `443,2053`); when set, replaces `-port`
- `-timeout duration` per DNS lookup, TCP dial, and TLS handshake timeout, default `2s`
- `-output string` write result lines to a file
- `-workers int` number of concurrent workers, default `200`
- `-verbose` include domains where every port failed (see Output)
- `-retries int` retries per IP on failure, default `0`
- `-q` hide start and completion logs
- `-target string` override DNS and probe one IP for every domain
- `-target-file string` override DNS and probe IPs from a file for every domain

## Output

- One line per domain (first occurrence order in the file). Each line shows IP, max successful handshake latency (or `-` if none), then each port as `443 ✓` or `443 ✗` (Unicode marks; colored when stdout is a TTY).
- By default, domains with **no** successful port are omitted; pass `-verbose` to list those too.

Probing uses **TCP connect + TLS** (not ICMP ping).

## Notes

- If a domain resolves to multiple IPs, `sniper` tries all of them.
- If `-target` or `-target-file` is set, `sniper` skips DNS and uses those IPs instead.
- A port is counted as allowed if any resolved IP completes TLS on that port (see counts in the completion log).
- `-timeout` is per attempt, not a total cap for the whole domain.
- Result lines go to stdout, or to the file passed with `-output`.
- Start, completion, and error logs are written to stderr.

# PHP2Shell

A command-line tool for detecting CVE-2026-109618 and CVE-2026-109619 in PHP applications.

## How It Works

The scanner sends a minimal multipart control request followed by up to three crafted multipart probes. The probes use PHP array keys nested 62 levels deep and increase from 1 MiB to 20 MiB, matching the detection logic used by Assetnote's internal scanner.

A target is reported vulnerable when the probe produces a PHP memory-exhaustion error, a differential empty HTTP 500, a PHP-FPM worker failure, or an advertised PHP version known to be unpatched. Initial 5xx responses, common request-rejection statuses, and nonempty HTTP 500 responses without the PHP fatal-error signature are not treated as crash signals.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved, and `--path` or `--path-file` can test custom paths. phpMyAdmin targets are automatically retested at `/show_config_errors.php`. Redirects are not followed unless `--follow-redirects` is set.

### SAPI Modes

The default `--sapi auto` mode applies both mod_php and PHP-FPM verdict rules, matching the combined behavior of Assetnote's postmodules. Use `--sapi mod_php` or `--sapi fpm` to restrict detection to a known SAPI.

### Network Impact

Each tested path may receive a 42-byte control request and three probes totalling about 29 MiB. Probing stops as soon as the verdict is settled, and duplicate input URLs are scanned once.

## Requirements

- Python 3.9+
- h11
- tqdm

## Installation

```
pip install -r requirements.txt
```

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Scan a custom path:

```
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Use only PHP-FPM verdict rules:

```
python3 scanner.py -u https://example.com --sapi fpm
```

## Options

```
-u, --url         Single URL to check
-l, --list        File containing hosts (one per line)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 60)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable hosts
-k, --insecure    Disable TLS certificate verification
--follow-redirects Follow HTTP redirects (up to 10 hops)
-H, --header      Custom header (can be used multiple times)
-v, --verbose     Show verdict reasons and response snippets
-q, --quiet       Only output vulnerable hosts
--no-color        Disable colored output
--sapi            Verdict rules: auto, mod_php, or fpm (1default: auto)
--path            Custom path to test (can be used multiple times)
--path-file       File containing paths to test (one per line)
```

## Credits

The first, original discovery of php2shell is attributed to the Calif team. You can read their write up here: [https://calif.io/php2shell/](https://calif.io/php2shell/).

The scanner was built by the Assetnote Security Research Team using logic built for [Searchlight's Exposure Platform](https://www.slcyber.io/exposure).

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence.

## Limitations

On specific PHP configurations, the scanner may report a false positive when its multipart probe exceeds PHP's `memory_limit`. Patched and vulnerable versions can then return the same empty HTTP 500 response.

This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

When PHP does not disclose its version, the scanner cannot distinguish this safe post-patch OOM from the vulnerable pre-patch behavior. Results should therefore be verified against the installed PHP version and any vendor backports

## Exploits

Three RCE exploits (Chains A, B, C) are included in [`exploit/`](exploit/):

| File | Chain | What It Does |
|------|-------|-------------|
| `chain_a_session_lfi.py` | A | Injects PHP code via upload filename → LFI includes session file → RCE |
| `chain_b_uaf_rce.php` | B | var_destroy UAF → discovers `zif_system` via EG() → overwrites `var_dump` handler via `/proc/self/mem` → RCE |
| `chain_c_mismatch_rce.py` | C | Pollutes FPM worker `PS(serializer)` → injects serialized object via filename → `__destruct` fires on decode failure → RCE |

Chains D and E exploits are available to [paid subscribers](https://qideng.substack.com/p/php2shell-dissecting-phps-critical).

```bash
# Chain A: Session injection + LFI → RCE
python3 exploit/chain_a_session_lfi.py --host TARGET --port 80 --command 'id'

# Chain B: var_destroy UAF → RCE (run on target or via uploaded webshell)
php exploit/chain_b_uaf_rce.php

# Chain C: Handler mismatch → __destruct → RCE
python3 exploit/chain_c_mismatch_rce.py --host TARGET --port 80 --command 'id'
```

## Detection Rules

Pre-built IDS / WAF / SIEM rules in [`detection/`](detection/):

| File | Format | Signatures |
|------|--------|-----------|
| `php2shell.rules` | Suricata / Snort | 13 rules — request, response, and recon |
| `php2shell.yaml` | Sigma | 5 rules — web logs, process creation, file events |
| `modsecurity.conf` | ModSecurity v2/v3 | 7 rules — drop-in for Apache/Nginx |
| `php2shell.lua` | OpenResty Lua | Lightweight reverse proxy module |

**Fastest mitigation:** block `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST bodies. Near-zero legitimate use, covers the primary attack vector for both CVEs.

## Mitigation

```ini
; Immediate — reduces attack surface
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

> **The only complete fix is patching PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+. The OOM corruption (Chain D) is in the Zend engine core — no INI setting fixes it.

For legacy / EOL environments (PHP 5.4–8.1) where upstream provides no official security updates, community-maintained backports with deployment automation and verification tooling are available at [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches).

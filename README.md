# redpent-tools

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![mcp](https://img.shields.io/badge/MCP-server-6E56CF.svg)

A **Model Context Protocol (MCP) server** that wraps a reconnaissance / web-security CLI
toolset (nmap, sqlmap, commix, subfinder, httpx, ffuf, nikto, tls, WHOIS/DNS/email-auth,
crt.sh, theHarvester, wayback, Shodan/Censys, …) as **safe, scope-gated, audited** tools an
AI agent can call. It runs as a persistent **HTTP MCP service** (API-key protected, Docker
out of the box) and plugs straight into **[RedPentAI](#add-it-to-redpentai)** or any MCP client.

> ⚠️ **AUTHORIZED assessments only.** Active scanners stay disabled until you declare scope +
> an authorization window in `scope.yaml`. Every target is scope-checked and every run is
> recorded. Do not point it at systems you are not explicitly permitted to test.

It keeps three lanes — **PASSIVE → BOUNDARY → ACTIVE** — and enforces the authorization gates
*in code*, not just in docs. **Every tool run is recorded** (JSONL audit trail + `SESSION.md`).

## Quickstart (Docker)

```bash
git clone https://github.com/<owner>/redpent-tools.git && cd redpent-tools
docker compose up -d --build
docker compose logs redpent-tools     # copy the auto-generated API key: rpk_…
# → service at http://localhost:8971/mcp  (header  X-API-Key: rpk_…)
```

Then add it to RedPentAI (or any MCP client) — see [Add it to RedPentAI](#add-it-to-redpentai).

## Lanes & tools

| Lane | Tools |
|------|-------|
| **Passive** | `whois_lookup`, `dns_lookup`, `email_auth_check`, `reverse_dns`, `crtsh_subdomains`, `subfinder_enum`, `harvester_enum`, `wayback_urls`, `shodan_host`, `shodan_search`, `censys_search` |
| **Boundary** (light touch) | `httpx_probe`, `http_headers`, `waf_detect`, `tls_scan`, `tech_fingerprint`, `favicon_hash`, `takeover_check` |
| **Active** (gated) | `nmap_scan`, `masscan_scan`, `ffuf_fuzz`, `nikto_scan`, `sqlmap_scan`, `commix_scan` |
| **Utility** | `scope_check`, `get_scope`, `merge_assets`, `session_log`, `recon_report` |

Resources: `scope://current`, `evidence://<engagement_id>/index`, `sop://checklist`.
Prompt: `passive_recon_flow(domain)`.

## Safety model (enforced in code)

1. **`scope.yaml` is the contract.** `out_of_scope` always wins. Hostnames are resolved
   and their IPs are checked against `out_of_scope` too.
2. **Active tools** (`nmap`/`masscan`/`ffuf`/`nikto`) run only when *all* hold:
   `active_allowed: true`, current time inside `active_window`, caller passes
   `confirm_authorized=true`, and `engagement_id` matches the scope. Any failure returns a
   clear error naming the failed gate — and is audited as `blocked`.
3. **Clamps:** `masscan --rate ≤ masscan_max_rate`, `ffuf -t ≤ ffuf_max_threads`,
   `nmap -T ≤ nmap_max_timing`. Intrusive NSE categories (`brute/dos/intrusive/exploit/vuln`)
   are refused unless `allow_intrusive_nse: true`.
4. **CDN/cloud protection:** CDN IPs are flagged; direct scanning of a CDN netblock IP is
   refused (scan the in-scope hostname instead).
5. **Strict input validation:** domain/IP/CIDR/port regexes; wordlists must live inside the
   allowed wordlists dir; no arbitrary flags ever reach a subprocess; never `shell=True`.
6. **No secrets leak:** API keys live in env vars; tool output is secret-masked before it is
   returned or written to evidence.
7. **Takeover is DETECT-ONLY** — the server never claims a dangling resource.

## Install

### Recommended: one command (installs the app **and** its CLI tools)

```bash
./bootstrap.sh            # venv + Python package + all CLI tools for this OS
./bootstrap.sh --passive  # ... passive + boundary tools only
```

`bootstrap.sh` creates `.venv`, installs the package, then installs the recon CLI tools
(`nmap`, `subfinder`, `httpx`, `ffuf`, `theHarvester`, …) using the right package manager
for your OS. After it finishes the whole application and its tools are ready.

Equivalent via make: `make install` then `make tools` (or just `make tools` to (re)install
tools into an existing install).

### How "tools install with the project" works

- The package exposes a console command **`redpent-tools-install`** (`[all|--passive|--check]`)
  that installs (or checks) the CLI tools for the current OS.
- `setup.py` registers a best-effort post-install hook, so a legacy
  `python setup.py install` / `pip install .` also triggers the tool install.
- **Note:** a modern `pip install -e .` uses the PEP 517 build backend, which does **not**
  run setup.py hooks — so `bootstrap.sh` (or `redpent-tools-install`) is the reliable path and
  is what the docs above use. Set `REDPENT_SKIP_TOOL_INSTALL=1` to opt out.

### Manual: Python package, then CLI tools

```bash
pip install -e .                 # or: pip install -r requirements.txt
redpent-tools-install all            # OS-aware tool install (same as ./install.sh)
redpent-tools-install --check        # report which tools are present/missing
```

The underlying OS-aware scripts can also be run directly:

```bash
./install.sh            # macOS / Linux (brew / apt / dnf / pacman / apk + go install)
./install.sh --check
.\install.ps1           # Windows (winget / choco / scoop + go install)
```

If Go tools aren't on PATH: `export PATH="$PATH:${GOBIN:-$HOME/go/bin}"` (the server also
resolves them from `$GOBIN`/`~/go/bin` automatically).

### Or just use Docker (all tools preinstalled, Kali base)

```bash
docker build -t redpent-tools .
docker run --rm -i \
  -v "$PWD/scope.yaml:/app/scope.yaml:ro" \
  -v "$PWD/evidence:/app/evidence" redpent-tools
```

## Configure an engagement

```bash
cp scope.example.yaml scope.yaml
$EDITOR scope.yaml          # set engagement_id, in/out scope, active_allowed, window
```

Start with `active_allowed: false`. Flip it to `true` (and set `active_window`) only once
the RoE for that engagement covers active testing — per SOP §1.5 / Appendix U.

Environment variables:

| Var | Purpose |
|-----|---------|
| `REDPENT_SCOPE_FILE` | path to scope.yaml (default `./scope.yaml`) |
| `REDPENT_EVIDENCE_DIR` | evidence root (default `./evidence`) |
| `REDPENT_WORDLISTS_DIR` | allowed wordlists dir (default `./wordlists`) |
| `SHODAN_API_KEY` | Shodan tools |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys search |

## Run

```bash
python -m redpent_tools.server            # stdio (Claude Desktop / Claude Code)
python -m redpent_tools.server --http     # streamable HTTP on 127.0.0.1:8971
./run.sh                                  # HTTP service (reads ./scope.yaml)
```

## Run as a persistent HTTP MCP service with an API key (Docker)

This is the "separate entity" mode RedPentAI integrates with. The Docker image **auto-generates
an API key on first start**, persists it to a volume, and prints it to the logs:

```bash
docker build -t redpent-tools .
docker run -d --name redpent-tools -p 8971:8971 \
  -v "$PWD/scope.yaml:/app/scope.yaml:ro" \
  -v redpent-data:/data -v "$PWD/evidence:/app/evidence" redpent-tools
docker logs redpent-tools          # <-- copy the printed  rpk_…  API key
```

- The key is generated by `redpent-tools-keygen` and saved at `/data/redpent-api-key` (stable
  across restarts). Supply your own with `-e REDPENT_API_KEY=rpk_…` to skip generation.
- The service then **requires** that key on every `/mcp` request (`X-API-Key: rpk_…` or
  `Authorization: Bearer rpk_…`); requests without it get `401`.
- Running on the host instead? Set `REDPENT_API_KEY` yourself (`redpent-tools-keygen` prints one)
  before `./run.sh`; with no key set, the host service runs **unauthenticated** (bind to
  127.0.0.1 only).

### Add it to RedPentAI

In RedPentAI → **System → MCP → Add server** (or the **RedPent Tools** preset):

- **transport:** `http`
- **url:** `http://localhost:8971/mcp`
- **env (sent as request headers):** `X-API-Key=rpk_…` (the key from `docker logs`)

Save → **Refresh tools** → the 29 tools appear. RedPentAI now calls the running service over
HTTP (authenticated) and the tools serve each request back.

## Troubleshooting "No tools discovered"

An MCP client discovers tools by **starting** the server and asking it to list them. If the
client shows no tools:

1. **Command not found.** The client must be able to launch the server. Either install it so
   `redpent-tools` is on PATH (`pipx install /path/to/redpent-tools`) **or** point the client at the
   absolute path, e.g. `…/redpent-tools/.venv/bin/redpent-tools`. A bare `redpent-tools` fails if the
   client's process PATH doesn't include your venv/`~/.local/bin`.
2. **Scope file.** The server starts even with no `scope.yaml` (it runs UNCONFIGURED and still
   lists all tools), but set `REDPENT_SCOPE_FILE` to a real scope so tools actually run against
   targets. A missing file only prints a stderr warning — it never blocks discovery.
3. Verify from a shell:
   `REDPENT_SCOPE_FILE=/abs/scope.yaml /abs/.venv/bin/redpent-tools` should start without a traceback.

## Register with Claude Code / Claude Desktop

Add to your MCP config (`~/.claude.json` / `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "redpent-tools": {
      "command": "python",
      "args": ["-m", "redpent_tools.server"],
      "cwd": "/path/to/redpent-tool",
      "env": {
        "REDPENT_SCOPE_FILE": "/path/to/redpent-tool/scope.yaml",
        "REDPENT_EVIDENCE_DIR": "/path/to/redpent-tool/evidence",
        "SHODAN_API_KEY": "",
        "CENSYS_API_ID": "",
        "CENSYS_API_SECRET": ""
      }
    }
  }
}
```

Or via the CLI:

```bash
claude mcp add redpent-tools -- python -m redpent_tools.server
# (run from the repo dir, or add --env REDPENT_SCOPE_FILE=/abs/path/scope.yaml)
```

Docker variant:

```json
{ "mcpServers": { "redpent-tools": {
  "command": "docker",
  "args": ["run","--rm","-i",
           "-v","/abs/scope.yaml:/app/scope.yaml:ro",
           "-v","/abs/evidence:/app/evidence","redpent-tools"]
}}}
```

## Evidence & audit layout

```
evidence/<engagement_id>/
  audit.jsonl              # one JSON object per tool run (allowed/blocked/error/ok)
  SESSION.md               # human-readable one-line-per-run log
  <tool>/<timestamp>.txt   # full raw output of each run (secret-masked)
  RECON-REPORT.md          # built by recon_report (SOP §4.3)
```

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

Covers scope matching (wildcards/CIDRs/OOS-wins), the active gate (every failing
condition), rate clamping, input validation, and output parsing from saved samples.
No network is touched by the tests.

## License / use

Maintained by Mithun. Use only against assets you are explicitly authorized to test.

# RJHex VAPT — External Tool Installation Guide

The portal **auto-detects** these tools and uses whichever are present. None are
required (built-in Python checks always run), but installing them makes the
assessment much deeper. Install the ones you want, then just re-run a scan.

> All tools below are free / open-source. Use them **only** against systems you
> are authorised to test.

---

## Fastest path: Kali Linux

Most of these ship with Kali or are one `apt`/`go install` away.

```bash
sudo apt update
sudo apt install -y \
  nmap nikto whatweb wafw00f dnsrecon dnsenum fierce \
  sslscan testssl.sh dirb wapiti theharvester amass
```

WordPress + Ruby tool:
```bash
sudo apt install -y wpscan        # or: gem install wpscan
```

Go-based tools (fast, modern — install Go first: `sudo apt install golang-go`):
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
# add Go bins to PATH:
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
nuclei -update-templates
```

Python-based:
```bash
pipx install sslyze
pipx install sublist3r        # or: sudo apt install sublist3r
```

Rust-based directory scanner:
```bash
sudo apt install -y feroxbuster     # or cargo install feroxbuster
```

---

## The full list (what each does + how it's used)

| Tool | Type | Purpose | How the portal uses it |
|------|------|---------|------------------------|
| **nmap** | passive | Port & service/version discovery | `-T4 -F -sV --open` top-ports scan |
| **whatweb** | passive | Web technology fingerprint | summarises detected stack |
| **wafw00f** | passive | WAF/CDN detection | records defensive controls |
| **dnsrecon** | passive | DNS enumeration | standard record enum |
| **dnsenum** | passive | DNS enumeration | detected only (manual use) |
| **fierce** | passive | DNS recon / subdomains | detected only |
| **sslscan** | passive | TLS cipher/protocol audit | flags weak ciphers/protocols |
| **testssl.sh** | passive | TLS configuration audit | fallback if sslscan absent |
| **sslyze** | passive | TLS analysis | detected only |
| **nikto** | passive | Web-server misconfig scanner | `-Tuning 123b`, time-bounded |
| **subfinder** | passive | Passive subdomain discovery | enumerates subdomains |
| **sublist3r** | passive | Subdomain discovery | alt to subfinder |
| **amass** | passive | Attack-surface / subdomain mapping | `enum -passive` |
| **theHarvester** | passive | OSINT emails/hosts | detected only |
| **httpx** | passive | HTTP probing of hosts | detected only |
| **nuclei** | active | Template-based vuln/exposure scan | low→critical templates |
| **wpscan** | active | WordPress core/plugin/theme audit | only if WordPress detected |
| **wapiti** | active | Black-box web vuln scan (XSS/SQLi…) | `-m xss,sql,exec,file`, time-capped |
| **gobuster** | active | Directory/content brute-force | common.txt wordlist |
| **ffuf** | active | Fast web fuzzer | alt to gobuster |
| **dirb** | active | Directory brute-force | alt to gobuster |
| **feroxbuster** | active | Recursive content discovery | time-limited |

**passive** tools are read-only recon. **active** tools send many requests and
run only when you tick *"Allow active tools"* in the portal (authorised testing).

---

## macOS (Homebrew)

```bash
brew install nmap nikto whatweb wafw00f sslscan testssl dnsrecon amass ffuf feroxbuster
brew install nuclei subfinder httpx        # projectdiscovery tap
pipx install sslyze sublist3r
```

## Windows

Use **WSL2 with Kali/Ubuntu** (recommended — follow the Kali steps above), or
install native builds of `nmap` and the Go/Rust tools. The portal detects
whatever is on `PATH`.

---

## Verifying detection

Start the portal — the home page shows a green ✓ next to every tool it found.
Anything not installed simply shows `—` and is skipped; the built-in checks
still run.

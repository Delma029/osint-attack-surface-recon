# OSINT and Attack Surface Reconnaissance

**Target:** The Nmap Project (`nmap.org` / `scanme.nmap.org`)

---

## 1. Objective

To map the publicly visible attack surface of an organization using only open-source intelligence (OSINT) techniques, without directly touching its systems. This exercise simulates the reconnaissance phase an attacker performs before ever engaging a target — using domain registration data, passive subdomain/email enumeration, internet-facing service fingerprinting, and search-engine indexing to build a picture of what is already exposed.

---

## 2. Authorization and Target Selection

**Target:** The Nmap Project — `nmap.org`, with specific focus on `scanme.nmap.org`.

`scanme.nmap.org` is explicitly maintained by the Nmap Project as a public test host for scanning and reconnaissance practice, as documented on Nmap's own site (`scanme.nmap.org` itself states: *"We set up this machine to help folks learn about Nmap and also to test and make sure that their Nmap installation (or Internet connection) is working properly"*). This makes it a legitimately authorized target for passive OSINT and active scanning practice. The parent domain `nmap.org` and its publicly listed maintainer (Gordon Lyon) were researched using only passive, publicly available sources — no systems were directly probed beyond what Shodan's own pre-existing scan database provided.

---

## 3. Technologies Used

| Category | Tool | Purpose |
|---|---|---|
| Domain intelligence | `whois` | Domain registration, registrar, expiry, nameservers |
| DNS intelligence | `dig`, `nslookup` | Mail routing (MX), SPF/TXT records, DNSSEC status, CAA policy |
| Subdomain/email enumeration | theHarvester 4.11.1 | Passive discovery of subdomains via Certificate Transparency logs and search engines |
| Internet-facing service fingerprinting | Shodan | Open ports, service banners, known vulnerabilities on discovered hosts |
| Search-engine reconnaissance | Google dorking | Discovery of indexed documents, directory listings, and exposed paths |
| Organizational/personnel research | Public bio pages | Named personnel, contact patterns, affiliated domains |

---

## 4. Methodology and Findings

### 4.1 WHOIS — Domain Registration Intelligence

```
Domain Name: nmap.org
Registrar: Dynadot Inc
Creation Date: 1999-01-18
Registry Expiry Date: 2029-01-18
Name Servers: ns1–ns5.linode.com
Domain Status: clientTransferProhibited
```

**Finding:** The domain has been registered since 1999 and is hosted on Linode's nameservers, indicating Linode is the organization's infrastructure provider. `clientTransferProhibited` status indicates a basic anti-hijacking protection is in place.

### 4.2 DNS Reconnaissance

```
A record:    50.116.1.184
AAAA record: 2600:3c01:e000:3e6::6d4e:7061
MX records:  aspmx.l.google.com (priority 1), alt1/alt2.aspmx.l.google.com,
             aspmx2/aspmx3.googlemail.com
TXT (SPF):   v=spf1 a mx ptr ip4:50.116.1.184 ... include:_spf.google.com ~all
TXT:         google-site-verification=SrtYpJGxZzMTcczZG44XtLVK-sEPit9bputDjWc0lF4
CAA:         0 issue "letsencrypt.org"
DNSSEC:      unsigned
```

**Findings:**
- **Email is hosted on Google Workspace** (MX records point to Google's mail servers) — this tells an attacker exactly which phishing/credential-harvesting infrastructure patterns to target (e.g. spoofed Google login pages), and which provider's own security controls (or lack of 2FA) would matter most.
- An **SPF record is present** and correctly scoped, reducing (but not eliminating) email spoofing risk.
- The **CAA record restricts certificate issuance to Let's Encrypt only** — a good practice that limits which Certificate Authorities can issue valid TLS certs for the domain, reducing risk from a compromised/rogue CA elsewhere.
- **DNSSEC is not enabled** — a gap. Without DNSSEC, DNS responses for this domain are not cryptographically signed, leaving it theoretically more exposed to DNS spoofing/cache poisoning attacks than a DNSSEC-signed domain.

### 4.3 theHarvester — Subdomain Enumeration

```bash
theHarvester -d nmap.org -b crtsh,duckduckgo -l 200
```

**Hosts found (4):**
- `svn.nmap.org`
- `issues.nmap.org`
- `scanme.nmap.org`
- `2Fsvn.nmap.org` *(likely a URL-encoding artifact of `/svn.nmap.org` picked up from a scraped link, not a genuinely distinct host — noted here for transparency rather than treated as a confirmed 4th subdomain)*

No emails or additional IPs were surfaced through this specific source combination.

**Finding:** Two of the three genuine subdomains — `svn.nmap.org` (version control) and `issues.nmap.org` (issue tracker) — represent meaningfully expanded attack surface beyond the main website. Version control and issue-tracking systems are common targets in real reconnaissance, since they can leak source code, credentials accidentally committed, or internal discussion revealing unpatched vulnerabilities.

### 4.4 Shodan — Internet-Facing Service Fingerprinting

**Target: `scanme.nmap.org` (45.33.32.156)**

| Port | Service | Detail |
|---|---|---|
| 22/tcp | SSH | OpenSSH 6.6.1p1 on Ubuntu 2ubuntu2.13 — **outdated** (Ubuntu 14.04-era release) |
| 80/tcp | HTTP | Apache/2.4.7 (Ubuntu) — Shodan's own vulnerability database flags **21 critical, 44 high, 51 medium** known vulnerabilities associated with this exact version |
| 123/udp | NTP | ntpd, protocol version 3 |
| 31337/tcp | (unspecified) | Notable as a classic "elite" port number often associated with backdoors/test tools in security culture |

Infrastructure: hosted on **Linode** (Akamai Connected Cloud, AS63949), Fremont, California, United States.

**Finding:** This is the most significant technical finding of the assessment. Both exposed services (OpenSSH 6.6.1p1 and Apache 2.4.7) are substantially outdated, and Shodan's vulnerability correlation shows over 100 combined known CVEs associated with the Apache version alone. In a real (non-authorized-test) target, this would represent a high-priority remediation item. Given that `scanme.nmap.org` is *intentionally* left as a public test host by its own maintainers, this exposure is a deliberate choice rather than an oversight — but it demonstrates exactly the kind of software-version fingerprinting an attacker would use to identify exploitable targets.

**Target: Researcher's home public IP**

A Shodan lookup against the researcher's own home public IP returned **no indexed results**, indicating either that the IP has not been previously scanned by Shodan's crawlers, or that no publicly accessible services are exposed on this network — consistent with a properly configured home router with no unnecessary port forwarding. This contrasts directly with `scanme.nmap.org`: one environment is intentionally exposed and richly fingerprintable, the other shows no discoverable footprint at all.

### 4.5 Google Dorking

| Dork | Result |
|---|---|
| `site:nmap.org filetype:pdf` | Multiple legitimate, intentionally published documentation PDFs (Table of Contents, Host Discovery Techniques, TCP Split Handshake paper) — no sensitive/internal documents found |
| `site:nmap.org inurl:admin` | No genuine admin panel exposure; results were NSE script files referencing the string "admin" (e.g. default-credential fingerprinting scripts), not real exposed admin interfaces |
| `site:nmap.org intitle:"index of"` | **One open directory listing found:** `scanme.nmap.org/images` — a real, if minor, misconfiguration exposing a raw file listing rather than a proper page |
| `site:nmap.org ext:log` | No genuine exposed log files; results were NSE script documentation referencing the word "log" in unrelated contexts |
| `site:nmap.org inurl:login` | No genuine login portal exposure found; top result was the `scanme.nmap.org` landing page itself |

**Finding:** The only concrete misconfiguration surfaced was the open `/images` directory listing on `scanme.nmap.org`. All other dork queries returned either intentionally published documentation or false-positive matches from Nmap's own script documentation (which frequently discusses concepts like "admin," "login," and "log" in a security-research context, without actually exposing anything).

### 4.6 Organizational and Personnel Research

Public bio page (`insecure.org/fyodor/`) for **Gordon Lyon ("Fyodor")**, founder and maintainer of the Nmap Project, disclosed:

- **Direct email address:** `fyodor@nmap.org` (self-published)
- **Physical location:** Palo Alto, California
- **Affiliated domains:** `insecure.org`, `seclists.org`, `sectools.org` — expanding the organization's footprint beyond `nmap.org` alone
- **Social media presence:** Facebook, Twitter, and Google+ accounts referenced
- **A PGP/GPG public key offered for encrypted contact** — a positive security practice, demonstrating awareness of secure communication norms

**Finding:** This is a case where the subject has *deliberately* self-disclosed personal and contact information as part of running a transparent, community-facing open-source project — a different risk calculus than an unintentional leak. In a corporate OSINT engagement, this same category of finding (named individual, direct email, physical location) would typically represent a genuine social-engineering risk rather than an intentional choice, and would warrant a recommendation to reduce exposure.

---

## 5. Consolidated "What an Attacker Would See First" Summary

| Category | Finding | Attacker Value | Exposure-Reduction Recommendation |
|---|---|---|---|
| Domain/WHOIS | Registrar (Dynadot), 1999 registration, Linode nameservers | Confirms hosting provider and domain age/stability | Maintain registrar transfer-lock (already in place) |
| DNS/Email | MX records point to Google Workspace; SPF present; DNSSEC **not** enabled | Identifies phishing infrastructure target (Google-branded lures); DNSSEC gap is a real weakness | Enable DNSSEC to protect against DNS spoofing/cache poisoning |
| Subdomains | `svn.nmap.org`, `issues.nmap.org`, `scanme.nmap.org` | Version control and issue trackers are common secondary targets | Ensure access controls and patching are applied consistently across all subdomains, not just the primary site |
| Internet-facing services | scanme.nmap.org: OpenSSH 6.6.1p1, Apache 2.4.7 — 100+ combined known CVEs flagged | Direct, fingerprinted exploitation targets | Patch/upgrade exposed service versions (deliberately left outdated here as a test host, but a genuine risk on any production system) |
| Directory exposure | Open `/images` index listing on scanme.nmap.org | Minor information disclosure | Disable directory listing (`Options -Indexes` in Apache config) |
| Personnel/social engineering | Named maintainer, self-disclosed email, location, affiliated domains | Social-engineering and phishing target profile | Intentional here for project transparency; a corporate target should minimize equivalent disclosures |

---

## 6. Challenges Faced

1. **theHarvester source compatibility** — The initial command specified `bing` as a data source, which is no longer supported in theHarvester 4.11.1, causing the tool to reject the entire query (`[!] Invalid source`). Resolved by checking the tool's own `-h` help output to confirm the current list of valid sources and re-running with `crtsh` and `duckduckgo` instead.

2. **Shodan CLI authentication failures** — The Shodan command-line tool returned `403 Forbidden` errors even after a valid API key was confirmed via `shodan info` (which correctly showed `0` available query/scan credits — consistent with a new free-tier account). Rather than wait for account activation or credit allocation, the same lookups were performed directly through Shodan's web interface (`shodan.io/host/<ip>`), which uses a different access path and returned full results immediately. This is noted as a legitimate alternative access method rather than an unresolved gap.

3. **Google dorking syntax confusion** — An initial attempt to run `site:nmap.org filetype:pdf` directly in the terminal failed (`command not found`), since Google dork syntax is a search-engine query, not a shell command. Resolved by running the same queries directly in a browser's Google search bar instead.

4. **Distinguishing genuine findings from false-positive matches** — Several Google dork queries (`inurl:admin`, `ext:log`, `inurl:login`) returned results that superficially matched the search terms but were, on inspection, Nmap's own NSE (Nmap Scripting Engine) script documentation discussing these concepts academically rather than exposing real admin panels, logs, or login portals. Each result was individually verified rather than counted at face value, to avoid overstating findings.

5. **URL-encoding artifact in theHarvester results** — One of the four "hosts" returned by theHarvester (`2Fsvn.nmap.org`) appears to be a parsing artifact from a URL-encoded path (`%2F` = `/`) rather than a genuinely distinct subdomain. This was flagged rather than reported as a confirmed finding, to maintain accuracy.

---

## 7. References

- Nmap Project — ScanMe host description: http://scanme.nmap.org
- Shodan: https://www.shodan.io
- theHarvester (Edge-Security / Christian Martorella): https://github.com/laramies/theHarvester
- ICANN WHOIS status codes: https://icann.org/epp
- Gordon Lyon ("Fyodor") public bio: https://insecure.org/fyodor/
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/

---

## 8. Conclusion

This exercise demonstrated how a meaningful attack-surface profile can be constructed entirely from passive, publicly available sources, without ever directly interacting with the target beyond querying already-public data. WHOIS and DNS records revealed the organization's hosting and email infrastructure (Linode, Google Workspace); theHarvester surfaced three legitimate subdomains expanding the footprint beyond the main domain; Shodan's pre-existing scan data exposed significantly outdated, vulnerability-flagged software versions on the designated test host; Google dorking surfaced one genuine (if minor) misconfiguration alongside several false-positive matches correctly filtered out through manual verification; and public biographical research revealed a named individual's self-disclosed contact details and organizational affiliations.

Taken together, these findings illustrate the core lesson of OSINT reconnaissance: an organization's public footprint is often far larger, and more informative to an attacker, than its own IT team may realize — spanning domain infrastructure, forgotten or secondary subdomains, outdated software fingerprints, minor web misconfigurations, and the personal disclosures of the people behind the organization. Reducing this footprint requires attention across all of these categories simultaneously, not just the primary website.

---

## Appendix: Evidence Index

| Folder | Contents |
|---|---|
| `screenshots/01-whois/` | WHOIS and DNS (`dig`/`nslookup`) output for nmap.org |
| `screenshots/02-theharvester/` | theHarvester subdomain enumeration results |
| `screenshots/03-shodan/` | Shodan results for scanme.nmap.org (ports 22, 80, 123) and home IP (no results) |
| `screenshots/04-google-dorking/` | All five Google dork query results |
| `screenshots/05-org-research/` | Authorization confirmation and Gordon Lyon bio page |

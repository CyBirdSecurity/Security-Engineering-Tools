# DNS Takeover Scanner

A GitHub Actions workflow that checks domains **you own** every day for
records an attacker could hijack. It finds hostnames from Certificate
Transparency logs, checks each one for dangling DNS records, and opens one
GitHub issue per finding.

No cloud or DNS-provider credentials are needed. It only reads public DNS
and CT data, so it works with any DNS provider.

> **Authorization:** only scan domains you own or are authorized to test.
> Apart from DNS queries, the scanner only sends a plain `GET /` to hostnames
> whose CNAME points at a known hosting service, to look for that service's
> "unclaimed" page.

## What it detects

| Finding | Severity | What it means | Why it's exploitable |
|---|---|---|---|
| `cname-unregistered-domain` | high | A CNAME points at a domain that no longer exists | Anyone can register that domain and serve content on your hostname |
| `cname-dangling-service` | high / medium | A CNAME points at a cloud or SaaS resource that was deleted (Azure, Elastic Beanstalk, S3, GitHub Pages, Heroku and [others](scripts/fingerprints.json)) | Anyone can create a resource with the same name on that service |
| `cname-dangling` | medium | A CNAME target doesn't exist and isn't a known service | Often harmless clutter, but check it |
| `ns-unregistered-domain` | high | A subdomain is delegated to a name server whose domain doesn't exist | Whoever registers that domain controls every record under the subdomain |
| `ns-dangling-provider` | high | A subdomain is delegated to a cloud DNS provider (Route 53, Azure DNS, Google Cloud DNS and others) that doesn't serve the zone | Someone can create the zone on that provider and may get the same name servers |
| `ns-lame-delegation` | medium | No delegated name server answers for the subdomain | Broken, and possibly claimable depending on the provider |
| `mx-unregistered-domain` | high | An MX record points at a mail server on an unregistered domain | Whoever registers it receives your mail |
| `mx-dangling` | medium | An MX host doesn't resolve | Mail delivery fails |
| `spf-unregistered-domain` | high | SPF `include:`, `redirect=`, `a:`, `mx:` or `exists:` names an unregistered domain | Whoever registers it can send mail that passes SPF as you |
| `spf-dangling` | medium | An SPF `include` or `redirect` target has no SPF record | SPF checks fail (permerror) |

"High" means a known, practical takeover path. "Medium" means broken and
worth fixing, but it may not be claimable. **Always confirm by hand before
acting.** For "unregistered" findings, check WHOIS or RDAP: a domain can lack
DNS records and still be registered.

### How each check works
- **Discovery.** For each root domain it queries [crt.sh](https://crt.sh)
  (which includes expired certificates, so old forgotten hostnames show up)
  and [Cert Spotter](https://sslmate.com/certspotter/), then merges the
  results. Wildcard labels are stripped, and the root itself is always
  checked.
- **CNAMEs.** It follows the CNAME chain. If the final target is NXDOMAIN, it
  checks whether the target's registrable domain exists (using the Public
  Suffix List) and whether the target matches a service where NXDOMAIN means
  "claimable". If the target resolves and belongs to a service with an
  HTTP fingerprint, it fetches the hostname and looks for that service's
  "unclaimed" page.
- **NS delegations.** It walks down from each root zone like a resolver does,
  asking each zone's own servers about the next label. That finds delegations
  even when they're broken (a normal resolver just returns SERVFAIL). For each
  delegation it checks that the name servers exist and answer authoritatively
  for the zone.
- **Mail.** For every hostname it checks MX hosts and SPF-referenced domains.

It uses a small DNS client written with the Python standard library. That's
needed for the non-recursive queries to specific name servers, and it means
there's nothing to install.

## Issues

| Situation | What happens |
|---|---|
| New finding | An issue opens, labelled `dns-takeover` and `dns-takeover:high` or `dns-takeover:medium` |
| Still present | The issue's body is refreshed ("last seen"), so you don't get a new comment every day |
| Fixed | It's commented on and closed, but **only** if that host was fully re-checked |
| Host couldn't be checked (DNS errors, CT outage) | The issue is left open as it is |
| Comes back after being fixed | The issue is reopened with a comment |
| You close it as **not planned** | Treated as an accepted risk: never reopened |

If the scan itself can't run properly, it opens a single
`dns-takeover-scan-failure` issue, and closes it after the next good run. That
covers a CT source failing for every provider, a root domain going
unscanned, or more than 20% of hosts being inconclusive. The full results are
also uploaded as the `findings.json` artifact (kept 30 days).

**Run it from a private repository.** Findings are a map of how to hijack
your domains, and issues and logs in a public repo are public. The script
checks the repo's visibility and refuses to open issues in a public repo
(override with `ALLOW_PUBLIC_REPO=true` only if you really mean it).

## Setup

1. In a **private** repo, copy:
   ```
   .github/workflows/dns-takeover-scanner.yml  ← DNS-Takeover-Scanner.yml
   .github/dns-takeover/scripts/               ← scripts/
   ```
2. **Settings → Secrets and variables → Actions:**

   | Name | Type | Required | Value |
   |---|---|---|---|
   | `DNS_ROOT_DOMAINS` | variable | ✅ | your registered domains, space or comma separated, e.g. `example.com example.org` |
   | `DNS_RESOLVERS` | variable | | recursive resolvers, default `1.1.1.1,8.8.8.8` |
   | `DNS_FAIL_ON` | variable | | `high` (default), `medium` or `none`: fail the run when findings at this severity exist |
   | `CERTSPOTTER_API_KEY` | secret | | an [SSLMate](https://sslmate.com/account/api_credentials) API key, for more Cert Spotter quota |

3. **Test run.** Run *DNS Takeover Scanner* manually with **dry_run** ticked.
   Check the run summary: hostnames found, findings, and anything inconclusive.
4. Run it again without dry run to start opening issues. After that it runs
   daily.

Subscribe to `dns-takeover` issues (or watch the repo) so the right people get
notified.

## Tuning and limits

- **Run time.** Hosts are checked 16 at a time (`DNS_MAX_WORKERS`). A few
  thousand hostnames normally take a few minutes. The NS walk runs
  sequentially but caches answers per zone.
- **CT only sees hostnames that had a certificate.** Names that never had a
  TLS certificate (internal names, HTTP-only CNAMEs, mail-only hosts) won't
  be found. Wildcard certificates hide individual names too.
- **Fingerprints change.** Services change how they behave, and some are now
  "edge" cases (claimable only in some configurations). They're kept in
  [`scripts/fingerprints.json`](scripts/fingerprints.json) so you can update
  them without touching code. The community list
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) is
  a good reference.
- **Not checked:** A/AAAA records pointing at cloud IPs you've released (that
  needs your cloud inventory), and SPF chains beyond the first level of
  includes.
- **"Unregistered" is a DNS heuristic.** It means the domain has no NS
  records (NXDOMAIN). Confirm with WHOIS or RDAP before treating it as
  available.

## Fixing findings

The usual fix is to **delete the record** in your DNS provider. Do this as
part of the same change that removes the cloud resource, so it doesn't
happen again. For delegations, remove the NS records from the *parent* zone.
If you need the name, recreate the resource (or register the domain) first,
then decide.

## Development

```bash
cd "Github Actions/DNS-Takeover-Scanner"
python3 -m unittest discover -s tests      # 23 tests, no network needed
DNS_ROOT_DOMAINS=example.com DRY_RUN=true python3 scripts/scan.py   # live scan, no issues
```

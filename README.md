# Subdomain Basket

Subdomain Basket is an authorization-only domain reconnaissance tool. It helps users inventory publicly observable hosts and basic web metadata for a domain they own or are explicitly authorized to assess.

## MVP workflow

- Ask for a root domain and require explicit authorization confirmation.
- Discover names with crt.sh Certificate Transparency plus Subfinder, Amass passive mode, Katana, Assetfinder, and Sublist3r.
- Normalize and deduplicate results, keeping only the root domain and its subdomains.
- Resolve DNS and check current HTTP/HTTPS reachability, page title, and TLS certificate details for each in-scope host.
- Print a readable summary and save timestamped JSON/CSV reports plus a separate `subdomains.txt`.

“Activity” means DNS resolution and HTTP/HTTPS reachability observed during this run only; the tool does not claim historical activity. Each host in the report lists the discovery sources that returned it, and every discovery tool has a status and any error recorded.

## Authorization and safety

Use this project only for a domain you own or have explicit written authorization to assess. The entered domain and its subdomains are the complete scope; unrelated hosts must not be queried or assessed.

The MVP caps the combined result set at 50 hosts and uses five-second timeouts and at least one second between its own DNS/HTTP(S) requests. Discovery programs run one at a time; each has a 70-second process limit. Subfinder and Katana are configured with a one-request-per-second limit and one worker; Katana is restricted to the authorized domain and one crawl level. Amass runs in passive mode, and Sublist3r is limited to one thread without its brute-force option. If a binary is missing or fails, its status is recorded and the remaining workflow continues. Neither the CT lookup nor HTTP checks follow redirects, and normal TLS certificate verification remains enabled. If DNS resolution fails, HTTP(S) checks for that host are skipped. Certificate DNS names outside the authorized domain scope are omitted.

The tool does not perform brute-force enumeration, port scanning, exploitation, credential testing, or access-control bypass. Gobuster and other unconfirmed tools are not invoked.

## Setup and usage

Requires Python 3.11 or later. Runtime dependencies are from the Python standard library; no third-party packages are needed.

Install these command-line tools separately and make them available on `PATH`:

- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Amass](https://github.com/owasp-amass/amass)
- [Katana](https://github.com/projectdiscovery/katana)
- [Assetfinder](https://github.com/tomnomnom/assetfinder)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)

The Python application does not install or update these external binaries. If one is absent, its discovery status is reported and the other sources still run. The Certificate Transparency source uses `crt.sh` over HTTPS.

Install from the project directory:

```bash
python -m pip install .
```

Run from the project directory without installing:

```bash
python -m subdomain_basket
```

Provide a domain directly or let the program prompt for it:

```bash
python -m subdomain_basket --domain example.com
```

After installation, the equivalent console command is:

```bash
subdomain-basket --domain example.com
```

The program then requires the exact confirmation `I HAVE AUTHORIZATION` before making any network requests. It writes timestamped JSON and CSV files under `reports/` by default, plus `subdomains.txt`. Use `--output-dir PATH` to select another directory. To avoid replacing files, repeated `subdomains.txt` outputs use `subdomains_1.txt`, `subdomains_2.txt`, and so on. Reports may contain sensitive asset inventory information and should be handled accordingly.

Run the offline unit tests with:

```bash
python -m unittest discover -s tests
```

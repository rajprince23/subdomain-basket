# Subdomain Basket

Subdomain Basket is a planned, authorization-only domain reconnaissance tool. Its purpose is to help users inventory the publicly observable hosts and basic web metadata for a domain they own or are explicitly authorized to assess.

## Planned features

- Passive subdomain discovery
- DNS resolution for discovered hosts
- Basic HTTP and HTTPS status checks
- Page-title extraction
- TLS certificate details
- Readable, consolidated results
- Timestamped JSON and CSV reports

These features are planned and are not implemented yet.

## Authorization and safety

Use this project only for a domain you own or have explicit written authorization to assess. The entered domain and its subdomains are the complete scope; unrelated hosts must not be queried or assessed.

When implemented, network requests will use documented rate limits and timeouts. This tool is not intended to perform brute-force enumeration, port scanning, exploitation, credential testing, or access-control bypass.

## Setup and usage

Setup and run instructions will be added after the implementation, supported Python version, and dependencies have been selected. No scan command is available yet.

# B2B 5-Layer SMTP & DNS MX Lead Verifier

Python pipeline for validating corporate contact lists prior to CRM upload or outbound campaigns.

## Verification Layers
1. **RFC 5322 Syntax Validation**: Rejects malformed addresses and role-based noise if configured.
2. **Disposable Domain Blocklist**: Filters temporary/throwaway inbox providers.
3. **DNS MX Resolution**: Cached lookup of active Mail Exchange servers via `dnspython`.
4. **Catch-All Heuristic Probe**: Detects domains that accept arbitrary local parts.
5. **Non-Intrusive Live SMTP Handshake**: Checks `RCPT TO` status codes without dispatching an email.

## Usage
```bash
pip install -r requirements.txt
python verifier.py --input raw_leads.csv --email-col email --out verified_leads.csv
```

"""
5-Layer B2B Email Verification & Hygiene Engine.
"""
import argparse
import logging
import re
import smtplib
import socket
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import dns.resolver
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("lead_verifier")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "throwawaymail.com", "getnada.com",
}


@dataclass
class VerificationResult:
    email: str
    syntax_valid: bool
    disposable: bool
    mx_host: Optional[str]
    catch_all: Optional[bool]
    smtp_status: str
    deliverable: bool


class LeadEmailVerifier:
    """Performs multi-layer validation with DNS MX caching."""

    def __init__(self, helo_domain: str = "verify.example.com", timeout_s: float = 6.0):
        self.helo_domain = helo_domain
        self.timeout_s = timeout_s
        self._mx_cache: Dict[str, Optional[str]] = {}
        self._catchall_cache: Dict[str, Optional[bool]] = {}

    def resolve_mx(self, domain: str) -> Optional[str]:
        if domain in self._mx_cache:
            return self._mx_cache[domain]
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=self.timeout_s)
            best = sorted(answers, key=lambda r: r.preference)[0].exchange.to_text().rstrip(".")
            self._mx_cache[domain] = best
            return best
        except Exception:
            self._mx_cache[domain] = None
            return None

    def _smtp_rcpt_probe(self, mx_host: str, target_email: str) -> Tuple[int, str]:
        try:
            with smtplib.SMTP(mx_host, 25, timeout=self.timeout_s) as smtp:
                smtp.helo(self.helo_domain)
                smtp.mail(f"probe@{self.helo_domain}")
                code, msg = smtp.rcpt(target_email)
                return code, msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else str(msg)
        except (socket.timeout, smtplib.SMTPException, OSError) as exc:
            return -1, str(exc)

    def is_catch_all(self, domain: str, mx_host: str) -> Optional[bool]:
        if domain in self._catchall_cache:
            return self._catchall_cache[domain]
        random_local = f"no_such_user_{uuid.uuid4().hex[:10]}"
        code, _ = self._smtp_rcpt_probe(mx_host, f"{random_local}@{domain}")
        if code == -1:
            self._catchall_cache[domain] = None
        else:
            self._catchall_cache[domain] = (200 <= code < 300)
        return self._catchall_cache[domain]

    def verify(self, raw_email: str, probe_smtp: bool = True) -> VerificationResult:
        email = (raw_email or "").strip().lower()
        if not EMAIL_REGEX.match(email):
            return VerificationResult(email, False, False, None, None, "INVALID_SYNTAX", False)

        domain = email.split("@", 1)[1]
        if domain in DISPOSABLE_DOMAINS:
            return VerificationResult(email, True, True, None, None, "DISPOSABLE_DOMAIN", False)

        mx_host = self.resolve_mx(domain)
        if not mx_host:
            return VerificationResult(email, True, False, None, None, "NO_MX_RECORD", False)

        if not probe_smtp:
            return VerificationResult(email, True, False, mx_host, None, "MX_VERIFIED", True)

        catch_all = self.is_catch_all(domain, mx_host)
        code, msg = self._smtp_rcpt_probe(mx_host, email)
        if 200 <= code < 300:
            status = "CATCH_ALL_ACCEPTED" if catch_all else "SMTP_VERIFIED"
            return VerificationResult(email, True, False, mx_host, catch_all, status, True)
        if code == -1:
            return VerificationResult(email, True, False, mx_host, catch_all, f"MX_ONLY_PORT25_BLOCKED", True)
        return VerificationResult(email, True, False, mx_host, catch_all, f"SMTP_REJECTED_{code}", False)


def verify_csv(input_csv: Path, output_csv: Path, email_col: str = "email", probe_smtp: bool = False) -> None:
    df = pd.read_csv(input_csv)
    verifier = LeadEmailVerifier()
    results: List[dict] = [asdict(verifier.verify(str(val), probe_smtp=probe_smtp)) for val in df[email_col]]
    res_df = pd.DataFrame(results)
    merged = pd.concat([df.reset_index(drop=True), res_df.drop(columns=["email"])], axis=1)
    merged.to_csv(output_csv, index=False, encoding="utf-8")
    logger.info("Verified %d rows -> %s", len(merged), output_csv)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="5-layer B2B email list verifier.")
    parser.add_argument("--input", required=True, help="Input CSV path")
    parser.add_argument("--out", required=True, help="Output verified CSV path")
    parser.add_argument("--email-col", default="email", help="Email column name")
    parser.add_argument("--probe-smtp", action="store_true", help="Perform live TCP/25 SMTP RCPT handshake")
    args = parser.parse_args()
    verify_csv(Path(args.input), Path(args.out), args.email_col, args.probe_smtp)

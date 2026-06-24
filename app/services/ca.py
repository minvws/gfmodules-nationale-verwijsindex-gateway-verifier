import base64
import hashlib
import logging
import os
from typing import List
from urllib.parse import unquote

from fastapi import Request
from OpenSSL import crypto

from app.models.oin import OinNumber

SSL_CLIENT_CERT_HEADER_NAME = "x-forwarded-tls-client-cert"

logger = logging.getLogger(__name__)


class CaService:
    """
    Service for handling CA certificate verification and cert-type detection.
    """

    def __init__(self, cert_paths: list[str]) -> None:
        self._ca_store = crypto.X509Store()

        for cert_path in cert_paths:
            if not os.path.exists(cert_path):
                raise ValueError(f"CA certificate file not found: {cert_path}")
            self._ca_store.load_locations(cert_path)

    def get_certs(self, request: Request) -> list[crypto.X509]:
        certs = self._verify_and_fetch(request, self._ca_store)
        if certs is None:
            logger.debug("No valid client certificate(s) found")
            return []
        return certs

    def is_oin_certificate(self, request: Request) -> tuple[bool, OinNumber | None]:
        """Returns (True, OinNumber) if the leaf cert has a 20-digit serialNumber in its subject."""
        certs = self.get_certs(request)
        if not certs:
            return False, None
        oin = self._extract_oin_from_cert(certs[0])
        return (oin is not None, oin)

    def get_presented_thumbprint(self, request: Request) -> str | None:
        """Returns the SHA-256 DER thumbprint (x5t#S256 form) of the presented leaf cert, if any."""
        certs = self.get_certs(request)
        if not certs:
            return None
        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, certs[0])
        return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")

    def check_cert_fingerprint(self, request: Request, thumbprint: str) -> bool:
        """Verifies the leaf cert's SHA-256 DER fingerprint matches the x5t#S256 value from the JWT cnf claim."""
        computed = self.get_presented_thumbprint(request)
        return computed is not None and computed == thumbprint

    @staticmethod
    def _extract_oin_from_cert(cert: crypto.X509) -> OinNumber | None:
        subject = cert.get_subject()
        for key, value in subject.get_components():
            if key == b"serialNumber":
                serial = value.decode("ascii")
                if len(serial) == 20 and serial.isdigit():
                    return OinNumber(serial)
        return None

    def _verify_and_fetch(self, request: Request, store: crypto.X509Store) -> List[crypto.X509] | None:
        certs = self.get_pem_from_request(request)
        if not certs:
            logger.debug("client certificate not found or verification failed.")
            return None

        x509_certs = [crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode("ascii")) for cert_pem in certs]
        leaf, *chain = x509_certs
        ctx = crypto.X509StoreContext(store, leaf, chain)
        try:
            ctx.verify_certificate()
            return x509_certs
        except crypto.X509StoreContextError:
            return None
        except Exception:
            logger.exception("unexpected error during certificate verification.")
            return None

    @staticmethod
    def get_pem_from_request(request: Request) -> List[str]:
        header_value = request.headers.get(SSL_CLIENT_CERT_HEADER_NAME)
        if not header_value:
            logger.debug("client certificate not found or verification failed.")
            return []

        certs = unquote(header_value).split(",")
        return [CaService.fixup_cert_headers_and_footers(cert) for cert in certs]

    @staticmethod
    def fixup_cert_headers_and_footers(cert: str) -> str:
        cert = cert.strip()
        cert = cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
        body = cert.strip()
        return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"

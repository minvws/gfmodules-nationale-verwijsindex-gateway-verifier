import logging
import os
from typing import List
from urllib.parse import unquote

from fastapi import Request
from OpenSSL import crypto

from app.db.models.oin import OinNumber

SSL_CLIENT_CERT_HEADER_NAME = "x-forwarded-tls-client-cert"

logger = logging.getLogger(__name__)


class CaService:
    """
    Service for handling CA certificate verification.
    """

    def __init__(self, oin_ca_cert_path: str) -> None:
        if not os.path.exists(oin_ca_cert_path):
            raise ValueError(f"CA certificate file not found: {oin_ca_cert_path}")
        self._oin_store = crypto.X509Store()
        self._oin_store.load_locations(cafile=oin_ca_cert_path)

    def is_oin_certificate(self, request: Request) -> tuple[bool, OinNumber | None]:
        """
        Determines if the server certificate is an OIN certificate signed by the OIN CA.
        """
        if not self._is_server_certificate(request, self._oin_store):
            logger.debug("server certificate not found or CA verification failed.")
            return False, None

        # Check for OIN number inside the cert
        certs = self.get_pem_from_request(request)
        if not certs:
            logger.debug("client certificate not found or verification failed.")
            return False, None

        x509_certs = [crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode("ascii")) for cert_pem in certs]
        leaf, *chain = x509_certs

        # Fetch serialNumber from components
        subject = leaf.get_subject()
        serial = None
        for key, value in subject.get_components():
            if key == b"serialNumber":
                serial = value.decode("ascii")
                break

        # Check if serial is 20 chars long, and contains only numbers
        if serial is None or len(serial) != 20 or not str(serial).isdigit():
            logger.debug("serial number %r is not a valid OIN number", serial)
            return False, None

        return True, OinNumber(serial)

    def _is_server_certificate(self, request: Request, store: crypto.X509Store) -> bool:
        """
        Verifies the client certificate against the provided CA store.
        """
        certs = self.get_pem_from_request(request)
        if not certs:
            logger.debug("client certificate not found or verification failed.")
            return False

        x509_certs = [crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode("ascii")) for cert_pem in certs]
        leaf, *chain = x509_certs
        ctx = crypto.X509StoreContext(store, leaf, chain)
        try:
            ctx.verify_certificate()
            return True
        except crypto.X509StoreContextError:
            return False
        except Exception:
            logger.exception("unexpected error during certificate verification.")
            return False

    @staticmethod
    def get_pem_from_request(request: Request) -> List[str]:
        """
        Extracts and returns the PEM-encoded client certificate from the request headers.
        """
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

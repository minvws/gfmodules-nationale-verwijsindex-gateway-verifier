import json
from typing import Dict

from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT


class JWTService:
    def __init__(self, public_key: bytes) -> None:
        self.public_key = public_key

    def deserialize(self, token: str) -> Dict[str, str]:
        key = JWK.from_pem(self.public_key)
        # check alg = P256
        # check iss
        # exp
        # nbf
        # iat
        data = JWT(jwt=token, key=key, check_claims={"aud": "nv"})
        results = json.loads(data.claims)
        return results

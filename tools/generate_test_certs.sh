#! /bin/bash
set -e

# This script generates test certificates for the OIN CA and a dummy server certificate signed by that CA.

OIN=${1:-"00000099000000001000"}
SECRET_DIR=secrets

echo "Creating certificate with OIN: ${OIN}"

if [ ! -d "$SECRET_DIR" ]; then
  mkdir -p "$SECRET_DIR"
fi

create_ca(){
  local name=$1
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -keyout "$SECRET_DIR"/$name.key -out "$SECRET_DIR"/$name.crt -days 3650 \
    -subj "/C=NL/O=$name/CN=dummy $name Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
}

sign_cert() {
  local cert_name=$1
  local ca_name=$2
  
  openssl x509 -req -days 500 -sha256 \
		-in "$SECRET_DIR"/$cert_name.csr \
		-CA "$SECRET_DIR"/$ca_name.crt \
		-CAkey "$SECRET_DIR"/$ca_name.key \
		-CAcreateserial \
		-copy_extensions copyall \
		-out "$SECRET_DIR"/$cert_name.crt  2>/dev/null
}


create_ca "dummy-oin-server-ca"


# Generate a dummy server certificate signed by the OIN CA
openssl req \
  -nodes \
  -keyout "$SECRET_DIR"/dummy-oin.key \
  -newkey rsa:2048 \
  -out "$SECRET_DIR"/dummy-oin.csr \
  -subj "/C=NL/O=MockTest Cert/CN=test.example.org/serialNumber=$OIN" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
   2>/dev/null
sign_cert dummy-oin dummy-oin-server-ca

rm -f "$SECRET_DIR"/*.csr || true
rm -f "$SECRET_DIR"/*.srl || true

echo "Test certificates generated in $SECRET_DIR"
echo "Generated certificates:"
ls -LRA "$SECRET_DIR"
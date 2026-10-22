#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Regenerates the openssl-made fixtures in this directory.  NOT run by the
# tests: its output is committed, so the tests need no openssl.  Run it from
# this directory after changing it:  sh mkfixtures.sh
#
# The two root PEMs (emSign_ECC_Root_CA_-_G3.pem, Comodo_AAA_Services_root.pem)
# are the public certificates also embedded in certstore-check.c.
set -eu
G3=emSign_ECC_Root_CA_-_G3.pem
AAA=Comodo_AAA_Services_root.pem
K=$(mktemp -d)
trap 'rm -rf "$K"' EXIT

openssl x509 -in "$G3" -outform DER -out emSign_ECC_Root_CA_-_G3.der
openssl x509 -in "$AAA" -outform DER -out Comodo_AAA_Services_root.der

# OpenSSL "TRUSTED CERTIFICATE" variants (aux trust after the DER)
openssl x509 -in "$G3" -addreject serverAuth -trustout -out g3-reject-serverauth.pem
openssl x509 -in "$G3" -addtrust serverAuth -trustout -out g3-trust-serverauth.pem
openssl x509 -in "$AAA" -addreject serverAuth -trustout -out aaa-reject-serverauth.pem
openssl x509 -in "$AAA" -addtrust emailProtection -trustout -out aaa-trust-email.pem
openssl x509 -in "$AAA" -setalias anchor -trustout -out aaa-alias-only.pem
openssl x509 -in "$G3" -addreject anyExtendedKeyUsage -trustout -out g3-reject-anyeku.pem
openssl x509 -in "$AAA" -addtrust anyExtendedKeyUsage -trustout -out aaa-trust-anyeku.pem

# A fake "AAA Certificate Services": same subject, serial, dates, signature
# algorithm and extensions as the real root but another RSA key.  Its DER has
# the same length and the same first 346 bytes (up to the key), so its first
# base64 line equals the real one: a candidate for every searcher that must be
# rejected by the exact DER comparison.
cat > "$K/fake.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
string_mask = utf8only
x509_extensions = ext
[dn]
C = GB
ST = Greater Manchester
L = Salford
O = Comodo CA Limited
CN = AAA Certificate Services
[ext]
subjectKeyIdentifier = A0:11:0A:23:3E:96:F1:07:EC:E2:AF:29:EF:82:A5:7F:D0:30:A4:B4
keyUsage = critical, keyCertSign, cRLSign
basicConstraints = critical, CA:TRUE
crlDistributionPoints = @crl
[crl]
URI.0 = http://crl.comodoca.com/AAACertificateServices.crl
URI.1 = http://crl.comodo.net/AAACertificateServices.crl
EOF
openssl genrsa -out "$K/fake.key" 2048 2>/dev/null
openssl req -x509 -new -config "$K/fake.cnf" -key "$K/fake.key" -sha1 -set_serial 1 \
	-not_before 20040101000000Z -not_after 20281231235959Z -out fake-aaa.pem
openssl x509 -in fake-aaa.pem -outform DER -out fake-aaa.der

# A leaf issued by the fake (its DER contains "AAA Certificate Services" as issuer)
openssl ecparam -name prime256v1 -genkey -noout -out "$K/leaf.key"
openssl req -new -key "$K/leaf.key" -subj /CN=leaf.example -out "$K/leaf.csr"
openssl x509 -req -in "$K/leaf.csr" -CA fake-aaa.pem -CAkey "$K/fake.key" -set_serial 2 \
	-days 3650 -out leaf-fake-aaa.pem 2>/dev/null
openssl x509 -in leaf-fake-aaa.pem -outform DER -out leaf-fake-aaa.der

# Unrelated roots that fill bundles
: > others.pem
for i in 1 2 3; do
	openssl ecparam -name prime256v1 -genkey -noout -out "$K/o$i.key"
	openssl req -x509 -new -key "$K/o$i.key" -subj "/O=emudhra-check tests/CN=Other Test Root $i" \
		-days 3650 -out "$K/o$i.pem"
	{ printf '# Other Test Root %s\n' "$i"; cat "$K/o$i.pem"; } >> others.pem
done

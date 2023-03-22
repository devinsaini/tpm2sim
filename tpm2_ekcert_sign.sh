#!/bin/bash -e
#
# This script mocks a TPM 2.0 manufacturer's Endorsement Key credentials enough
# to run our EKC acceptance tests with a freshly-instantiated TPM 2.0 simulator.
#
# It takes a DER-encoded TPM 2.0 RSA public EK as input, and generates a signed
# X.509v3 certificate with (some of) the unusual extension and encoding
# requirements from the TCG EKC profile specifications.
#
# Usage:
#
#   bash -e code_sign.sh [public.ek.portion.cer]
#
#
# The script will:
#
#  - [as input] take a DER-encoded RSA public key (with a TPM 2.0 public EK)
#  - create a self-signed Root CA certificate
#  - generate a X.509v3 CSR from the TPM's public EK
#  - [as output] generate and sign an X.509v3 EK Credential certificate
#
# The generated CSR and X.509 certificate contain structures specific to TPM
# 2.0 EK Credentials
#
# - This includes SOME of the X509v3 extensions expected from a PC Client
#   Platform TPM manufacturer.
# - This does NOT icomprehensively include all of the guidance documented in
#   "TCG EK Credential Profile for TPM Family 2.0"
#   https://trustedcomputinggroup.org/tcg-ek-credential-profile-tpm-family-2-0/
#
# Notes:
#
#  - Portions of this script were adapted from the impressively polished code
#    at https://gist.github.com/vszakats/7ef9e86506f5add961bae0412ecbe696
#

# /usr/local/opt/openssl/bin/openssl list-cipher-algorithms
# /usr/local/opt/openssl@1.1/bin/openssl list -cipher-algorithms

# yum install --enablerepo=epel -y openssl pwgen

# 2.1 Endorsement Key
#
# Assumed to be a DER-encoded 2048-bit RSA public key (sec 2.1, TCG-EK-CP)

readonly h_ek_pub_crt='0x1c00002'
readonly ek_cert_nvram_attr='0x42072001'

readonly cwd="${PWD}"
readonly base='tpm2_'
readonly root_ca="${base}CA"
readonly ekc="${base}ekc"

readonly pubkey_to_certify=${1:-public.ek.portion.pem}
readonly manufacturer_ca='tpm.manufacturer.test'

readonly verbose_files=${VERBOSE_FILES:-yes}
readonly verbose_files_dir="${VERBOSE_FILES_DIR:-summaries}/"
readonly working_dir="/ekcert/work_dir/"

# ~10 years
readonly ca_cert_validity_days=3652
readonly tpm_cert_validity_days=$ca_cert_validity_days

# FIPS-compatible
readonly keylength=2048



# Redirect stdout securely to non-world-readable files
privout() {
   cd "${working_dir}"; o="$1"; rm -f "$o"; touch "$o"; chmod 0600 "$o"; shift
   (
      "$@"
   ) >> "$o"
   cd - &> /dev/null
}

# Redirect all output securely to non-world-readable files
privall() {
   cd "${working_dir}"; ="$1"; rm -f "$o"; touch "$o"; chmod 0600 "$o"; shift
   (
      "$@"
   ) >> "$o" 2>&1
   cd - &> /dev/null
}

echo "OpenSSL      $(openssl version 2> /dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9a-z]+')"

[ ! -z "${working_dir}" ]       && mkdir -p "${working_dir}"
[ "${verbose_files}" == 'yes' ] && mkdir -p "${verbose_files_dir}"


echo '! Creating self-signed Root CA...'
# https://pki-tutorial.readthedocs.io/en/latest/simple/root-ca.conf.html
# https://en.wikipedia.org/wiki/X.509

readonly root_ca_csr_config="/ekcert/openssl/configs/${root_ca}.csr.config"
readonly root_ca_private_pem="${root_ca}_private.pem"
readonly root_ca_private_der="${root_ca}_private.der"
readonly root_ca_cert="${root_ca}.crt"
readonly root_ca_pass="PASSWORD"
privout "${root_ca}.password" echo "${root_ca_pass}"

# create CA Root
# NOTE: For right now, we're only making a self-signed root CA for our tests

# PKCS #8 private key, encrypted, PEM format.
privout "${root_ca_private_pem}" \
  openssl genpkey -algorithm RSA -aes-256-cbc \
  -pkeyopt rsa_keygen_bits:${keylength} \
  -pass "pass:${root_ca_pass}"

privout "${root_ca}_private.pem.asn1.txt" \
  openssl asn1parse -i -in "${root_ca_private_pem}"


# TODO: add `-strictpem` option to all `openssl asn1parse` commands
#       where a PEM file is expected @ OpenSSL 1.1.0. Otherwise
#       openssl would also process the BEGIN/END separators, leading
#       to occasional processing errors.
#          https://github.com/openssl/openssl/issues/1381#issuecomment-237095795


# PKCS #8 private key, encrypted, DER format.
privout "${root_ca_private_der}" \
  openssl pkcs8 -topk8 -v2 aes-256-cbc \
    -in "${root_ca_private_pem}" -passin "pass:${root_ca_pass}" \
    -outform DER -passout "pass:${root_ca_pass}"

privout "${root_ca}_private.der.asn1.txt" \
  openssl asn1parse -i -inform DER -in "${root_ca_private_der}"

# Sign CA cert
# .crt is certificate (public key + subject + signature)
openssl req -batch -verbose -new -sha256 -x509 \
  -days "${ca_cert_validity_days}"  \
  -key "${working_dir}${root_ca_private_pem}" -passin "pass:${root_ca_pass}" \
  -out "${working_dir}${root_ca_cert}" -config "${root_ca_csr_config}"

openssl x509 -in "${working_dir}/${root_ca_cert}" \
  -text -noout -nameopt utf8 -sha256 -fingerprint \
    > "${working_dir}/${root_ca_cert}.x509.txt"

openssl asn1parse -i -in "${working_dir}/${root_ca_cert}" \
  > "${working_dir}/${root_ca_cert}.asn1.txt"



# Generate a signed  X.509 certificate from the TPM's Endorsment key.
#
# A TPM's private Endorsement Key is inaccessible by design, so only the public
# key is available to create a CSR.
#
# Conceptually, that seems straightforward: an X.509 CSR is essentially a public
# key with additional attributes.  However:
#
#   - A private key is still required to sign the CSR.
#   - Most SSL tools (including `openssl req` are hard-coded to simply generate
#     the public key for the CSR directly from that private key.
#
# This involves several workarounds:
#
#

# most SSL tools ―including `openssl
# req`―require a *private* key to sign a CSR, which then.
#
# So: we create a spurious private key to give to `openssl req` so it will
# create the CSR, then tell `openssl x509` to use our TPM's public key instead
# with the option `-force_pubkey FILE`.

# Even though the CSR will be based on the public key
#
#

echo '! Creating TPM Endorsement Key Certificate...'

readonly ekc_csr_config="/ekcert/openssl/configs/${ekc}.csr.config"
readonly pubkey_basename=${pubkey_to_certify%.*}

openssl rsa -pubin \
  -inform DER -in "${pubkey_to_certify}" -text -noout \
    > "${pubkey_to_certify}.rsa.txt"

openssl asn1parse -i -inform DER -in "${pubkey_to_certify}" \
  > "${pubkey_to_certify}.asn1.txt"

# This creates a private key file that must exist for `openssl req` to run.  The public create
readonly csr_priv_key_pass="PASSWORD"
privout "${ekc}_unused.password" echo "${csr_priv_key_pass}"
privout "${ekc}_unused.private.pem" \
  openssl genpkey -algorithm RSA -aes-256-cbc \
    -pkeyopt rsa_keygen_bits:${keylength} \
    -pass "pass:${csr_priv_key_pass}" 2> /dev/null


openssl req -batch -verbose -new -sha256 \
  -subj '/' \
  -passout "pass:${csr_priv_key_pass}" -keyout "${working_dir}${ekc}_unused.private.pem" \
  -out "${working_dir}${ekc}.csr" -config "${ekc_csr_config}"

if [ "${verbose_files}" == 'yes' ]; then
  openssl asn1parse -i -in "${working_dir}${ekc}.csr" > "${working_dir}${ekc}.csr.asn1.txt"
fi

output_pem_crt="${ekc}.pem.crt"
output_der_crt="${ekc}.der.crt"

# Sign a PEM-encoded certificate
openssl x509  -in "${working_dir}${ekc}.csr" -req \
  -extfile "${ekc_csr_config}" \
  -force_pubkey "${pubkey_to_certify}" -keyform DER  \
  -CA "${working_dir}${root_ca_cert}" -CAkey "${working_dir}${root_ca_private_pem}" \
  -CAcreateserial \
  -passin "pass:${root_ca_pass}" \
  -out "${output_pem_crt}" \
  -extensions v3_req \
  -days ${tpm_cert_validity_days} -sha256

echo 'SIGN DER'
# Sign a DER-encoded certificate
openssl x509  -in "${working_dir}${ekc}.csr" -req \
  -extfile "${ekc_csr_config}" \
  -force_pubkey "${pubkey_to_certify}" -keyform DER  \
  -CA "${working_dir}${root_ca_cert}" -CAkey "${working_dir}${root_ca_private_pem}" \
  -CAcreateserial \
  -passin "pass:${root_ca_pass}" \
  -outform der \
  -out "${output_der_crt}" \
  -extensions v3_req \
  -days ${tpm_cert_validity_days} -sha256

# report
if [ "${verbose_files}" == 'yes' ]; then
  openssl asn1parse -i -in "${output_pem_crt}" \
    > "${working_dir}${ekc}.crt.asn1.txt"
  openssl x509 -in "${output_pem_crt}" -text -noout -nameopt utf8 -sha256 \
    -fingerprint > "${working_dir}${ekc}.crt.x509.txt"
fi


echo "Store EK cert in NVRAM index ${h_ek_pub_crt}"

ek_der_cert_size=$(cat "${output_der_crt}" | wc -c)
# NOTE: if you want to remove existing NVRAM EK cert (at your risk), use the following command
# tpm2_nvrelease -x "${h_ek_pub_crt}" -a "${h_authorization}"
#tpm2_nvdefine -x "${h_ek_pub_crt}" -s "${ek_der_cert_size}" -t "${ek_cert_nvram_attr}"
tpm2_nvdefine "${h_ek_pub_crt}" -C o -s "${ek_der_cert_size}"

#tpm2_nvwrite -x "${h_ek_pub_crt}" "${output_der_crt}"
tpm2_nvwrite "${h_ek_pub_crt}" -C o -i "${output_der_crt}"
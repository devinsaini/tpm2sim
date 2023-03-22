#!/bin/bash

# create endorsement key and save the public part in work dir
tpm2_createek -c 0x81010001 -G rsa -u /ekcert/work_dir/ek.pub

/ekcert/tcgRSApub2PemDer.sh /ekcert/work_dir/ek.pub

/ekcert/tpm2_ekcert_sign.sh /ekcert/work_dir/ek.pub.cer

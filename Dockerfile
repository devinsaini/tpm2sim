FROM strongx509/tpm

COPY tcgRSApub2PemDer.sh /ekcert/tcgRSApub2PemDer.sh
COPY tpm2_ekcert_sign.sh /ekcert/tpm2_ekcert_sign.sh
COPY openssl /ekcert/openssl
COPY install_cert.sh /install_cert.sh
RUN mkdir /ekcert/work_dir

RUN apt-get update
RUN apt-get install xxd

CMD tpm_server
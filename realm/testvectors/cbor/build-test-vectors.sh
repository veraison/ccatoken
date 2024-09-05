#!/bin/bash
# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -eu
set -o pipefail

DIAG_FILES=
DIAG_FILES="${DIAG_FILES} CcaRealmClaimsAll"
DIAG_FILES="${DIAG_FILES} CcaClaimsMissingMandPubKey"
DIAG_FILES="${DIAG_FILES} CcaClaimsMissingMandExtendedMeas"
DIAG_FILES="${DIAG_FILES} CcaClaimsMissingMandInitialMeas"
DIAG_FILES="${DIAG_FILES} CcaRealmClaimsMissingMandNonce"
DIAG_FILES="${DIAG_FILES} CcaClaimsMissingMandHashAlgID"
DIAG_FILES="${DIAG_FILES} CcaRealmLegacyClaimsAll"

TV_DOT_GO=${TV_DOT_GO?must be set in the environment.}

printf "package realm \n\n" > ${TV_DOT_GO}

for t in ${DIAG_FILES}
do
	echo "// automatically generated from $t.diag" >> ${TV_DOT_GO}
	echo "var testEncoded${t} = "'`' >> ${TV_DOT_GO}
	cat ${t}.diag | diag2cbor.rb | xxd -p >> ${TV_DOT_GO}
	echo '`' >> ${TV_DOT_GO}
	gofmt -w ${TV_DOT_GO}
done

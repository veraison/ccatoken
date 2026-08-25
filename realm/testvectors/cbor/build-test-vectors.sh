#!/bin/bash
# Copyright 2022-2026 Contributors to the Veraison project.
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
DIAG_FILES="${DIAG_FILES} v2/CcaRealmClaimsV2All"
DIAG_FILES="${DIAG_FILES} v2/CcaRealmClaimsV2InvalidMECPolicy"
DIAG_FILES="${DIAG_FILES} v2/CcaRealmClaimsV2MissingMECPolicy"
DIAG_FILES="${DIAG_FILES} profile-registry/CcaRealmClaimsRegisteredProfile"
DIAG_FILES="${DIAG_FILES} profile-registry/CcaRealmClaimsUnregisteredProfile"

TV_DOT_GO=${TV_DOT_GO?must be set in the environment.}

printf "package realm \n\n" > ${TV_DOT_GO}

for t in ${DIAG_FILES}
do
	fullpath=${t}
	filename=${t##*/}
	echo "// automatically generated from $fullpath.diag" >> ${TV_DOT_GO}
	echo "var testEncoded${filename} = "'`' >> ${TV_DOT_GO}
	cat ${fullpath}.diag | diag2cbor.rb | xxd -p >> ${TV_DOT_GO}
	echo '`' >> ${TV_DOT_GO}
	gofmt -w ${TV_DOT_GO}
done

#!/bin/bash
# Copyright 2022-2024 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -eu
set -o pipefail

DIAG_FILES=
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsAll"
DIAG_FILES="${DIAG_FILES} CcaPlatformLegacyClaimsAll"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsMandatoryOnly"
DIAG_FILES="${DIAG_FILES} CcaPlatformLegacyClaimsMandatoryOnly"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsInvalidMultiNonce"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsMissingMandatoryNonce"

TV_DOT_GO=${TV_DOT_GO?must be set in the environment.}

printf "package platform\n\n" > ${TV_DOT_GO}

for t in ${DIAG_FILES}
do
	echo "// automatically generated from $t.diag" >> ${TV_DOT_GO}
	echo "var testEncoded${t} = "'`' >> ${TV_DOT_GO}
	cat ${t}.diag | diag2cbor.rb | xxd -p >> ${TV_DOT_GO}
	echo '`' >> ${TV_DOT_GO}
	gofmt -w ${TV_DOT_GO}
done

#!/bin/bash
# Copyright 2022-2026 Contributors to the Veraison project.
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
DIAG_FILES="${DIAG_FILES} v2/CcaPlatformClaimsV2All"
DIAG_FILES="${DIAG_FILES} v2/CcaPlatformClaimsV2MandatoryOnly"
DIAG_FILES="${DIAG_FILES} v2/CcaPlatformClaimsV2MissingClientID"
DIAG_FILES="${DIAG_FILES} v2/CcaPlatformClaimsV2InvalidMfgConfig"
DIAG_FILES="${DIAG_FILES} v2/CcaPlatformClaimsV2InvalidTbbRotpkHashLength"

TV_DOT_GO=${TV_DOT_GO?must be set in the environment.}

printf "package platform\n\n" > ${TV_DOT_GO}

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

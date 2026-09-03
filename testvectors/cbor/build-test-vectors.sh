#!/bin/bash
# Copyright 2022-2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -eu
set -o pipefail

DIAG_FILES=
DIAG_FILES="${DIAG_FILES} CcaTokenRev03"

TV_DOT_GO=${TV_DOT_GO?must be set in the environment.}

printf "package ccatoken\n\n" > ${TV_DOT_GO}

for t in ${DIAG_FILES}
do
	fullpath=${t}
	filename=${t##*/}
	echo "// automatically generated from $fullpath.diag" >> ${TV_DOT_GO}
	echo "// nolint:gosec" >> ${TV_DOT_GO}
	echo "var testGenerated${filename} = "'`' >> ${TV_DOT_GO}
	cat ${fullpath}.diag | diag2cbor.rb | xxd -p >> ${TV_DOT_GO}
	echo '`' >> ${TV_DOT_GO}
	gofmt -w ${TV_DOT_GO}
done

# Copyright 2024 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
import os
import re
import sys

cover_line_re = re.compile(r'ok\s+(?P<package>\S+)\s.*coverage: (?P<pc>[\d.])% of statements')

default_min_cover = float(re.findall(r'\d*\.\d+|\d+', os.environ['GITHUB_WORKFLOW'])[0])

min_cover_map = {}
for arg in sys.argv[1:]:
    package, min_cover_str = arg.split(':')
    min_cover_map[package] = float(min_cover_str)

for line in sys.stdin:
    if 'FAIL' in line:
        print('ERROR: tests failed')
        sys.exit(1)

    match = cover_line_re.search(line)
    if match is None:
        continue

    package = match.group('package')
    cover = float(match.group('pc'))
    min_cover = min_cover_map.get(package, default_min_cover)

    if cover < min_cover:
        sys.exit(1)

sys.exit(0)

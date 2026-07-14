# This tool will go through all the dmp files and apply some formatting fixes.

import os
import re

BASE_PATH = '/Users/erocarrera/Devel/pefile/tests/test_files'

parse_date_line = re.compile('.*TimeDateStamp:\s+0x[a-fA-F0-9]+\s+\[')

def process_file(filepath):
    print(f'Processing file: {filepath}')
    lines = []
    with open(filepath) as f:
        data = f.read()
        # with open(filepath+'.bak_20190929', 'w') as bak:
        #     bak.write(data)
        for line in data.split('\n'):
            if line == '----------DOS_HEADER----------':
                if lines and lines[0] == '----------Parsing Warnings----------':
                    print('Warnings found')
                    lines = (
                        ['----------Parsing Warnings----------', '',] +
                        [l for l in lines[1:-1] if l] +
                        ['',])
            if line.strip() == 'DllCharacteristics:':
                continue
            if parse_date_line.match(line):
                lines.append(re.sub(
                    r'(TimeDateStamp:\s+0x[a-fA-F0-9]+)\s+\[', r'\1 [', line))
            else:
                lines.append(line.rstrip())
    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))
    # print('\n'.join(lines))
    # os.sys.exit()

for (dirpath, dirnames, filenames) in os.walk(BASE_PATH):
    dmp_files = [fname for fname in filenames if fname.endswith('.dmp')]
    print(f'Processing directory: {dirpath}, which has {len(dmp_files)} files')
    # print(f'Files: {dmp_files}')
    for dmp_file in dmp_files:
        process_file(os.path.join(dirpath, dmp_file))

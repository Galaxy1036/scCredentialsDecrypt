# -*- coding: utf-8 -*-

import os
import json
import argparse

from io import BytesIO, BufferedReader


def decrypt_xor(data, key):
    return bytes([chunk ^ key[index % len(key)] for index, chunk in enumerate(data)])


def read_string(data):
    string_length = int.from_bytes(data.read(2), 'big')
    return data.read(string_length).decode('utf-8')


def parse(data):
    output = []

    while data.peek():
        log_length = int.from_bytes(data.read(1), 'big')
        actual_log = {}

        for i in range(log_length // 2):

            key = read_string(data)
            value = read_string(data)
            actual_log[key] = value

        output.append(actual_log)

    return json.dumps(output, indent=4)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A little script that aim to decrypt and dump .sce log files')
    parser.add_argument('files', help='.sce files to decrypt and dump', nargs='+')

    args = parser.parse_args()

    for file in args.files:
        if os.path.isfile(file):
            if file.endswith('.sce'):
                with open(file, 'rb') as f:
                    unxored = BufferedReader(BytesIO(decrypt_xor(f.read(), b'secrets.')))
                    parsed  = parse(unxored)

                    with open('dumped_{}.json'.format(os.path.splitext(file)[0]), 'w') as j:
                        j.write(parsed)

            else:
                print('[*] Only .sce are supported !')

        else:
            print('[*] {} don\'t exists !'.format(file))

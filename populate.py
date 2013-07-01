#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import sys
import redis
import time

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
            default=sys.stdin, help='List of domains from stdin or a text file.')
    args = parser.parse_args()

    r = redis.Redis(unix_socket_path='./redis.sock')
    while True:
        try:
            r.ping()
            break
        except:
            time.sleep(1)

    p = r.pipeline(False)

    for line in args.infile:
        domain = line.strip()
        if len(domain) == 0:
            continue
        p.sadd('domains', domain)
    # copy the key
    p.sunionstore('to_process_domains', 'domains')
    p.execute()


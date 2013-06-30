#!/usr/bin/python
# -*- coding: utf-8 -*-

import redis
import csv

if __name__ == '__main__':
    r = redis.Redis(unix_socket_path='./redis.sock')
    with open('dump.txt', 'w') as f:
        w = csv.writer(f)
        for domain in r.smembers('domains'):
            for ip in r.smembers(domain):
                dates = list(r.smembers(ip))
                dates.sort()
                day = dates[-1]
                entries = r.hgetall(ip + '|' + day)
                for port, cipher in r.hgetall(ip + '|' + day).iteritems():
                    w.writerow([domain, ip, port, cipher])



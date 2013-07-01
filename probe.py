#!/usr/bin/python
# -*- coding: utf-8 -*-

import smtplib
import redis
import datetime
import argparse
import sys
import pprint

timeout = 10
r = None

def probe(host, port, force_ssl = False):
    """
        force_ssl means no startssl
    """
    to_return = {'host': host, 'port': port}
    if force_ssl:
        smtp = smtplib.SMTP_SSL
    else:
        smtp = smtplib.SMTP

    try:
        s = smtp(host, port, timeout=timeout)
    except Exception as e:
        to_return['error'] = 'Unable to connect to {}:{} : {}'.format(host,
                                port, e)
        return to_return

    if not force_ssl:
        try:
            code, msg = s.starttls()
            if code != 220:
                to_return['error'] = 'STARTTLS error on {}:{} : {}'.format(host,
                                        port, e)
                return to_return
        except Exception as e:
            to_return['error'] = 'Global error on {}:{} : {}'.format(host,
                                    port, e)
            return to_return

    # get details
    to_return['cipher_name'], to_return['version'], to_return['size'] = s.sock.cipher()
    to_return['ip'], to_return['port'] = s.sock.getpeername()
    to_return['peercert'] = s.sock.getpeercert(True)
    return to_return


def historize(p, data):
    day = datetime.date.today().isoformat()
    if data.get('error') is not None:
        return False
    if r.sismember(data['host'], data['ip']):
        dates = list(r.smembers(data['ip']))
        dates.sort()
        if day in dates:
            return False
        cipher = r.hget(data['ip'] + '|' + str(dates[-1]), port)
        if cipher == data['cipher_name']:
            return False
    else:
        p.sadd(data['host'], data['ip'])
        p.sadd(data['ip'], day)
    p.hset(data['ip'] + '|' + day, port, data['cipher_name'])
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--history', action='store_true', default=False,
            help='Save the informations related to the server in a redis backend.')
    g.add_argument('domains', nargs='?', type=argparse.FileType('r'),
            default=sys.stdin, help='List of domains from stdin or a text file.')
    args = parser.parse_args()

    if args.history:
        r = redis.Redis(unix_socket_path='./redis.sock')
        while True:
            domain = r.spop('to_process_domains')
            if domain is None:
                break
            p = r.pipeline(False)
            for port in [25, 587, 465]:
                out = probe(domain, port, (port==465))
                historize(p, out)
            p.execute()
    else:
        for domain in args.domains:
            domain = domain.strip()
            if len(domain) == 0:
                continue
            for port in [25, 587, 465]:
                out = probe(domain, port, (port==465))
                pp = pprint.PrettyPrinter(depth=6)
                pp.pprint(out)

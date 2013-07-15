#!/usr/bin/python
# -*- coding: utf-8 -*-

import ssl
from OpenSSL import crypto
import smtplib
redis_package = True
try:
    import redis
except:
    redis_package = False
import datetime
from dateutil import parser
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
    to_return['cipher_name'], to_return['version'], to_return['size'] \
            = s.sock.cipher()
    to_return['ip'], to_return['port'] = s.sock.getpeername()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM,
            ssl.DER_cert_to_PEM_cert(s.sock.getpeercert(True)))
    to_return['peercert'] = __prepare_cert(cert)
    return to_return

def __prepare_cert(cert):
    to_return = {}
    to_return['issuer'] = cert.get_issuer().get_components()
    #to_return['pubkey'] = cert.get_pubkey()
    to_return['serial_number'] = cert.get_serial_number()
    try:
        to_return['signature_algorithm'] = cert.get_signature_algorithm()
    except:
        to_return['signature_algorithm'] = None
    to_return['subject'] = cert.get_subject().get_components()
    to_return['version'] = cert.get_version()
    to_return['notBefore'] = cert.get_notBefore()
    if cert.get_notBefore() is not None:
        to_return['notBefore'] = parser.parse(cert.get_notBefore())
    if cert.get_notAfter() is not None:
        to_return['notAfter'] = parser.parse(cert.get_notAfter())
    to_return['digest_sha256'] = cert.digest('sha256')
    return to_return


def historize(p, data):
    day = datetime.date.today().isoformat()
    if data.get('error') is not None:
        return False
    if r.sismember(data['host'], data['ip']):
        dates = list(r.smembers(data['ip']))
        dates.sort(reverse=True)
        if day in dates:
            return False
        # Is it sane to assume the cert will be the same on all the ports ?
        digest = r.hget(data['ip'] + '|' + str(dates[0]), 'digest')
        if digest == data['peercert']['digest_sha256']:
            return False
    else:
        p.sadd(data['host'], data['ip'])
        p.sadd(data['ip'], day)
    p.hmset(data['ip'] + '|' + day, {port: data['cipher_name'],
        'digest': data['peercert']['digest_sha256']})
    return True

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument('--history', action='store_true', default=False,
            help='Save the informations related to the server in a redis backend.')
    g.add_argument('domains', nargs='?', type=argparse.FileType('r'),
            default=sys.stdin, help='List of domains from stdin or a text file.')
    args = p.parse_args()

    if args.history:
        if not redis_package:
            sys.exit('redis module unavailable.')
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

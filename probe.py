#!/usr/bin/python
# -*- coding: utf-8 -*-

import smtplib
import redis
import datetime
from dateutil import parser

timeout = 10
r = None

def try_host(p, host, port, force_ssl = False):
    """
        force_ssl means no startssl
    """
    day = datetime.date.today().isoformat()
    if not force_ssl:
        smtp = smtplib.SMTP
    else:
        smtp = smtplib.SMTP_SSL
    try:
        s = smtp(host, port, timeout=timeout)
    except Exception as e:
        #print(host, port, 'Not working')
        return False
    starttls = False
    if not force_ssl:
        try:
            code, msg = s.starttls()
            if code != 220:
                #print(host, port, msg)
                return False
            else:
                starttls = True
        except Exception as e:
            #print(host, port, e)
            return False
    # get details
    cipher_name, version, size = s.sock.cipher()
    ip, port = s.sock.getpeername()
    if r.sismember(host, ip):
        dates = list(r.smembers(ip))
        dates.sort()
        if day in dates:
            return False
        cipher = r.hget(ip + '|' + str(dates[-1]), port)
        if cipher == cipher_name:
            return False
    else:
        p.sadd(host, ip)
        p.sadd(ip, day)
    p.hset(ip + '|' + day, port, cipher_name)
    return True


if __name__ == '__main__':
    r = redis.Redis(unix_socket_path='./redis.sock')
    while True:
        domain = r.spop('to_process_domains')
        if domain is None:
            break
        p = r.pipeline(False)
        for port in [25, 587, 465]:
            try_host(p, domain, port, (port==465))
        p.execute()


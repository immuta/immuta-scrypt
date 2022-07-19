'''
Ported to python from scrypt-kdf javascript library, contains much of the
original authors' comments

https://github.com/chrisveness/scrypt-kdf/blob/335b5da29a77f4004a2d5cb1fa137bdf842d82ca/scrypt.js
'''
import argparse
import base64
import hashlib
import hmac
import math
import psutil
import time

from secrets import token_bytes

import pydash as py_
import scrypt


def kdf(password, log_n=15, r=8, p=1):
    log_n = round(log_n)
    r = round(r)
    p = round(p)

    # range-check log_n, r, p
    assert(not math.isnan(log_n) and type(log_n) is int), 'log_n must be an integer'
    assert(log_n >= 1 and log_n <= 30), 'log_n must be between 1 and 30'
    assert(not math.isnan(r) and type(r) is int and r > 0), 'r must be a positive integer'
    assert(not math.isnan(p) and type(p) is int and p > 0), 'p must be a positive integer'
    assert((p * r) <= (2**30 - 1)), 'p * r must be <= 2^30-1'

    # create buffer
    buff = bytearray(96)

    # create salt as random 32 bytes
    salt = token_bytes(32)

    # add 'scrypt', params, and salt to the buffer
    buff[0:6] = 'scrypt'.encode('utf-8')
    buff[7:8] = log_n.to_bytes(1, byteorder='little', signed=False)
    buff[8:12] = r.to_bytes(4, byteorder='big', signed=False)
    buff[12:16] = p.to_bytes(4, byteorder='big', signed=False)
    buff[16:48] = salt

    # add checksum of params and salt to buffer
    prefix48 = buff[0:48]
    checksum = hashlib.sha256()
    checksum.update(prefix48)
    checksum_digest = checksum.digest()
    buff[48:64] = checksum_digest[0:16]

    try: # to add HMAC hash from scrypt-derived key to the buffer
        # apply scrypt kdf to salt to derive hmac key
        hmac_key = scrypt.hash(password, salt, N=2**log_n, r=r, p=p, buflen=64)

        # get HMAC hash of params, salt, and checksum, using first 32 bytes of scrypt hash as the key
        prefix64 = buff[0:64]
        hmac_hash = hmac.new(hmac_key[32:64], digestmod='sha256')
        hmac_hash.update(prefix64)
        hmac_digest = hmac_hash.digest()
        buff[64:96] = hmac_digest

        return base64.b64encode(buff).decode()
    except Exception as e: # e.g. memory limit exceeded; localise error to this function
        print(f'Memory limit exceeded: {e}')
        raise

def pick_params(maxtime, maxmem=psutil.virtual_memory().total, maxmemfrac=0.5):
    # ensure maxmem and maxmemfrac are valid
    if (maxmem == 0 or maxmem == None): maxmem = psutil.virtual_memory()[0]
    if (maxmemfrac == 0 or maxmemfrac > 0.5): maxmemfrac = 0.5

    # memory limit is memfrac * physical memory, no more than maxmem and no less than 1MiB
    physical_memory = psutil.virtual_memory().total
    memlimit = max(min(physical_memory * maxmemfrac, maxmem), 1024 * 1024)

    # Colin Percival measures how many scrypts can be done in one clock tick using C/POSIX
    # clock_getres() / CLOCKS_PER_SEC (usually just one?); we will use performance.now() to get
    # a DOMHighResTimeStamp. (Following meltdown/spectre timing attacks Chrome reduced the high
    # res timestamp resolution to 100µs, so we'll be conservative and do a 1ms run - typically
    # 1..10 minimal scrypts).
    i = 0
    start = time.process_time() * 1000
    while (time.process_time() * 1000) - start < 1:
        scrypt.hash('', '', N=128, r=1, p=1, buflen=64)
        i += 512 # we invoked the salsa20/8 core 512 times

    duration = (time.process_time() - start) # in seconds
    ops = i / duration

    # allow a minimum of 2^15 salsa20/8 cores
    opslimit = max(ops * maxtime, 2**15)
    r = 8

    # memory limit requires that 128*N*r <= memlimit
    # CPU limit requires that 4*N*r*p <= opslimit
    # if opslimit < memlimit/32, opslimit imposes the stronger limit on N

    p = None
    log_n = 0
    if opslimit < (memlimit / 32):
        p = 1 # set p = 1 and choose N based on CPU limit
        max_n = opslimit / (r * 4)
        while ((1 << log_n) <= (max_n / 2)) and (log_n < 63): log_n += 1
    else:
        max_n = memlimit / (r * 128) # set N based on the memory limit
        while ((1 << log_n) <= (max_n / 2)) and (log_n < 63): log_n += 1
        maxrp = min((opslimit / 4) / (1 << log_n), 0x3fffffff) # choose p based on the CPU limit
        p = round(maxrp / r)

    return (log_n, r, p)


def main():
    # parse arguments
    parser = argparse.ArgumentParser(description='Scrypt password-based key derivation function')
    parser.add_argument('password', metavar='p', type=str, help='password to derive a key from')
    args = parser.parse_args()

    # derive key from password
    log_n, r, p = pick_params(0.1)
    derivation = kdf(args.password, log_n=log_n, r=r, p=p)
    print(derivation)


if __name__ == '__main__':
    main()

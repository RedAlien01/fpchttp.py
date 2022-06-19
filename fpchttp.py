import threading
import requests
import argparse
import queue
import sys
import re


# configuration
FINGERPRINT = (
    r'HTTP/1.1 401 Unauthorized\r\n',
    r'WWW-Authenticate'
)


def get_response_raw(res):
    """ Format response to raw HTTP response packet.
    Formats requests response object toa raw HTTP response packet.
    Args:
        res (requests.models.Response): requests response instance.
    Returns:
        str: requests response instance in raw HTTP response packet format.
    """
    return 'HTTP/1.1 %(status)d %(reason)s\r\n%(headers)s\r\n\r\n%(body)s' % {
        'status'    : res.status_code,
        'reason'    : res.reason,
        'headers'   : '\r\n'.join([f'{k}:{v}' for k, v in res.headers.items()]),
        'body'      : res.text
    }


def check_thread():
    """ HTTP fingerprint checker thread.
    
    Fetches host from host-queue, sends a HTTP request
    and matches fingerprints in the raw HTTP response.
    """
    while True:
        ip = q.get()

        try:
            res = requests.get(f'http://{ip}:{args.port}{args.endpoint}', headers={'Connection': 'close'}, timeout=args.timeout, verify=False)

            raw_res = get_response_raw(res)

            with thread_lock:
                if all([bool(re.search(f, raw_res)) for f in FINGERPRINT]):
                    print(f'| \x1b[32m{ip}\x1b[0m')
                    print(ip, file=open(args.out, 'a'))

                elif args.verbose >= 1:
                    print(f'| \x1b[31m{ip}\x1b[0m')                

        except Exception:
            if args.verbose >= 2:
                with thread_lock:
                    print(f'| \x1b[33m{ip}\x1b[0m')

        q.task_done()


if __name__ == '__main__':
    print('\nsimple http fingerprint checker')

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-l', '--list', help='host list file', dest='list')
    parser.add_argument('-o', '--out', help='out host file', dest='out')
    parser.add_argument('-T', '--threads', help='threads count', dest='threads', type=int, default=10)
    parser.add_argument('-p', '--port', help='target http port', dest='port', type=int, default=80)  # TODO: multiple port support
    parser.add_argument('-e', '--endpoint', help='target http endpoint', dest='endpoint', default='/')
    parser.add_argument('-t', '--timeout', help='connection timeout', dest='timeout', type=float, default=5.0)
    parser.add_argument('-v', '--verbose', help='verbose output mode', dest='verbose', type=int, default=0)

    args = parser.parse_args()

    # output current configuration
    print('> threads     :', args.threads)
    print('> url example :', f'http://127.0.0.1:{args.port}{args.endpoint}')
    print('> fingerprint :', '  '.join(FINGERPRINT))

    # output color code explanation
    print('\n\x1b[42m  \x1b[0m ok', end='  ')
    print('\x1b[43m  \x1b[0m timed out', end='  ')
    print('\x1b[41m  \x1b[0m fingerprint not matching\n')

    thread_lock = threading.Lock()
    q = queue.Queue()

    # start checking hosts
    print('[*] starting...')

    if args.list:
        with open(args.list) as f:
            ips = [ip.strip() for ip in f.readlines() if ip.strip()]
    else:

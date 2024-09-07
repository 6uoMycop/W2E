'''
* \file   w2e_reachability_test.py
* \brief  Automatic reachability test tries to connect to sites in a file and counts statistics (Windows)
*         Usage: python .\w2e_reachability_test.py .\sites1000.txt
*
* \author 6uoMycop
* \date   September 2024
'''


import sys
import signal
import os
from subprocess import Popen
from time import time, strftime, localtime

# Test file
filename = None

# Results
ctr_all = 0   # Total number of tested links
ctr_ok  = 0   # Number of passed tests
r_dns   = []  # DNS error sites
r_err   = []  # Unreachable sites

# Test start localtime
time_start_local = None


# Present results
def results():
    # Results filename
    results_fname = strftime('%y%m%d_%H%M%S_', time_start_local) + filename.split('\\')[-1].split('.')[0] + '.txt'

    ctr_dns = len(r_dns)
    ctr_err = len(r_err)

    os.write(sys.stdout.fileno(), b'\nTotal links tested:   ') 
    os.write(sys.stdout.fileno(), bytes(str(ctr_all), 'utf-8'))
    os.write(sys.stdout.fileno(), b'\n    Tests passed:     ') 
    os.write(sys.stdout.fileno(), bytes(str(ctr_ok), 'utf-8'))
    os.write(sys.stdout.fileno(), b'\n    Errors:           ') 
    os.write(sys.stdout.fileno(), bytes(str(ctr_dns + ctr_err), 'utf-8'))
    os.write(sys.stdout.fileno(), b'\n        DNS:          ') 
    os.write(sys.stdout.fileno(), bytes(str(ctr_dns), 'utf-8'))
    os.write(sys.stdout.fileno(), b'\n        Connection:   ') 
    os.write(sys.stdout.fileno(), bytes(str(ctr_err), 'utf-8'))
    os.write(sys.stdout.fileno(), b'\n\nDetailed stats file:')
    os.write(sys.stdout.fileno(), bytes(results_fname, 'utf-8'))

    with open(results_fname, mode='w') as f:
        f.write('TEST START: ')
        f.write(strftime('%x %X', localtime()))
        f.write('\nTEST FILE:  ')
        f.write(filename)
        f.write('\n')
        f.write('\nTotal links tested:   ')
        f.write(str(ctr_all))
        f.write('\n    Tests passed:     ')
        f.write(str(ctr_ok))
        f.write('\n    Errors:           ')
        f.write(str(ctr_dns + ctr_err))
        f.write('\n        DNS:          ')
        f.write(str(ctr_dns))
        f.write('\n        Connection:   ')
        f.write(str(ctr_err))
        f.write('\n')

        if len(r_dns):
            f.write('\nDNS error links:')
            f.write(str(ctr_dns))
            f.write('\n')
            for e in r_dns:
                f.write(e)

        if len(r_err):
            f.write('\nConnection error links:')
            f.write(str(ctr_err))
            f.write('\n')
            for e in r_err:
                f.write(e)


# SIGINT handler (not to lose results on interrupt)
def signal_handler(sig, frame):
    os.write(sys.stdout.fileno(), b'\nTEST INTERRUPT')

    # Print results
    results()

    exit(0)


# Test a URL routine
#   cURL ret codes
#     0  - OK
#     2  - SYNTAX ERROR - shouldn't happen
#     6  - DNS error
#     28 - Timeout
#     35 - Connection reset
#     56 - Recv failure: Connection was reset
def test(url, timeout=2, verbose=False):
    cmd = 'curl -s --connect-timeout ' + str(timeout) + ' --max-time ' + str(timeout) + ' --output NUL '

    proc = Popen((cmd + url).split())
    proc.wait()
    ret = proc.returncode

    if verbose:
        print('Ret:', ret, '\t', url)

    return ret


# Takes filename as an argument.
# File contains list of URLs to test, each on a new line.
if __name__ == '__main__':
    filename = sys.argv[1]

    signal.signal(signal.SIGINT, signal_handler)

    print('Test file:', filename)
    print('----------')

    time_start_local = localtime()
    t_start = time()

    with open(filename, mode='r') as f:
        for url in f:
            # Execute test
            ret = test(url)
            # Result processing
            if ret == 0:  # OK
                ctr_ok += 1
            elif ret == 6:  # DNS
                r_dns.append(url)
            elif ret == 2:  # Syntax -- wtf
                print('SYNTAX ERROR')
                exit(1)
            else:  # Unreachable
                r_err.append(url)
                
            ctr_all += 1
            # Print time
            print('URLs checked:', ctr_all, '\tTime elapsed:', round(time() - t_start, 1), 's', end='\r')

    # Print results
    results()

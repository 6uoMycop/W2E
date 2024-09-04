'''
* \file   w2e_reachability_test.py
* \brief  Automatic reachability test tries to connect to sites in a file and counts statistics (Windows)
*         Usage: python .\w2e_reachability_test.py .\sites.txt
*
* \author 6uoMycop
* \date   September 2024
'''


import sys
from subprocess import Popen
from time import time


# Test a URL routine
#     cURL ret codes
#     0 - OK
#     2 - SYNTAX ERROR - shouldn't happen
#     6 - DNS error
#     28 - Timeout
#     35 - Connection reset
#     56 - Recv failure: Connection was reset
def test(url):
    cmd = 'curl -s --connect-timeout 2 --max-time 2 --output NUL '
    #print('Try:', url)

    proc = Popen((cmd + url).split())
    proc.wait()
    ret = proc.returncode

    #print('Ret:', ret, '\t', url)

    return ret


# Takes filename as an argument.
# File contains list of URL's to test, each on a new line.
if __name__ == '__main__':
    filename = sys.argv[1]

    # Results
    ctr_all = 0  # Total number of tested links
    ctr_ok = 0  # Number of passed tests
    r_dns = []  # DNS error sites
    r_err = []  # Unreachable sites

    print('Test file:', filename)
    print('----------')

    t_start = time()

    with open(filename, mode='r') as f:
        for url in f:
            ctr_all += 1
            # Execute test
            ret = test(url)
            # Result processing
            if ret == 0:  # OK
                ctr_ok += 1
            elif ret == 6:  # DNS
                r_dns.append(url)
            elif ret == 2:  # Syntax -- wtf
                print('SYNTAX ERROR')
                break
            else:  # Unreachable
                r_err.append(url)

            # Print time
            print('URLs checked:', ctr_all, '\tTime elapsed:', round(time() - t_start, 1), 's', end='\r')

    # Present results
    print()
    print('Total links tested: ', ctr_all)
    print('Tests passed:       ', ctr_ok)
    print('DNS errors:         ', len(r_dns))
    print('Connection errors:  ', len(r_err))
    print()

    if len(r_dns):
        print('DNS error links:')
        for e in r_dns:
            print(e)
        print()

    if len(r_err):
        print('Connection error links:')
        for e in r_err:
            print(e)
        print()

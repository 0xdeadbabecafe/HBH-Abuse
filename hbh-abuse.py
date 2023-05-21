# credit to github.com/ndavison
# modified by github.com/alexanderjvking
# Features added:
## Proxying to Burp Suite (-p [all, no-verify, findings])
## Enter other Hop by Headers ie Keep-Alive, Transfer-Encoding, TE, Connection,
#### Trailer, Upgrade, Proxy-Authorization and Proxy-Authenticate
## read from File
## output file if you don't want to use Burp proxy but still want easy to copy request
#### for Repeater
## choice of only including the hop by hop header you provide (ran into an issue with
#### akamai blocking the 'Connection' header if a comma was present)
## adding a custom user-agent if needed for bug-bounty etc.
## Custom timing delay between requests
## Also added colors so in verbose mode potential findings are easier to see

import requests
import random
import string
from time import sleep
from os import path
from os import environ
from argparse import ArgumentParser
from urllib.parse import urlparse

ascii_art = (r'''


 ,--.-,,-,--,   _,.---._        _ __                           ,--.-,,-,--,   _,.---._        _ __
/==/  /|=|  | ,-.' , -  `.   .-`.' ,`.   _..---. ,--.-.  .-,--/==/  /|=|  | ,-.' , -  `.   .-`.' ,`.
|==|_ ||=|, |/==/_,  ,  - \ /==/, -   \.' .'.-. /==/- / /=/_ /|==|_ ||=|, |/==/_,  ,  - \ /==/, -   \
|==| ,|/=| _|==|   .=.     |==| _ .=. /==/- '=' \==\, \/=/. / |==| ,|/=| _|==|   .=.     |==| _ .=. |
|==|- `-' _ |==|_ : ;=:  - |==| , '=',|==|-,   ' \==\  \/ -/  |==|- `-' _ |==|_ : ;=:  - |==| , '=',|
|==|  _     |==| , '='     |==|-  '..'|==|  .=. \ |==|  ,_/   |==|  _     |==| , '='     |==|-  '..'
|==|   .-. ,\\==\ -    ,_ /|==|,  |   /==/- '=' ,|\==\-, /    |==|   .-. ,\\==\ -    ,_ /|==|,  |
/==/, //=/  | '.='. -   .' /==/ - |  |==|   -   / /==/._/     /==/, //=/  | '.='. -   .' /==/ - |
`--,---.-`--`   `--`--''   `--`---'  `-,-,--._,'  ,----.      `--`-' `-`--`   `--`--''   `--`---'
 .--.'  \       _..---.  .--.-. .-.-.,-.'-  _\ ,-.--` , \
 \==\-/\ \    .' .'.-. \/==/ -|/=/  /==/_ ,_.'|==|-  _.-`
 /==/-|_\ |  /==/- '=' /|==| ,||=| -\==\  \   |==|   `.-.
 \==\,   - \ |==|-,   ' |==|- | =/  |\==\ -\ /==/_ ,    /
 /==/ -   ,| |==|  .=. \|==|,  \/ - |_\==\ ,\|==|    .-'
/==/-  /\ - \/==/- '=' ,|==|-   ,   /==/\/ _ |==|_  ,`-._
\==\ _.\=\.-|==|   -   //==/ , _  .'\==\ - , /==/ ,     /
 `--`       `-._`.___,' `--`..---'   `--`---'`--`-----``


''')

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class HBHToFile:
    def __init__(self, res_choice, res_num, output_file, url, hbh_header):
        self.res_choice = res_choice
        self.res_num = res_num
        self.output_file = output_file
        self.url = url
        self.hbh_header = hbh_header
        
    def open_file(self):
        self.hbhout = open(self.output_file, 'w')
        
    #Chooses request or response delimiter to write to file
    def choose_intro(self, intro_choice):
        return getattr(self, 'intro_' + str(intro_choice), lambda: default)()
        
    def intro_1(self):
        return '''----------Initial Request to %s----------

''' % (self.res_choice.request.url)

    def intro_2(self):
        return '''----------Hop By Hop Header: %s Request to %s----------

''' % (self.hbh_header, self.res_choice.request.url)

    def intro_3(self):
        return '''----------Response from %s----------

''' % (self.res_choice.request.url)
    
    def outro_1(self):
    #adds footer to request or response
        return '''

----------END----------



'''
        
    def write_req(self):
        #writing the request and response to the file
        #python is dumb so you have to do some BS to get it looking like a request again
        #URL param is missing
        firstline = '%s %s HTTP/1.1\n' % (self.res_choice.request.method, urlparse(self.url).path)
        hostline = 'Host: %s\n' % urlparse(self.url).hostname
        self.hbhout.write(self.choose_intro(self.res_num))
        self.hbhout.write(firstline)
        self.hbhout.write(hostline)
        for header_name, header_content in self.res_choice.request.headers.items():
            self.hbhout.write(header_name + ':' + header_content + '\n')
        self.hbhout.write('\n\n')
        if self.res_choice.request.body:
            self.hbhout.write(self.res_choice.request.body)
        self.hbhout.write(self.outro_1())
        #now for the response
        self.hbhout.write(self.intro_3())
        self.hbhout.write('HTTP/1.1 ' + str(self.res_choice.status_code) + '\n')
        for header_name, header_content in self.res_choice.headers.items():
            self.hbhout.write(header_name + ':' + header_content + '\n')
        self.hbhout.write('\n\n')
        self.hbhout.write(self.res_choice.text)
        self.hbhout.write(self.outro_1())

class ProxySettings:
    def find_proxy_arg(self, proxy, only_findings_flag):
        self.proxy = proxy
        self.only_findings_flag = only_findings_flag
        if self.proxy != False and self.proxy != 'no-verify' and self.only_findings_flag == False:
            self.proxy_all()
        if self.proxy != False and self.proxy != 'no-verify' and self.only_findings_flag == True:
            self.proxy_findings()
        if self.proxy == 'no-verify':
            self.proxy_no_verify()
        else:
            self.proxy_no_proxy()
        return self.proxies, self.verify
        
    def proxy_all(self):
        try:
            path.exists(self.proxy)
        except FileNotFoundError:
            print("File name does not exist; trying to continue in no-verify mode")
            self.proxy_no_verify()
        environ["REQUESTS_CA_BUNDLE"] = self.proxy
        environ["HTTP_PROXY"] = "127.0.0.1:8080"
        environ["HTTPS_PROXY"] = "127.0.0.1:8080"
        self.proxies = {"http": "", "https": ""}
        self.verify = True
        
    def proxy_findings(self):
        try:
            path.exists(self.proxy)
        except FileNotFoundError:
            print("File name does not exist; trying to continue in no-verify mode")
            self.proxy_no_verify()
        self.read_burp_cert = open(self.proxy,'r')
        self.ca_contents = read_proxy.read()
        self.environ["REQUESTS_CA_BUNDLE"] = ca_contents
        self.proxies = {"http": "", "https": ""}
        self.verify = True
        
    def proxy_no_verify(self):
        self.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        self.verify = False
        
    def proxy_no_proxy(self):
        self.proxies = {"http": "", "https": ""}
        self.verify = True

class HBHHeaders:
    def __init__(self, hbh_header, cli_headers, file_headers):
        self.hbh_header = hbh_header
        self.cli_headers = cli_headers
        self.file_headers = file_headers
    #used to make file origination and cli origination the same
    def clean_header_lists(self):
        if self.file_headers != False:
            new_line_file = open(self.file_headers, 'r')
            file_data = new_line_file.read()
            self.header_list = self.file_data.replace('\n',',')
        elif self.cli_headers != False and self.file_headers != False:
            self.header_list = str(self.cli_headers)+str(self.header_list)
        else:
            self.header_list = self.cli_headers
        self.header_list = self.header_list.split(',')
        return self.header_list
        
    def get_header(self, custom_ua, no_keep_alive, count):
        self.custom_ua = custom_ua
        self.no_keep_alive = no_keep_alive
        self.count = count
        if self.no_keep_alive == False:
            self.headers = {
                '%s' % self.hbh_header: 'keep-alive, %s' % self.header_list[self.count]
            }
        else:
            self.headers = {
                '%s' % self.hbh_header: '%s' % self.header_list[self.count]
            }
        #custom User-Agent works well for bug bounties that require hackerone in the UA
        if self.custom_ua != False:
            self.headers.update({'User-Agent': '%s' % self.custom_ua})
        return self.headers

class HBHRequests:
    def __init__(self, verb, url, data, proxies, time):
        self.verb = verb
        self.url = url
        self.data = data
        self.proxies = proxies
        self.time = time
        
        if self.data != False:
            self.data=self.data.replace('\\n','\n')
        else:
            self.data = ''

    def cache_bust_param(self):
        letters = string.ascii_lowercase
        params = {
            'cb': ''.join(random.choice(letters) for i in range(10))
        }
        return params

    def first_request(self):
        try:
            params_1 = self.cache_bust_param()
            request_1 = requests.request(self.verb, self.url, params=params_1, data=self.data, proxies=self.proxies[0], allow_redirects=False, verify=self.proxies[1])
            sleep(self.time/1000)
            return request_1
        except requests.exceptions.ConnectionError as e:
            print(e)
            exit(1)

    def hop_by_hop_request(self, header):
        self.header = header
        try:
            self.params_2 = self.cache_bust_param()
            request_2 = requests.request(self.verb, self.url, params=self.params_2, headers=self.header, data=self.data, proxies=self.proxies[0], allow_redirects=False, verify=self.proxies[1])
            sleep(self.time/1000)
            return request_2
        except requests.exceptions.ConnectionError as e:
            print(e)
            exit(1)

    def cache_request(self):
        try:
            request_3 = requests.request(self.verb, self.url, params=self.params_2, data=self.data, proxies=self.proxies[0], allow_redirects=False, verify=self.proxies[1])
            sleep(self.time/1000)
            return request_3
        except requests.exceptions.ConnectionError as e:
            print(e)
            exit(1)

    def potential_finding_to_proxy(self):
        print(f'{bcolors.OKGREEN}+++check your Burp Proxy History for the requests+++{bcolors.ENDC}')
        environ["HTTP_PROXY"] = "127.0.0.1:8080"
        environ["HTTPS_PROXY"] = "127.0.0.1:8080"
        self.request_1 = requests.request(self.verb, self.url, params=self.param_1, data=self.data, allow_redirects=False)
        sleep(args.timing/1000)
        self.request_2 = requests.request(self.verb, self.url, headers=self.headers, params=self.params_2, data=self.data, allow_redirects=False)
        sleep(args.timing/1000)
        environ.pop("HTTP_PROXY", None)
        environ.pop("HTTPS_PROXY", None)
        
def get_args():
    parser = ArgumentParser(description="Attempts to find hop-by-hop header abuse.")
    parser.add_argument("-u", "--url", required=True, help="\tURL to target", type=str)
    parser.add_argument("-x", "--headers", nargs='?', const="X-Forwarded-For,X-Forwarded-Host,X-Real-IP", default=False, help="\tA comma separated list of headers to add as hop-by-hop do not add spaces!")
    parser.add_argument("-c", "--cache-test", action="store_true", help="\tTest for cache poisoning")
    parser.add_argument("-v", "--verbose", action="store_true", help="\tMore output")
    parser.add_argument("-p", "--proxy", nargs='?', const="no-verify", default=False, help="Proxying requests through Burp. Provide the location of your Burp CA if you do not want to get no-verify errors", type=str.lower)
    parser.add_argument("-ofp", "--only-findings-proxied", nargs='?', const=True, default=False, help="Proxying only potential findings through burp", type=str.lower)
    parser.add_argument("-hb", "--hbh-header", default="Connection", help="\tThe HBHheader to be injected (default is Connection)", type=str)
    parser.add_argument("-f", "--file", default=False, help="\tInput file to be read from")
    parser.add_argument("-t", "--timing", default=500, help="\tDelay between requests (default is 500ms)", type=int)
    parser.add_argument("-nka", "--no-keep-alive", nargs='?', const=True, default=False, help="\tSome WAFs like Akamai check if there is multiple\nheaders being placed this removes keep-alive")
    parser.add_argument("-o", "--output", nargs='?', const='HBH_abuse_results', help="\toutputs potentially vulnerable HBH\nrequest and response to file", type=str)
    parser.add_argument("-ua", "--user-agent", default=False, help="\tadd custom user-agent")
    parser.add_argument("-m", "--method", nargs='?', const="GET", default="GET", help="\tchange HTTP verb", type=str.upper)
    parser.add_argument("-d", "--data", nargs='?', const="x=1", default=False, help="\tadd data to the request body")

    return parser.parse_args()

if __name__ == '__main__':
    count = 0
    
    args = get_args()
    print(ascii_art)
    #check which proxy arg is set if any
    proxy = ProxySettings()
    prxy = proxy.find_proxy_arg(args.proxy, args.only_findings_proxied)
    
    if args.verbose:
        print("Trying %s" % (args.url))
    #attempt a normal request to ensure the target is alive
    try:
        request_1 = HBHRequests(args.method, args.url, args.data, prxy, args.timing)
        res1 = request_1.first_request()
        if args.output:
            if args.verbose:
                print(f'{bcolors.OKCYAN}+++Writing initial request and response of %s to "%s"+++{bcolors.ENDC}' % (res1.request.url, args.output))
            #writing first request to file, and selecting the delimiter to use for the first request.
            hbh_write_1 = HBHToFile(res1, 1, args.output, args.url, args.hbh_header)
            hbh_write_1.open_file()
            hbh_write_1.write_req()
    except requests.exceptions.ConnectionError as e:
        print(e)
        exit(1)
        
    hbh = HBHHeaders(args.hbh_header, args.headers, args.file)
    header_list = hbh.clean_header_lists()
    while True:
        if len(header_list)==count:
            break
        header = hbh.get_header(args.user_agent, args.no_keep_alive, count)
        line = header[args.hbh_header]
        # hop-by-hop headers request
        request_2 = HBHRequests(args.method, args.url, args.data, prxy, args.timing)
        res2 = request_2.hop_by_hop_request(header)
        # Compare responses
        if res1.status_code != res2.status_code:
            print(f'{bcolors.WARNING}+%s returns a %s, but returned a %s with the hop-by-hop header of "%s"+{bcolors.ENDC}' % (res1.request.url, res1.status_code, res2.status_code, line))
            if args.output:
                if args.verbose:
                    print(f'{bcolors.OKCYAN}+++Writing %s\'s request and response with hop-by-hop header "%s" to %s+++{bcolors.ENDC}' % (res2.request.url, line, args.output ))
                hbh_write_2 = HBHToFile(res1, 1, args.output, args.url, line)
                hbh_write_2.write_req()
            if args.only_findings_flag:
                potential_finding_to_proxy()
                
        if len(res1.content) != len(res2.content) and res1.status_code == res2.status_code:
            print(f'{bcolors.WARNING}+%s was %s in response size, but was %s with the hop-by-hop header of "%s"+{bcolors.ENDC}' % (res1.request.url, len(res1.content), len(res2.content), line))
            if args.only_findings_flag:
                potential_finding_to_proxy()
        # if enabled, run the cache poison test by quering the HbH request's cache buster without the HbH headers and comparing status codes
        if args.cache_test:
            try:
                request_3 = HBHRequests(args.method, args.url, args.data, args.timing, prxy)
                res3 = request_3.cache_request(header)
            except requests.exceptions.ConnectionError as e:
                print(e)
                exit(1)
                
            if res3.status_code == res2.status_code:
                print(f'{bcolors.WARNING}+++%s poisoned?+++{bcolors.ENDC}' % (res3.request.url))
                if args.only_findings_flag:
                    potential_finding_to_proxy()
            else:
                print('No poisoning detected')
        else:
            if args.verbose:
                print('No change detected requesting "%s" with the hop-by-hop headers "%s" \nResponse: [%s] Content-Length: [%s]' % (res2.request.url, line, res2.status_code, len(res2.content)))
        count += 1
#removes env variables so you aren't stuck with everything going through burp and forgetting
    environ.pop("REQUESTS_CA_BUNDLE", None)
    environ.pop("HTTP_PROXY", None)
    environ.pop("HTTPS_PROXY", None)
    exit(1)

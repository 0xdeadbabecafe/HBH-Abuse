# HBH-Abuse


***


Credit to [ndavison](https://gist.github.com/ndavison/298d11b3a77b97c908d63a345d3c624d) for his original work and great [article](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers) talking about Hop-By-Hop Header abuse.



Used for finding potential Hop-By-Hop header abuse by appending cookie values to Hop By Hop headers.


***


### USAGE


***


	usage: hbh-abuse.py [-h] -u URL [-x [HEADERS]] [-c] [-v] [-p [PROXY]] [-bc BURP_CERT] [-hb HBH_HEADER] [-f FILE] [-t TIMING] [-nka [NO_KEEP_ALIVE]] [-o [OUTPUT]]
                    [-ua USER_AGENT] [-m [METHOD]] [-d [DATA]]

	Attempts to find hop-by-hop header abuse.

	optional arguments:
	  -h, --help            				show this help message and exit
	  -u URL, --url URL     				URL to target
	  -x [HEADERS], --headers [HEADERS] 			A comma separated list of headers to add as hop-by-hop do not add spaces!
	  -c, --cache-test      				Test for cache poisoning
	  -v, --verbose         				More output
	  -p [PROXY], --proxy [PROXY] 				Arguments: findings: only potential findings will be passed 
									all: all traffic will be proxied through using burp's cert 
									no-verify: all traffic will be proxied through without using burp's cert
									findings: only potentials findings will be proxied through burp
	  -bc BURP_CERT, --burp-cert BURP_CERT 			provide the path to your burp certificate (.pem format)
	  -hb HBH_HEADER, --hbh-header HBH_HEADER 		The HBHheader to be injected (default is Connection)
	  -f FILE, --file FILE  				Input file to be read from
	  -t TIMING, --timing TIMING				Delay between requests (default is 500ms)
	  -nka [NO_KEEP_ALIVE], --no-keep-alive [NO_KEEP_ALIVE]	Some WAFs like Akamai check if there is multiple headers being placed this removes keep-alive
	  -o [OUTPUT], --output [OUTPUT]			outputs potentially vulnerable HBH request and response to file
	  -ua USER_AGENT, --user-agent USER_AGENT 		add custom user-agent
	  -m [METHOD], --method [METHOD]			change HTTP verb
	  -d [DATA], --data [DATA]				add data to the request body

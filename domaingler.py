#!/usr/bin/python3
#By: Cary Hooper @nopantsrootdanc
#Input a list of valid domain names and outputs a list of mangled domains to stdout.
#Used as a helper tool for subdomain enumeration of lower-level environments exposed to the internet. 
import sys
import argparse
import dns.resolver
import socket

#To Do: keep track of different levels of mangling.  Mangle at all levels, not just the top level.
#		Recursive function maybe?  Let's whiteboard it.  dns.resolver makes this easier.
#To Do: explore keeping track of results with a sqlite3 database.
#To Do: make do_resolve() multithreaded... takes too long.

def banner():
    sys.stderr.write("""
 _____                        _             _           
|  __ \                      (_)           | |          
| |  | | ___  _ __ ___   __ _ _ _ __   __ _| | ___ _ __ 
| |  | |/ _ \| '_ ` _ \ / _` | | '_ \ / _` | |/ _ \ '__|
| |__| | (_) | | | | | | (_| | | | | | (_| | |  __/ |   
|_____/ \___/|_| |_| |_|\__,_|_|_| |_|\__, |_|\___|_|   
                                       __/ |            
                                      |___/
\t# Coded By Cary Hooper - @nopantsrootdanc\n""")

#Argument handling.
parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -i /path/to/subdomain.lst")
parser.add_argument("-i", "--infile", help="path to the domain list",required=True)
parser.add_argument("-o", "--outfile", help="path to the output file")
parser.add_argument("-n", "--numbers", help="appends numbers to the lower-level environments.\n(ex. dev2.example.com)", action='store_true')
parser.add_argument("-r", "--resolve", help="resolve the domain list and output valid domains (must use with -o option)", action='store_true')
args = parser.parse_args()
banner()
infileloc = args.infile
outfileloc = args.outfile

#Checks if infile exists.  If not, exception is thrown.
try:
	infile = open(infileloc,"r")
except:
	print("Infile does not exist!")
	sys.exit()

#Create outfile.  If it exists, overwrite it.
if outfileloc != None:
	outfile = open(outfileloc,"w") 

#List of lower-level environments.
mang = ["temp",
		"tmp",
		"test",
		"testing",
		"tst",
		"prod"
		"production",
		"replica",
		"qa",
		"dev",
		"devel",
		"develop",
		"development",
		"pp",
		"preprod",
		"pre-prod",
		"stg",
		"stage",
		"staging",
		"uat",
		"st",
		"sit",
		"bit",
		"cit",
		"cce",
		"cert",
		"live",
		"devtemp",
		"prodtemp",
		"uattemp"]

#Change these based on OSINT and size of target
nums = ["","0","1","2","3","4"]
delimiters = ["","-"]
domains = []

#Maybe instead of sending these out we should store in an array...
def sendout(url):
	if outfileloc == None:
		print(url)
	else:
		outfile.write(url + "\n")

def mangle(url):
	subdomain = url.split(".",1)[0]
	bottomlevel = url.split(".",1)[1]

	if args.numbers == True:
		for environ in mang:
			for numbers in nums:
				#dev2.example.com
				plaindom = environ + numbers + "." + subdomain + "." + bottomlevel
				sendout(plaindom)
				for delim in delimiters:
					#dev-example.com
					mangdom1 = environ +  numbers + delim + subdomain + "." + bottomlevel
					#example-dev.com
					mangdom2 = subdomain + delim + environ + numbers + "." + bottomlevel
					sendout(mangdom1)
					sendout(mangdom2)
	else:
		for environ in mang:
			for delim in delimiters:
				mangdom1 = environ +  delim + subdomain + "." + bottomlevel
				mangdom2 = subdomain + delim + environ + "." + bottomlevel
				sendout(mangdom1)
				sendout(mangdom2)

def do_resolve():
	#Initialize variables
	alldomains = []
	validsubs = []
	resolver = dns.resolver.Resolver()
	resolver.timeout = 1
	resolver.lifeime = 1
	resolver.nameservers = ['8.8.8.8','8.8.4.4','80.80.80.80','80.80.81.81']
	#populate array
	for i in open(outfileloc,'r').readlines():
		alldomains.append(i)
	#Cycle through subdomains.  Adds to validsubs array if valid.
	for domain in alldomains:
		domain = domain[:-1]
		#print("Resolving... " + domain)
		try:
			ans = resolver.query(domain,'A')
			for data in ans:
				print('[*] Found! ' + str(ans.canonical_name)[:-1] + ' has address: ' + str(data.address))
				validsubs.append(str(ans.canonical_name)[:-1])
		except dns.resolver.NXDOMAIN as e:
		 	#print("No domain found for " + str(i))
		 	pass
		except dns.resolver.NoAnswer as e:
			print("Resolver issue.")
			pass
	return validsubs


for url in infile: 
	mangle(url.strip())


if outfileloc != None:
	outfile = open(outfileloc,"w") 

if args.resolve == True:
	#Right now, only works with -o specified...  To Do
	validsubs = do_resolve()
	print("Program Complete.")
	for i in validsubs:
		print(i)


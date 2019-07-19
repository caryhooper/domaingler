#!/usr/bin/python3
#By: Cary Hooper @nopantsrootdanc
#Input a list of valid domain names and outputs a list of mangled domains to stdout.
#Used as a helper tool for subdomain enumeration of lower-level environments exposed to the internet. 
import sys
import argparse
import dns.resolver
import socket
from multiprocessing.dummy import Pool as ThreadPool

#To Do: keep track of different levels of mangling.  Mangle at all levels, not just the top level.
#		Recursive function maybe?  Let's whiteboard it.  dns.resolver makes this easier.
#To Do: explore keeping track of results with a sqlite3 database.  Maybe importable into recon-ng?
#To Do: graceful exit on CTL+C for multithreading
#To Do: handle input from stdin as well as file

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
\t# Developed By Cary Hooper - @nopantrootdance\n""")

#Argument handling.
parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -i /path/to/domains.lst -r -t 16")
parser.add_argument("-i", "--infile", help="path to the domain list",required=True)
parser.add_argument("-o", "--outfile", help="path to the output file")
parser.add_argument("-n", "--numbers", help="appends numbers to the lower-level environments.\n(ex. dev2.example.com)", action='store_true')
parser.add_argument("-r", "--resolve", help="resolve the domain list and output valid domains", action='store_true')
parser.add_argument("-t", "--threads", help="number of threads", default=16)
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

#Change these based on OSINT and size of target
nums = ["","0","1","2","3","4"]
delimiters = ["","-"]
domains = []

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



#Input domain object and output a string
def stringify(domainobj):
	string = ""
	for part in domainobj:
		string += part + "."
	return string[:-1]

#Input a set and output either an outfile or names to stdout
def sendout(domainset):
	if outfileloc == None:
		for domainobj in domainset:
			print(stringify(domainobj))
	else:
		outfile = open(outfileloc,"w") 
		for domainobj in domainset:
			outfile.write(stringify(domainobj) + "\n")
		outfile.close()

#Input a set of domain objects
#Output a set of new domain objects
def mangle(domainset):
	outlist = set()
	for domainobj in domainset:
		outlist.add(domainobj)

		#Prepare the parts - bottom ~ "www"
		bottom = domainobj[0]
		#Prepare the parts - topdom ~ "example.com"
		topdom = stringify(domainobj[1:])

		if args.numbers == True:
			pass
		else:
			nums = [""]
		for environ in mang:
			for numbers in nums:
				#dev2.example.com
				sub = environ + numbers + "." + bottom + "." + topdom
				subobj = dns.name.from_text(sub.strip())
				outlist.add(subobj)
				for delim in delimiters:
					#dev2-example.com
					mang1 = environ +  numbers + delim + bottom + "." + topdom
					mang1obj = dns.name.from_text(mang1.strip())
					outlist.add(mang1obj)
					#example-dev2.com
					mang2 = bottom + delim + environ + numbers + "." + topdom
					mang2obj = dns.name.from_text(mang2.strip())
					outlist.add(mang2obj)
	return outlist

def do_resolve(domainset):
	def query(domainobj):
		resolver = dns.resolver.Resolver()
		resolver.timeout = 1
		resolver.lifeime = 1
		resolver.nameservers = ['8.8.8.8','8.8.4.4','80.80.80.80','80.80.81.81']
		for reqtype in ['A','AAAA']:
			try:
				ans = resolver.query(domainobj,reqtype)
				for data in ans:
					print('[*] Found! ' + str(ans.canonical_name)[:-1] + ' has address: ' + str(data.address))
					validsubs.add(domainobj)
			except dns.resolver.NXDOMAIN as e:
			 	#print("No domain found for " + stringify(domainobj))
			 	pass
			except dns.resolver.NoAnswer as e:
				#print("Resolver issue.")
				pass
			except dns.name.LabelTooLong as e:
				print("DNS label is too long (> 63 octets) for domain " + stringify(domainobj))
				pass

	#Initialize variables
	validsubs = set()
	#Multithreading
	pool = ThreadPool(int(args.threads))
	pool.map(query,domainset)
	#Cycle through subdomains.  Adds to validsubs array if valid.

		#print("Resolving... " + stringify(domainobj))

	return validsubs

##MAIN##
alldomains = set()
#Populate domain set
for domain in infile: 
	domainobj = dns.name.from_text(domain.strip())
	alldomains.add(domainobj)

#returns a set of mangled domains
mangdomains = mangle(alldomains)

if args.resolve == True:
	try:
		validsubs = do_resolve(mangdomains)
	except KeyboardInterrupt as e:
		print("\nProgram terminated by user.")
		sys.exit()
	print("Program Complete.")

sendout(validsubs)
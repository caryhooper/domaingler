#!/usr/bin/python3
#By: Cary Hooper @nopantsrootdanc
#Input a list of valid domain names and outputs a list of mangled domains to stdout.
#Used as a helper tool for subdomain enumeration of lower-level environments exposed to the internet. 
import sys
import argparse

#To Do: keep track of different levels of mangling.  Mangle at all levels, not just the top level.
#		Recursive function maybe?  Let's whiteboard it.

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
mang = [	"temp",
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

for url in infile: 
	mangle(url.strip())
	
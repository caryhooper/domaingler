#!/usr/bin/python3
#By: Cary Hooper @nopantsrootdanc
#Input a list of valid domain names and outputs a list of mangled domains to stdout.
#Used as a helper tool for subdomain enumeration of lower-level environments.
import sys

if len(sys.argv) != 2:
	print("Requires one argument.\n\n./domaingler.py /path/to/subdomain/list")
	sys.exit()

#To Do: argument handling and argument validation... argparse?  Maybe later.
#To Do: keep track of different levels of mangling.  Mangle at all levels, not just the top level.
#		Recursive function maybe?  Let's whiteboard it.
urlfile = sys.argv[1]

file = open(urlfile,"r")

mang = [	"test",
			"testing",
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
			"tst",
			"uat",
			"st",
			"sit",
			"cit",
			"cce",
			"cert",
			"live"]
nums = ["","0","1","2","3","4"]
delimiters = ["","-"]


def mangle(url):
	subdomain = url.split(".",1)[0]
	bottomlevel = url.split(".",1)[1]

	for environ in mang:
		for numbers in nums:
			plaindom = environ + numbers + "." + subdomain + "." + bottomlevel
			print(plaindom)
			for delim in delimiters:
				mangdom1 = environ +  numbers + delim + subdomain + "." + bottomlevel
				mangdom2 = environ + numbers + delim + subdomain + "." + bottomlevel
				print(mangdom1)
				print(mangdom2)

for url in file: 
	mangle(url.strip())
	
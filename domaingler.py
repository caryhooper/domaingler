#!/usr/bin/python3
#By: Cary Hooper @nopantsrootdanc
#Input a list of valid domain names and outputs a list of mangled domains to stdout.
#Used as a helper tool for subdomain enumeration of lower-level environments.
import sys
import argparse

#To Do: argument validation... argparse


#To Do: keep track of different levels of mangling.  Mangle at all levels, not just the top level.
#		Recursive function maybe?  Let's whiteboard it.

parser = argparse.ArgumentParser()
parser.add_argument("-i","--infile", help="path to the list of domains")
parser.add_argument("-o", "--outfile", help="path for the output file")
args = parser.parse_args()

infileloc = args.infile
outfileloc = args.outfile
if infileloc == None :
	print("Requires infile argument.\n\n./domaingler.py /path/to/subdomain/list")
	sys.exit()

if outfileloc != None:
	outfile = open(outfileloc,"w") 

infile = open(infileloc,"r")


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

#Maybe make adding the numbers an optional flag.
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

	for environ in mang:
		for numbers in nums:
			plaindom = environ + numbers + "." + subdomain + "." + bottomlevel
			sendout(plaindom)
			for delim in delimiters:
				mangdom1 = environ +  numbers + delim + subdomain + "." + bottomlevel
				mangdom2 = environ + numbers + delim + subdomain + "." + bottomlevel
				sendout(mangdom1)
				sendout(mangdom2)

for url in infile: 
	mangle(url.strip())
	
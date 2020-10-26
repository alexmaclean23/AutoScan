#!/usr/bin/python3


# Importing the os library to execute bash commands
import os
from os import path


# Default variable values
ip = "127.0.0.1"
port = ""
scan = ""
speed = ""
syntax = ""
output = ""
nmapCommands = ["", "", "", "", ""]
index = 0
infoLines = 0
syn = ""
tcp = ""
udp = ""
xmas = ""
null = ""
scannedSYN = False
scannedTCP = False
scannedUDP = False
scannedXMAS = False
scannedNULL = False
useWhoIs = False
useTheHarvester = False
useNikto = False
useDirb = False
useSearchSploit = False
useGoogle = False
hasWebServer = False
openServices = []


# Welcome Banner
def welcome_banner():
	
	print()
	print()
	print("        ^^^      ^^   ^^  ^^^^^^^^   ^^^^^^     ")
	print("       ^^ ^^     ^^   ^^     ^^     ^^    ^^    ")
	print("      ^^^^^^^    ^^   ^^     ^^     ^^    ^^    ")
	print("     ^^     ^^   ^^   ^^     ^^     ^^    ^^    ")
	print("    ^^       ^^    ^^^       ^^      ^^^^^^     ")
	print()
	print("       ^^^^^^    ^^^^      ^^^      ^^    ^^    ")
	print("     ^^        ^^         ^^ ^^     ^^^   ^^    ")
	print("      ^^^^^    ^^        ^^^^^^^    ^^ ^^ ^^    ")
	print("          ^^   ^^       ^^     ^^   ^^   ^^^    ")
	print("    ^^^^^^       ^^^^  ^^       ^^  ^^    ^^    ")
	print()
	print()
	print()


# Select IP
def select_ip():

	global ip

	print()
	print("Please enter your target(s) to scan. Targets can be specified as an individual IP")
	print("or host, as a range of addresses, or using CIDR notation. To use a target file,")
	print("enter X into the field below, and leave the field blank to scan the local machine.")
	print()

	ip = input("Target(s): ")

	if (ip.upper() == "X"):
		print("Enter the target .txt file (or path to the .txt file).")
		ip = input("Target File: ")
		if (ip[-4:] == ".txt"):
			ip = "-iL " + ip
		elif (ip == ""):
			print("No target specified. Defaulting to local machine.")
			ip = "127.0.0.1"
		else:
			ip = "-iL " + ip
	elif (ip == ""):
		print("No target specified. Defaulting to local machine.")
		ip = "127.0.0.1"
	elif ((" " in ip) or ("," in ip) or ("/" in ip) or (":" in ip) or (";" in ip)):
		print("Invalid target. Defaulting to local machine.")
		ip = "127.0.0.1"
	else:
		pass
	print()


# Select Port
def select_port():

	global port

	print()
	print("Please enter the ports to scan, separated by commas with no spaces between them.")
	print("Leaving this field blank will default to the top 1000 ports, and entering ALL")
	print("will scan all 65535 ports on each specified target (UDP will still only scan top 1000).")
	print()

	port = input("Ports: ")

	if (port.upper() == "ALL"):
		port = "-p-"
	elif (port == ""):
		print("No ports specified. Defaulting to top 1000 ports.")
	elif (" " in port):
		print("Invalid port selection. Defaulting to top 1000 ports.")
		port = ""
	else:
		port = "-p" + port
	print()


# Select Scan
def select_scan():

	global scan
	global nmapCommands
	global index
	scans = []
	types = ["SYN", "TCP", "UDP", "XMAS", "NULL"]

	print()
	print("Please enter the type of scan(s) you wish to perform. For multiple scan types, enter")
	print("each scan separated by commas, with no spaces before or after the comma. Acceptable scans")
	print("include SYN, TCP, UDP, XMAS, and NULL. To use all 5 types, enter ALL.")
	print()

	scan = input("Scan(s): ")
	scan = scan.replace(" ","")

	if (scan.upper() == "ALL"):
		nmapCommands[0] = "syn"
		nmapCommands[1] = "tcp"
		nmapCommands[2] = "udp"
		nmapCommands[3] = "xmas"
		nmapCommands[4] = "null"
	elif (scan == ""):
		print("No scans specified. Defaulting to SYN scan.")
		nmapCommands[index] = "syn"
		index += 1
	else:
		scans = scan.upper().split(",")
		for item in scans:
			if (item in types):
				if (item == "SYN"):
					try:
						nmapCommands[index] = "syn"
						index += 1
					except:
						pass
				elif (item == "TCP"):
					try:
						nmapCommands[index] = "tcp"
						index += 1
					except:
						pass
				elif (item == "UDP"):
					try:
						nmapCommands[index] = "udp"
						index += 1
					except:
						pass
				elif (item == "XMAS"):
					try:
						nmapCommands[index] = "xmas"
						index += 1
					except:
						pass
				elif (item == "NULL"):
					try:
						nmapCommands[index] = "null"
						index += 1
					except:
						pass
				else:
					pass
			else:
				print("{} is not a valid scan. Defaulting to SYN scan.".format(item))
				nmapCommands[index] = "syn"
				index += 1
	print()


# Select Speed
def select_speed():
	
	global speed

	print()
	print("Please select a speed at which to conduct your scans. Enter 1 for  slowest , 2 for slow, 3")
	print("for medium, 4 for fast, and 5 for fastest. Leaving this field will default to normal speed (3).")
	print()

	speed = input("Speed: ")

	if (speed == "1" or speed == "2" or speed == "3" or speed == "4" or speed == "5"):
		speed = "-T" + speed
	elif (speed == ""):
		print("No speed specified. Default to speed of 3.")
		speed = "-T3"
	else:
		print("Invalid speed selection. Defaulting to speed of 3.")
		speed = "-T3"
	print()


# Select Syntax
def select_syntax():

	global syntax
	global infoLines

	print()
	print("Please select a syntax for your scan output. Enter sV to include version information, O")
	print("to enable OS detection, or A to include both of the previous options. Leaving the field")
	print("blank will omit all options and will output only the status of each selected port.")
	print()

	syntax = input("Syntax: ")

	if (syntax == "sV" or syntax == "O" or syntax == "A"):
		syntax = " -" + syntax
	elif (syntax == ""):
		print("No syntax specified. Defaulting to non-verbose syntax.")
		syntax = ""
	else:
		print("Invalid syntax selection. Defaulting to no syntax specifications.")
		syntax = ""
	print()
	
	if (syntax == "sV"):
		infoLines = 3
	elif (syntax == "O"):
		infoLines = 8
	elif (syntax == "A"):
		infoLines = 2
	else:
		infoLines = 2


# Select Output
def select_output():

	global output

	print()
	print("If you would like the results of each scan to be printed to a file, please enter a file to be")
	print("created in the field below. If you do not have a specific filename in mind, leave the field")
	print("blank to accept the program's default filename prefix.")
	print()

	output = input("Output Filenames: ")
	output.replace(" ","_")
	output.replace(",","")
	output.replace(".","")
	output.replace(";","")
	output.replace(":","")
	output.replace("*","")
	output.replace("/","")
	
	if (output == ""):
		print("No output filenames specified. Defaulting to filename prefix of 'AutoScan'.")
		output = "AutoScan"
	else:
		pass
	print()
	

# Select Options
def select_options():

	global useWhoIs
	global useTheHarvester
	global useNikto
	global useDirb
	global useSearchSploit
	global useGoogle
	
	print()
	print("Would you like to use WhoIs to translate the specified domain / IP address between IPv4")
	print("and a FQDN? Enter 'Yes' or 'No' to designate your selection.")
	print()
	
	selectWhoIs = input("Use WhoIs? ")
	
	if (selectWhoIs == ""):
		print("No selection made. Defaulting to no use of WhoIs.")
		useWhoIs = False
	elif (selectWhoIs.upper() == "YES"):
		useWhoIs = True
	elif (selectWhoIs.upper() == "NO"):
		useWhoIs = False
	else:
		pass
	print()
	
	print()
	print("Would you like to use The Harvester to gain OSINT on the specified domain / IP address?")
	print("Enter 'Yes' or 'No' to designate your selection.")
	print()
	
	selectTheHarvester = input("Use The Harvester? ")
	
	if (selectTheHarvester == ""):
		print("No selection made. Defaulting to no use of The Harvester.")
		useTheHarvester = False
	elif (selectTheHarvester.upper() == "YES"):
		useTheHarvester = True
	elif (selectTheHarvester.upper() == "NO"):
		useTheHarvester = False
	else:
		pass
	print()
	
	print()
	print("Would you like to use Nikto to scan for web vulnerabilities (if a web server is detected)?")
	print("Enter 'Yes' or 'No' to designate your selection.")
	print()
	
	selectNikto = input("Use Nikto? ")
	
	if (selectNikto == ""):
		print("No selection made. Defaulting to no use of Nikto.")
		useNikto = False
	elif (selectNikto.upper() == "YES"):
		useNikto = True
	elif (selectNikto.upper() == "NO"):
		useNikto = False
	else:
		pass
	print()
	
	print()
	print("Would you like to use Dirb to brute force web directories (if a web server is detected)?")
	print("Enter 'Yes' or 'No' to designate your selection.")
	print()
	
	selectDirb = input("Use Dirb? ")
	
	if (selectDirb == ""):
		print("No selection made. Defaulting to no use of Dirb.")
		useDirb = False
	elif (selectDirb.upper() == "YES"):
		useDirb = True
	elif (selectNikto.upper() == "NO"):
		useDirb = False
	else:
		pass
	print()

	print()
	print("Would you like to use SearchSploit to analyze the open protocols on the target system(s)?")
	print("Enter 'Yes' or 'No' to designate your selection.")
	print()
	
	selectSearchSploit = input("Use SearchSploit? ")
	
	if (selectSearchSploit == ""):
		print("No selection made. Defaulting to no use of SearchSploit.")
		useSearchSploit = False
	elif (selectSearchSploit.upper() == "YES"):
		useSearchSploit = True
	elif (selectSearchSploit.upper() == "NO"):
		useSearchSploit = False
	else:
		pass
	print()
	
	print()
	print("Would you like to use Google to analyze the open protocols on the target system(s)?")
	print("Enter 'Yes' or 'No' to designate your selection.")
	print()
	
	selectGoogle = input("Use Google? ")
	
	if (selectGoogle == ""):
		print("No selection made. Defaulting to no use of Google.")
		useGoogle = False
	elif (selectGoogle.upper() == "YES"):
		useGoogle = True
	elif (selectGoogle.upper() == "NO"):
		useGoogle = False
	else:
		pass
	print()	


# Create Scans
def create_scans():

	global output
	global syn
	global tcp
	global udp
	global xmas
	global null

	out = ""
	portUDP = port

	global scannedSYN
	global scannedTCP
	global scannedUDP
	global scannedXMAS
	global scannedNULL

	print()
	print()
	input("Data acquired. Ready to scan?")

	for item in nmapCommands:
		if (item == "syn"):
			if (scannedSYN == False):
				if (output == ""):
					pass
				else:
					out = " >> " + output + "/Nmap/" + output + "-NmapSYNscan.txt"
				syn = "sudo nmap -sS{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedSYN = True
			else:
				pass
		elif (item == "tcp"):
			if (scannedTCP == False):
				if (output == ""):
					pass
				else:
					out = " >> " + output + "/Nmap/" + output + "-NmapTCPscan.txt"
				tcp = "nmap -sT{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedTCP = True
			else:
				pass
		elif (item == "udp"):
			if (scannedUDP == False):
				if (output == ""):
					pass
				else:
					out = " >> " + output + "/Nmap/" + output + "-NmapUDPscan.txt"
				if (port == "-p-"):
					portUDP = ""
				else:
					portUDP = " " + port
				udp = "nmap -sU{} {}{} {}{}".format(syntax, speed, portUDP, ip, out)
				scannedUDP = True
			else:
				pass
		elif (item == "xmas"):
			if (scannedXMAS == False):
				if (output == ""):
					pass
				else:
					out = " >> " + output + "/Nmap/" + output + "-NmapXMASscan.txt"
				xmas = "nmap -sX{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedXMAS = True
			else:
				pass
		elif (item == "null"):
			if (scannedNULL == False):
				if (output == ""):
					pass
				else:
					out = " >> " + output + "/Nmap/" + output + "-NmapNULLscan.txt"
				null = "nmap -sN{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedNULL = True
			else:
				pass
		else:
			pass
	print()
	

# Create Directories
def create_directories():

	os.system("mkdir " + output)
	os.system("mkdir " + output + "/Nmap")
	
	if (useWhoIs == True):
		os.system("mkdir " + output + "/WhoIs")
	else:
		pass
	
	if (useTheHarvester == True):
		os.system("mkdir " + output + "/TheHarvester")
	else:
		pass
		
	if (useNikto == True):
		os.system("mkdir " + output + "/Nikto")
	else:
		pass
		
	if (useDirb == True):
		os.system("mkdir " + output + "/Dirb")
	else:
		pass

	if (useSearchSploit == True):
		os.system("mkdir " + output + "/SearchSploit")
	else:
		pass
		
	if (useGoogle == True):
		os.system("mkdir " + output + "/Google")
	else:
		pass

	
# Run Scans
def run_nmap():

	global hasWebServer
	global openServices

	synScanDone = False
	tcpScanDone = False
	udpScanDone = False
	xmasScanDone = False
	nullScanDone = False

	if (syn == ""):
		pass
	else:
		os.system("gnome-terminal -- bash -c '" + syn + "'")

	if (tcp == ""):
		pass
	else:
		os.system("gnome-terminal -- bash -c '" + tcp + "'")

	if (udp == ""):
		pass
	else:
		os.system("gnome-terminal -- bash -c '" + udp + "'")

	if (xmas == ""):
		pass
	else:
		os.system("gnome-terminal -- bash -c '" + xmas + "'")

	if (null == ""):
		pass
	else:
		os.system("gnome-terminal -- bash -c '" + null + "'")
		
	os.system("updatedb")
	
	while True:
		if (scannedSYN == True):
			if (path.exists(output + "/Nmap/" + output + "-NmapSYNscan.txt")):
				synScanDone = True
				scanFile = open(output + "/Nmap/" + output + "-NmapSYNscan.txt")				
				lines = scanFile.readlines()				
				for i in range(5):
					lines.pop(0)
				for i in range(infoLines):
					lines.pop(-1)
				for line in lines:
					if ((line[:6] == "80/tcp") or (line[:7] == "443/tcp")):
						hasWebServer = True
					else:
						pass
					if (line[0].isnumeric()):
						line.replace("     ", " ")
						line.replace("    ", " ")
						line.replace("   ", " ")
						line.replace("  ", " ")
						segments = line.split(" ")
						discoveredService = segments[-1]
						discoveredService = discoveredService[:-1]
						openServices.append(discoveredService)
					else:
						pass
				scanFile.close()
			else:
				synScanDone = False
		else:
			synScanDone = True
		if (scannedTCP == True):
			if (path.exists(output + "/Nmap/" + output + "-NmapTCPscan.txt")):
				tcpScanDone = True
				scanFile = open(output + "/Nmap/" + output + "-NmapTCPscan.txt")
				lines = scanFile.readlines()				
				for i in range(5):
					lines.pop(0)
				for i in range(infoLines):
					lines.pop(-1)
				for line in lines:
					if ((line[:6] == "80/tcp") or (line[:7] == "443/tcp")):
						hasWebServer = True
					else:
						pass
					if (line[0].isnumeric()):
						line.replace("     ", " ")
						line.replace("    ", " ")
						line.replace("   ", " ")
						line.replace("  ", " ")
						segments = line.split(" ")
						discoveredService = segments[-1]
						discoveredService = discoveredService[:-1]
						openServices.append(discoveredService)
					else:
						pass
				scanFile.close()
			else:
				tcpScanDone = False
		else:
			tcpScanDone = True
		if (scannedUDP == True):
			if (path.exists(output + "/Nmap/" + output + "-NmapUDPscan.txt")):
				udpScanDone = True
				scanFile = open(output + "/Nmap/" + output + "-NmapUDPscan.txt")
				lines = scanFile.readlines()				
				for i in range(5):
					lines.pop(0)
				for i in range(infoLines):
					lines.pop(-1)
				for line in lines:
					if ((line[:6] == "80/tcp") or (line[:7] == "443/tcp")):
						hasWebServer = True
					else:
						pass
					if (line[0].isnumeric()):
						line.replace("     ", " ")
						line.replace("    ", " ")
						line.replace("   ", " ")
						line.replace("  ", " ")
						segments = line.split(" ")
						discoveredService = segments[-1]
						discoveredService = discoveredService[:-1]
						openServices.append(discoveredService)
					else:
						pass
				scanFile.close()
			else:
				udpScanDone = False
		else:
			udpScanDone = True
		if (scannedXMAS == True):
			if (path.exists(output + "/Nmap/" + output + "-NmapXMASscan.txt")):
				xmasScanDone = True
				scanFile = open(output + "/Nmap/" + output + "-NmapXMASscan.txt")
				lines = scanFile.readlines()				
				for i in range(5):
					lines.pop(0)
				for i in range(infoLines):
					lines.pop(-1)
				for line in lines:
					if ((line[:6] == "80/tcp") or (line[:7] == "443/tcp")):
						hasWebServer = True
					else:
						pass
					if (line[0].isnumeric()):
						line.replace("     ", " ")
						line.replace("    ", " ")
						line.replace("   ", " ")
						line.replace("  ", " ")
						segments = line.split(" ")
						discoveredService = segments[-1]
						discoveredService = discoveredService[:-1]
						openServices.append(discoveredService)
					else:
						pass
				scanFile.close()
			else:
				xmasScanDone = False
		else:
			xmasScanDone = True
		if (scannedNULL == True):
			if (path.exists(output + "/Nmap/" + output + "-NmapNULLscan.txt")):
				nullScanDone = True
				scanFile = open(output + "/Nmap/" + output + "-NmapNULLscan.txt")
				lines = scanFile.readlines()				
				for i in range(5):
					lines.pop(0)
				for i in range(infoLines):
					lines.pop(-1)
				for line in lines:
					if ((line[:6] == "80/tcp") or (line[:7] == "443/tcp")):
						hasWebServer = True
					else:
						pass
					if (line[0].isnumeric()):
						line.replace("     ", " ")
						line.replace("    ", " ")
						line.replace("   ", " ")
						line.replace("  ", " ")
						segments = line.split(" ")
						discoveredService = segments[-1]
						discoveredService = discoveredService[:-1]
						openServices.append(discoveredService)
					else:
						pass
				scanFile.close()
			else:
				nullScanDone = False
		else:
			nullScanDone = True
		if ((synScanDone == True) and (tcpScanDone == True) and (udpScanDone == True) and (xmasScanDone == True) and (nullScanDone == True)):
			break
		else:
			pass
	
	if (len(openServices) == 0):
		os.system("rmdir " + output + "/SearchSploit")
		os.system("rmdir " + output + "/Google")
	else:
		pass
		
	if (hasWebServer == False):
		os.system("rmdir " + output + "/Nikto")
		os.system("rmdir " + output + "/Dirb")
	else:
		pass
			
	
# Run WhoIs
def run_whois():

	if (useWhoIs == True):
		os.system("gnome-terminal -- bash -c 'whois " + ip + " >> " + output + "/WhoIs/" + output + "-WhoIs.txt'")
	else:
		pass
	

# Run TheHarvester
def run_theharvester():
	
	if (useTheHarvester == True):
		os.system("gnome-terminal -- bash -c 'theHarvester -d" + ip + "-l 50 -b google >> " + output + "/TheHarvester/" + output + "-TheHarvester.txt'")
	else:
		pass
	

# Run Nikto
def run_nikto():
	
	if ((useNikto == True) and (hasWebServer == True)):
		os.system("gnome-terminal -- bash -c 'nikto -h http://" + ip + "/ >> " + output + "/Nikto/" + output + "-NiktoHTTP.txt'")
		os.system("gnome-terminal -- bash -c 'nikto -h https://" + ip + "/ >> " + output + "/Nikto/" + output + "-NiktoHTTPS.txt'")
	else:
		pass


# Run Dirb
def run_dirb():
	
	if ((useDirb == True) and (hasWebServer == True)):
		os.system("gnome-terminal -- bash -c 'dirb http://" + ip + "/ /usr/share/wordlists/custom/large-directories.txt >> " + output + "/Dirb/" + output + "-DirbHTTP.txt'")
		os.system("gnome-terminal -- bash -c 'dirb https://" + ip + "/ /usr/share/wordlists/custom/large-directories.txt >> " + output + "/Dirb/" + output + "-DirbHTTPS.txt'")
	else:
		pass
	

# Run SearchSploit
def run_searchsploit():
	
	if ((useSearchSploit == True) and (len(openServices) > 0)):
		for service in openServices:
			os.system("gnome-terminal -- bash -c 'searchsploit " + service + " >> " + output + "/SearchSploit/" + output + "-SearchSploit" + service + ".txt'")
	else:
		pass
	

# Run Google
def run_google():
	
	if ((useGoogle == True) and (len(openServices) > 0)):
		for service in openServices:
			os.system("curl -sA -L 'https://www.google.com/search?q=" + service + "+site%3Ahttps%3A%2F%2Fwww.rapid7.com%2F" + "' -o " + output + "/Google/" + output + "-Rapid7" + service + ".html")
			os.system("curl -sA -L 'https://www.google.com/search?q=" + service + "+site%3Ahttps%3A%2F%2Fwww.exploit-db.com%2F" + "' -o " + output + "/Google/" + output + "-ExploitDB" + service + ".html")
			os.system("curl -sA -L 'https://www.google.com/search?q=" + service + "+site%3Ahttps%3A%2F%2Fcve.mitre.org%2F" + "' -o " + output + "/Google/" + output + "-CVE" + service + ".html")
	else:
		pass

# End Banner
def end_banner():
	print("AutoScan complete!")
	print()
	print()
	print("        ^^^      ^^   ^^  ^^^^^^^^   ^^^^^^     ")
	print("       ^^ ^^     ^^   ^^     ^^     ^^    ^^    ")
	print("      ^^^^^^^    ^^   ^^     ^^     ^^    ^^    ")
	print("     ^^     ^^   ^^   ^^     ^^     ^^    ^^    ")
	print("    ^^       ^^    ^^^       ^^      ^^^^^^     ")
	print()
	print("       ^^^^^^    ^^^^      ^^^      ^^    ^^    ")
	print("     ^^        ^^         ^^ ^^     ^^^   ^^    ")
	print("      ^^^^^    ^^        ^^^^^^^    ^^ ^^ ^^    ")
	print("          ^^   ^^       ^^     ^^   ^^   ^^^    ")
	print("    ^^^^^^       ^^^^  ^^       ^^  ^^    ^^    ")
	print("                -by Alex Maclean                ")
	print()
	print()


# Script Controller
def main():
	welcome_banner()
	select_ip()
	select_port()
	select_scan()
	select_speed()
	select_syntax()
	select_output()
	select_options()
	create_scans()
	create_directories()
	run_nmap()
	run_whois()
	run_theharvester()
	run_nikto()
	run_dirb()
	run_searchsploit()
	run_google()
	end_banner()
	
if __name__ == "__main__":
	main()

#!/usr/bin/python

# Importing the os library to execute bash commands
import os

# Default variable values
ip = "127.0.0.1"
port = ""
scan = ""
speed = ""
syntax = ""
output = ""
nmapCommands = ["", "", "", "", ""]
index = 0
syn = ""
tcp = ""
udp = ""
xmas = ""
null = ""

# Welcome banner	
def welcome_banner():
	
	print()
	print()
	print("====================================================================================")
	print("####################################################################################")
	print("##############   ############    ######    ####                ######       ########")
	print("#############     ###########    ######    ####                ####           ######")
	print("############       ##########    ######    ##########    #########     ###     #####")
	print("#######3###    #    #########    ######    ##########    #########    #####    #####")
	print("##########    ###    ########    ######    ##########    #########    #####    #####")
	print("#########             #######    ######    ##########    #########    #####    #####")
	print("########               ######    ######    ##########    #########    #####    #####")
	print("#######     #######     #####     ####     ##########    #########     ###     #####")
	print("######     #########     #####            ###########    ##########           ######")
	print("#####     ###########     ######        #############    ############       ########")
	print("####################################################################################")
	print("====================================================================================")
	print("                                                                                    ")
	print("           #############      ############          ##          #####      ####     ")
	print("         ##############     #############          ####         ######     ####     ")
	print("        ######             #####                  ######        #######    ####     ")
	print("        ####              #####                  ###  ###       #### ###   ####     ")
	print("         #########        ####                  ###    ###      #### ####  ####     ")
	print("          #########       ####                 ############     ####  #### ####     ")
	print("                ####      #####               ##############    ####   ### ####     ")
	print("              ######       #####              ######  ######    ####    #######     ")
	print("      #############         #############    ######    ######   ####     ######     ")
	print("     ############             ############   #####      #####   ####      #####     ")
	print("                                                                                    ")
	print("====================================================================================")
	print()
	print()
	print()
	print()

# IP selector
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
			ip = "-iL " + ip + ".txt"
	elif (ip == ""):
		print("No target specified. Defaulting to local machine.")
	elif (" " in ip):
		print("Invalid target. Default to local machine.")
		ip = "127.0.0.1"
	else:
		pass
	print()

# Port selector
def select_port():

	global port

	print()
	print("Please enter the ports to scan, separated by commas with no spaces between them.")
	print("Leaving this field blank will default to the top 1000 ports, and entering ALL")
	print("will scan all 65535 ports on each specified target.")
	print()

	port = input("Ports: ")

	if (port.upper() == "ALL"):
		port = "-p-"
		print("All ports selected. UDP scans will still only scan the top 1000 ports.")
	elif (port == ""):
		print("No ports specified. Defaulting to top 1000 ports.")
	elif (" " in port):
		print("Invalid port selection. Defaulting to top 1000 ports.")
		port = ""
	else:
		port = "-p" + port
	print()

# Scan selector
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

	if (scan.upper() == "ALL"):
		nmapCommands[0] = "syn"
		nmapCommands[1] = "tcp"
		nmapCommands[2] = "udp"
		nmapCommands[3] = "xmas"
		nmapCommands[4] = "null"
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

# Speed selector
def select_speed():
	
	global speed

	print()
	print("Please select a speed at which to conduct your scans. Enter 1 for  slowest , 2 for slow, 3")
	print("for medium, 4 for fast, and 5 for fastest. Leaving this field will default to normal speed (3).")
	print()

	speed = input("Speed: ")

	if (speed == "1" or speed == "2" or speed == "3" or speed == "4" or speed == "5"):
		speed = "-T" + speed
	else:
		print("Invalid speed selection. Defaulting to speed of 3.")
		speed = "-T3"
	print()

# Syntax selector
def select_syntax():

	global syntax

	print()
	print("Please select a syntax for your scan output. Enter V to include version information, O")
	print("to enable OS detection, or A to include both of the previous options. Leaving the field")
	print("blank will omit all options and will output only the status of each selected port.")
	print()

	syntax = input("Syntax: ")

	if (syntax.upper() == "V" or syntax.upper() == "O" or syntax.upper() == "A"):
		syntax = " -" + syntax.upper()
	elif (syntax == ""):
		pass
	else:
		print("Invalid syntax selection. Defaulting to no syntax specifications.")
		syntax = ""
	print()

# Output selector
def select_output():

	global output

	print()
	print("If you would like the results of each scan to be printed to a file, please enter a file to be")
	print("created in the field below. If you do not need the scan results in a new file, leave the field")
	print("blank for standard terminal output.")
	print()

	output = input("Output File: ")
	output.replace(" ","_")
	print()

# Scans
def create_scans():

	global output
	global index
	global syn
	global tcp
	global udp
	global xmas
	global null

	index = 1
	out = ""
	portUDP = port

	scannedSYN = False
	scannedTCP = False
	scannedUDP = False
	scannedXMAS = False
	scannedNULL = False

	print()
	print()
	input("Data acquired. Ready to scan?")
	print()
	print()

	for item in nmapCommands:
		if (item == "syn"):
			if (scannedSYN == False):
				if (output == ""):
					pass
				elif (output[-4:] == ".txt"):
					out = " -oN " + output + str(index)
				else:
					out = " -oN " + output + str(index) + ".txt"
					index += 1			
				syn = "nmap -sS{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedSYN = True
			else:
				pass
		elif (item == "tcp"):
			if (scannedTCP == False):
				if (output == ""):
					pass
				elif (output[-4:] == ".txt"):
					out = " -oN " + output + str(index)
				else:
					out = " -oN " + output + str(index) + ".txt"
					index += 1
				tcp = "nmap -sT{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedTCP = True
			else:
				pass
		elif (item == "udp"):
			if (scannedUDP == False):
				if (output == ""):
					pass
				elif (output[-4:] == ".txt"):
					out = " -oN " + output + str(index)
				else:
					out = " -oN " + output + str(index) + ".txt"
					index += 1
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
				elif (output[-4:] == ".txt"):
					out = " -oN " + output + str(index)
				else:
					out = " -oN " + output + str(index) + ".txt"
					index += 1
				xmas = "nmap -sX{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedXMAS = True
			else:
				pass
		elif (item == "null"):
			if (scannedNULL == False):
				if (output == ""):
					pass
				elif (output[-4:] == ".txt"):
					out = " -oN " + output + str(index)
				else:
					out = " -oN " + output + str(index) + ".txt"
					index += 1
				null = "nmap -sN{} {} {} {}{}".format(syntax, speed, port, ip, out)
				scannedNULL = True
			else:
				pass
		else:
			pass
	print()
	
def run_scans():

	select_ip()
	select_port()
	select_scan()
	select_speed()
	select_syntax()
	select_output()
	create_scans()

	if (syn == ""):
		pass
	else:
		os.system(syn)

	if (tcp == ""):
		pass
	else:
		os.system(tcp)

	if (udp == ""):
		pass
	else:
		os.system(udp)

	if (xmas == ""):
		pass
	else:
		os.system(xmas)

	if (null == ""):
		pass
	else:
		os.system(null)

welcome_banner()
run_scans()
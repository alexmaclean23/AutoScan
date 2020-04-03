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


# Welcome banner	
def welcome_banner():
	print("")
	print("")
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

# IP selector
def select_ip():
	global ip
	print("")
	print("Please enter your target(s) to scan. Targets can be specified as an individual IP")
	print("or host, as a range of addresses, or using CIDR notation. To use a target file,")
	print("enter X into the field below.")
	print("")
	
	ip = (input("Target(s): ")
	
	if (ip == "X"):
		print("Enter the target file (or path to the file), including the extension.")
		ip = "-iL " + str(input("Target File: "))

# Port selector
# Scan selector
# Speed selector
# Output selector
# File selector

# SYN Scan
# TCP Scan
# UDP Scan
# XMAS Scan
# Null Scan

welcome_banner()
select_ip()

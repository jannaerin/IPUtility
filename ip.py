#!/usr/bin/env python

import subprocess
import csv
import GeoIP
import requests
import json
import socket
import data_ret
import GUI


def netstat(ext):
	"""Runs netstat once and calls the GeoIP API with each IP address
	found""" 
	cmd = ['netstat', ext]
	process = subprocess.Popen(cmd, stdout=subprocess.PIPE) # Call netstat -antu
	stdout, stderr = process.communicate() # Get output of netstat
	reader = csv.DictReader(stdout.decode('ascii').splitlines(), # Put output into CSV
	                        delimiter=' ', skipinitialspace=True,
	                        fieldnames=['protocol', 'rec-q',
	                                    'send-q', 'local address', 'foreign address',
	                                    'state'])
	geos = {}
	# Take each IP, call GeoIP API, and return information in dictionary
	for row in reader:
		IP = row['foreign address']
		if ord(IP[0]) > 48 and ord(IP[0]) < 58:
			IP = IP.split(':', 1)[0]
			url = 'http://freegeoip.net/json/' + IP
			r = requests.get(url)
			IPinfo = r.json()
			if IPinfo['country_name'] != '':
				geos[IP] = ['Country: ' + IPinfo['country_name'], 'City: ' + IPinfo['city']]
	return geos


def netstat_cont(ext, window, output):
	"""Runs netstat continuously, if an IP is found to be a threat, 
	stops the program and calls the alert function"""
	dat = data_ret.run_rep()

	# This is just an example to show the threat alert for an IP found in the DB
	"""threat = data_ret.get_rep("222.124.202.178", dat)
	if threat != None:
		output.put(True)
		output.put(["222.124.202.178"] + threat)
		return"""

	cmd = ['netstat', ext]
	process = subprocess.Popen(cmd, stdout=subprocess.PIPE) # Call netstat -cantu
	lines_iterator = iter(process.stdout.readline, b"") # As running, read each line
	for line in lines_iterator: # Check each IP for threat
		IP = line.split()[4]
		if ord(IP[0]) > 48 and ord(IP[0]) < 58:
			IP = IP.split(':', 1)[0]
			threats = data_ret.get_rep(IP, dat)
			if threats != None: # If threat found
				output.put(True) # Put True in output so that GUI knows to stop process and displasssssy alert
				output.put([IP] + threats)
				return


def display_info(output, var, window):
	"""Puts the desired information from netstat as a string into the output queue
	to be displayed by the GUI""" 
	if var == 1: # If checkbox is marked
		netstat_cont('-cantu', window, output) # Call continuous netstat
	else:
		connections = netstat('-antu') # Call netstat
		dat = data_ret.run_rep() # Get database
		ret_val = ''
		for key in connections: # Get all desired info for each IP and put in string
			threats = data_ret.get_rep(key, dat)
			ret_val += 'IP: ' + str(key) + '\n'
			for elem in connections[key]:
				if elem == 'city: ':
					ret_val += str(elem) + 'Unknown' + '\n'
				else:
					ret_val += str(elem) + '\n'
			if not threats:
				ret_val += 'Threats: none\n'
			else:
				ret_val += "Threat: " + threats[0] + '\n' + "Reliability: " + threats[1] + '\n' + "Risk: " + threats[2] + '\n'
			ret_val += '------------------------------------\n'
		output.put(ret_val) # Put string in output queue
		return


def display_firewall(output, IPs, self):
	"""Puts the desired information from the firewall log in the
	output queue to be dispalyed to the GUI"""
	dat = data_ret.run_rep()
	ret_val = ''

	for key in IPs: # Get all desired info for every IP
		ret_val += 'IP: ' + str(key) + '\n'
		url = 'http://freegeoip.net/json/' + key
		r = requests.get(url)
		IPinfo = r.json()
		if IPinfo['country_name'] != '':
			ret_val += 'Country: ' + IPinfo['country_name'] + '\n' + 'City: ' + IPinfo['city'] + '\n'
		threats = data_ret.get_rep(key, dat)
		if not threats:
			ret_val += 'Threats: none\n'
		else:
			ret_val += "Threat: " + threats[0] + '\n' + "Reliability: " + threats[1] + '\n' + "Risk: " + threats[2] + '\n'
		ret_val += '------------------------------------\n'
	output.put(ret_val) # Put in output queue
	return

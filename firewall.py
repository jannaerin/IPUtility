#!/usr/bin/python

import re

def read_log(f='log.txt'):
	log = open(f, 'r')
	IPlst = []

	for line in log:
		l = str(line)
		src = re.search("src=", l)
		dst = re.search("dst=", l)
		if src:
			srcIP = l[src.start() + 4:].split()[0]
			IPlst += [srcIP]
		if dst:
			dstIP = l[dst.end():].split()[0]
			IPlst += [dstIP]

	log.close()
	return IPlst
#!/usr/bin/python
"""Pulls information from the Alienvault IP reputation database"""
import sys
import urllib
import os.path
import pandas as pd

def run_rep():
	"""Returns the information from the Alienvault database"""
	avURL = "http://reputation.alienvault.com/reputation.data"
	avRep = "reputation.data"
	if not os.path.isfile(avRep):
		urllib.urlretrieve(avURL, filename=avRep)
	av = pd.read_csv(avRep, sep="#")
	av.columns = ["IP", "Reliability", "Risk", "Type", "Country", "Locale", "Coords", "x"]
	return av


def get_rep(currIP, data):
	"""Queries for the reputation of a particular IP adress"""
	if currIP in data['IP'].values:
		idx = data[data['IP'] == currIP].index.tolist() # pull data for IP
		row = data.loc[idx]
		threat = row["Type"].tolist() + row["Reliability"].tolist() + row["Risk"].tolist() # Take only desired data
		return threat


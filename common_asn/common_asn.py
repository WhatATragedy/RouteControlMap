from glob import glob
import collections
import logging
from tqdm import tqdm
import requests
import pandas as pd
import io

rib_lists = [
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.amsix\\rib.20200713.0000',
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.linx\\rib.20200713.0000',
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.kixp\\rib.20200713.0000',
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.sydney\\rib.20200713.0000',
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.eqix\\rib.20200713.0000',
]

rib_list = [
    'route-views.amsix',
    'route-views.linx',
    'route-views.kixp',
    'route-views.sydney',
    'route-views.eqix',
]

def init_asn_names():
    ##can be found here: https://ftp.ripe.net/ripe/asnames/asn.txt
    #with open('as_names.txt', 'w') as output:
    #   output.write(r.content)
    asn_name_data = []
    urlData = requests.get('https://ftp.ripe.net/ripe/asnames/asn.txt').content
    rawData = io.StringIO(urlData.decode('utf-8'))
    for line in rawData:
        if len(line.split(',')) >= 3:
            asn_num_and_name, asn_country = line.rsplit(',', 1)
            asn_num, asn_name = asn_num_and_name.split(' ', 1)
        else:
            values = line.split(' ', 1)
            asn_number = values[0]
            if len(values[1].split(',')) == 2:
                asn_name, asn_country = values[1].split(',')
            else:
                asn_name = values[1]
                asn_country = 'None'
        asn_name_data.append([asn_number, asn_name, asn_country.replace('\n', '')])     
    return asn_name_data

def enrich_asn_names(asn_counter):
    asn_name_df = pd.DataFrame(init_asn_names(), columns=['ASN', 'AS_Name', 'AS_Country'])
    asn_counter_df = pd.DataFrame(list(asn_counter.items()), columns=['ASN', 'Count'])
    combined = pd.merge(asn_counter_df, asn_name_df, how='left', on='ASN')

    return combined

asn_counter = collections.Counter()
for rib in rib_list:
    directory = f'E:\Stuff\Code\TheBlackGate\\ribs\\{rib}\\'
    print(f'About to Parse {directory}')
    for filename in glob(directory+'*'):
        lines_in_file = len(open(filename, 'r').readlines())
        print(f'About to Parse {lines_in_file} lines in {filename}...')
        with open(filename) as input_rib:
            for line in tqdm(input_rib, total=lines_in_file, position=0, leave=True):
                """ Table Breakdown
                [0] - Table Name
                [1] - Date
                [2] - Protocol
                [3] - Originating IP
                [4] - Originating AS
                [5] - Prefix Advertised
                [6] - AS-Path
                [7] - Learnt Via
                """
                asn_path = line.split('|')[6]
                asn_counter.update(asn for asn in asn_path.split(' '))
        
top_asns = enrich_asn_names(asn_counter)
top_asns.to_csv('top_asn_rib.csv')
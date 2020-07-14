from glob import glob
import collections
import logging
from tqdm import tqdm
import requests
import pandas as pd
import io

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

def enrich_asn_names_ip(grouped_asn):
    asn_name_df = pd.DataFrame(init_asn_names(), columns=['ASN', 'AS_Name', 'AS_Country'])
    asn_name_df['ASN'] = asn_name_df['ASN'].astype(str)
    grouped_asn['ASN'] = grouped_asn['ASN'].astype(str)
    combined = pd.merge(grouped_asn, asn_name_df, how='left', on='ASN')
    return combined

def request_top_ips():
    #TODO
    return None

def load_top_ip_file(filename):
    top_ip_data = []
    with open(filename) as input_file:
        for line in input_file:
            line = line.strip()
            ip, source, count = line.split(',')
            top_ip_data.append((ip, count))
    top_ip_df = pd.DataFrame(top_ip_data, columns=['ip', 'count'])
    return top_ip_df

def load_ip_to_asn_file():
    import pyasn
    # Initialize module and load IP to ASN database
    # the sample database can be downloaded or built - see below
    asndb = pyasn.pyasn('/home/ec2-user/RouteControlMap/top_asns_and_ips/amsix.db')
    return asndb

def enrich_ips_with_asn(top_ip_df, asndb):
    top_ip_df = top_ip_df.dropna()
    top_ip_df[['ASN', 'Range']] = top_ip_df.ip.apply(enrich_ip)
    return top_ip_df

def enrich_ip(ip_row):
    asn, ip_range = asndb.lookup(ip_row)
    if asn is not None and ip_range is not None:
        return pd.Series([asn, ip_range])
    else:
        return pd.Series(['Unknown', 'Unknown'])

    
directory = '/home/ec2-user/TheBlackGate/ribs/route-views.linx/'
asn_counter = collections.Counter()
for filename in glob(directory+'*'):
    lines_in_file = len(open(filename, 'r').readlines())
    logging.debug(f'About to Parse {lines_in_file} lines in {filename}...')
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
linx_top_asns = enrich_asn_names(asn_counter)
linx_top_asns.to_csv('top_asn_linx_rib.csv')

# top_ip_df = load_top_ip_file('/home/ec2-user/RouteControlMap/top_asns_and_ips/response.json')
# asndb = load_ip_to_asn_file()
# results = enrich_ips_with_asn(top_ip_df, asndb)
# results['count'] = results['count'].astype(int)
# results = results.groupby(['ASN'])['count'].sum().reset_index()
# enriched_results = enrich_asn_names_ip(results)
# enriched_results.to_csv('aggregated_asns_from_ips.csv')


    
            
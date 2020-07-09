import pandas as pd
import json
import netaddr
import ipaddress
import logging 
from tqdm import tqdm
import multiprocessing
from functools import partial
import os

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s: %(message)s"
)

def process_bgp_rib_file(filepath):
    prefix_and_originating_as = set()
    lines_in_file = len(open(filepath, 'r').readlines())
    logging.debug(f'About to Parse {lines_in_file} lines in {filepath}...')
    with open(filepath) as bgp_rib_file:
        for line in tqdm(bgp_rib_file, total=lines_in_file, position=0, leave=True):
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
            values = line.split('|')
            date = values[1]
            prefix_advertised = values[5]
            origin_asn = values[6].split(' ')[-1]
            item = (date, prefix_advertised, origin_asn)
            prefix_and_originating_as.add(item)
    return prefix_and_originating_as

def create_processed_rib_files(filenames, output_file=None):
    output_file = output_file if output_file is not None else 'processed_ribs_new.txt'
    data = set()
    ##something going wrong here with parsing
    """
    ,0,1,2,Date,OriginASN,Prefix
    0,07/02/20 18:36:03,109.49.192.0/18,2860,,,
    """
    for filename in filenames:
        file_data = process_bgp_rib_file(filename)
        data.update(file_data)
    rib_df = pd.DataFrame(data, columns=['Date', 'Prefix', 'OriginASN'])
    rib_df = rib_df.drop_duplicates()
    rib_df.to_csv(output_file)
    return rib_df

def load_rpki_routes(filenames):
    logging.debug(f'About to Load in RPKI Files...')
    tal_df = pd.DataFrame(columns=['ASN', 'IP Prefix', 'Max Length'])
    for filename in filenames:
        try:
            tal_df = tal_df.append(pd.read_csv(filename)[['ASN','IP Prefix','Max Length']])
        except KeyError:
            logging.debug(f'Error Parsing {filename}...')
    logging.debug(f'Finished Loading RPKI Files...')
    return tal_df

def load_processed_ribs(filename):
    logging.debug(f'About to Load in RIB File...')
    return pd.read_csv(filename)
    logging.debug(f'Finished Loading RIB File...')


def is_route_stamped(signed_routes, row):
    ip_prefix = row['Prefix']
    ip_prefix = ipaddress.ip_network(ip_prefix)
    #do some initial checks to make sure nobody is advertising a huge range
    if is_range_valid(ip_prefix):
        for rpki_prefix in signed_routes:
            if ip_prefix.overlaps(ipaddress.ip_network(rpki_prefix)):
                logging.debug(f'{ip_prefix} and {rpki_prefix}: {ip_prefix.overlaps(ipaddress.ip_network(rpki_prefix))}')
                return True
            else:
                continue
        return False
    else:
        logging.debug(f'Issue with {ip_prefix}...')
    
def is_range_valid(ip_prefix):
    if (ip_prefix.version == 4):
        ##check it's no larger than a /15
        if ip_prefix.num_addresses > 131072:
            logging.debug(f'Too many hosts, {ip_prefix} has {ip_prefix.num_addresses} hosts...')
            return False
        ##check if it's a valid IPv4 (not reserved)
        elif not ip_prefix.is_global:
            logging.debug(f'{ip_prefix} is not global...')
            return False
        else:
            return True
    if (ip_prefix.version == 6):
        return False
    else:
        return False

rib_list = [
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.amsix\\rib.20200707.0000',
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.linx\\rib.20200707.0000',
    'E:\Stuff\Code\TheBlackGate\\ribs\\route-views.kixp\\rib.20200707.0000',
]

#rib_df = create_processed_rib_files(rib_list)
tal_files = []
for dirpath, dirnames, filenames in os.walk('E:\Stuff\Code\\tals'):
    for filename in filenames:
        tal_files.append(os.path.join(dirpath, filename))

rpki_dataframe = load_rpki_routes(tal_files)

rib_df = load_processed_ribs('processed_ribs_new.txt')
#merged = pd.merge(rpki_dataframe, rib_df, left_on='IP Prefix', right_on='Prefix', how='right')
rib_df = rib_df.drop_duplicates()
merged = pd.merge(rpki_dataframe, rib_df, left_on='IP Prefix', right_on='Prefix', how='right')   
merged['isRPKI'] = [False if isinstance(item['ASN'], float) else True for (index, item) in merged.iterrows()]


"""
bgp_ribs = pd.read_csv('rib-amsix-2020-03-27-14-00.parsed', sep='|', header=None)
bgp_ribs.columns = ['Name', 'Date', 'Protocol', 'Source_IP', 'Source_ASN', 'Prefix', 'AS_PATH', 'Learnt_Via']
with open('data.json') as rpki_file:
    rpki_routes = json.load(rpki_file)
rpki_df = pd.DataFrame(rpki_routes['roas'])
signed_routes = rpki_df['prefix'].values
#create a new data frame for our results
results_df = pd.DataFrame()
#for index, row in tqdm(bgp_ribs.iterrows(), total=bgp_ribs.shape[0]):
func = partial(is_route_stamped, signed_routes)
pool=multiprocessing.Pool(7)
pool.map(func, bgp_ribs.iterrows()[1])
pool.close()
pool.join()
"""
"""
for index, row in bgp_ribs.iterrows():
    ip_prefix = row['Prefix']
    ip_prefix = ipaddress.ip_network(ip_prefix)
    #do some initial checks to make sure nobody is advertising a huge range
    if is_range_valid(ip_prefix):
        for rpki_prefix in signed_routes:
            logging.debug(f'{ip_prefix} and {rpki_prefix}')
            logging.debug(f'{ip_prefix.overlaps(ipaddress.ip_network(rpki_prefix))}')
    else:
        logging.debug(f'Issue with {ip_prefix}...')
##loop over the BPG ranges and work out if they're signed of not"""


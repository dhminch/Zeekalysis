#!/usr/bin/python3

import argparse
import binascii
import gzip
import ipaddress
import os
import sqlite3
import time

#class ZeekLog:
#
#    def __init__(self, directory, filename):
#        self.directory = directory
#        self.filename = filename
#
#
#
#def find_logs(logdirs):
#    for basedir in logdirs:
#        for current_dir, subdirlist, filelist in os.walk(basedir):
#            for current_file in filelist:
#                print("{} {}".format(basedir, dirname, current_file))
#


def parse_zeek_log(logfile):
    if not os.path.isfile(logfile):
        raise ValueError("Log file {} does not exist".format(logfile))

    if logfile.endswith('.gz'):
        open_method = gzip.open
    else:
        open_method = open

    with open_method(logfile, 'rt') as logfile_handle:
        separator = None
        fields = None

        for line in logfile_handle:
            if not line.strip().startswith('#'):
                break

            if line.strip().lstrip('#').startswith('separator'):
                separator_text = line.strip().lstrip('#').split(' ')[1]
                separator = binascii.unhexlify(separator_text[2:]).decode("utf8")

            if line.strip().lstrip('#').startswith('fields'):
                if separator is None:
                    raise ValueError("Log does not specify separator")
                fields = line.strip().lstrip('#').split(separator)
                fields.pop(0)

        if separator is None or fields is None:
            raise ValueError("Unable to parse log headers")

        logfile_handle.seek(0)

        for line in logfile_handle:
            if line.strip().startswith('#'):
                continue
            
            line_fields = line.strip().split(separator)
            line_dict = {}
            for i,field in enumerate(fields):
                line_dict[field] = line_fields[i]
            yield line_dict



def load_dns_into_db(conn, dns_log):
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS dns''')
    cursor.execute('''CREATE TABLE dns (id INTEGER PRIMARY KEY, timestamp REAL, sip TEXT, query TEXT, answer TEXT)''')
    conn.commit()

    for line_dict in parse_zeek_log(dns_log):
        if line_dict['qtype_name'] not in ['A']:
            continue

        for answer in line_dict['answers'].split(','):
            cursor.execute('''INSERT INTO dns VALUES (NULL,?,?,?,?)''', 
                            (line_dict['ts'], line_dict['id_orig_h'],
                                line_dict['query'], answer))

    conn.commit()
    cursor.close()


def load_conn_into_db(conn, conn_log):
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS conn''')
    cursor.execute('''CREATE TABLE conn (id INTEGER PRIMARY KEY, timestamp REAL, sip TEXT, sport INTEGER, dip TEXT, dport INTEGER, proto TEXT, bytes INTEGER, duration REAL)''')

    for line_dict in parse_zeek_log(conn_log):
        if line_dict['orig_bytes'] == '-':
            orig_bytes = 0
        else:
            orig_bytes = int(line_dict['orig_bytes'])

        if line_dict['resp_bytes'] == '-':
            resp_bytes = 0
        else:
            resp_bytes = int(line_dict['resp_bytes'])

        if line_dict['duration'] == '-':
            duration = 0
        else:
            duration = float(line_dict['duration'])
    
        total_bytes = orig_bytes + resp_bytes

        cursor.execute('''INSERT INTO conn VALUES (NULL, ?,?,?,?,?,?,?,?)''',
                        (line_dict['ts'], line_dict['id_orig_h'], line_dict['id_orig_p'],
                            line_dict['id_resp_h'], line_dict['id_resp_p'], line_dict['proto'],
                            total_bytes, duration))

    conn.commit()
    cursor.close()


def make_dns_associations(conn):
    dns_cursor = conn.cursor()
    dnsconn_cursor = conn.cursor()
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS conndns''')
    cursor.execute('''CREATE TABLE conndns (dnsid INTEGER, connid INTEGER)''')
    
    cursor.execute('''SELECT id, timestamp, dip FROM conn LIMIT 10000''')
    for conn_row in cursor:
        timestamp = conn_row[1]
        dip = conn_row[2]
        
        dip_ipaddr = ipaddress.ip_address(dip)
        if dip_ipaddr is ipaddress.IPv6Address:
            continue
        if not dip_ipaddr.is_global or dip_ipaddr.is_multicast:
            continue

        dns_cursor.execute('''SELECT id FROM dns 
                                WHERE   answer = ? AND 
                                        timestamp < ? 
                                ORDER BY timestamp DESC
                                LIMIT 1''', (dip, timestamp))
        dns_row = dns_cursor.fetchone()
        if dns_row is None:
            print("No DNS associated with {}".format(dip))
            continue

        dnsconn_cursor.execute('''INSERT INTO conndns VALUES (?,?)''', (dns_row[0], conn_row[0]))

    conn.commit()
    dnsconn_cursor.close()
    dns_cursor.close()
    cursor.close()





def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dnslog')
    parser.add_argument('connlog')
    args = parser.parse_args()

    if not os.path.isfile(args.dnslog):
        raise ValueError("The DNS log file given is not a file: {}".format(args.dnslog))

    if not os.path.isfile(args.connlog):
        raise ValueError("The Conection log file given is not a file: {}".format(args.connlog))        

    conn = sqlite3.connect('zeekalysis.db')
    
    print("Begin loading of DNS logs.")
    load_dns_start = time.time()  
    load_dns_into_db(conn, args.dnslog)
    load_dns_stop = time.time()
    print("Done loading of DNS logs ({:.2f} s).".format(load_dns_stop-load_dns_start))
    
    print("Begin loading of Connection logs.")
    load_conn_start = time.time()
    load_conn_into_db(conn, args.connlog)
    load_conn_stop = time.time()
    print("Done loading of Connection logs ({:.2f} s).".format(load_conn_stop-load_conn_start))
    
    print("Begin making DNS associations.", end='')
    make_dns_assoc_start = time.time()
    make_dns_associations(conn)
    make_dns_assoc_stop = time.time()
    print("Done making DNS associations ({:.2f} s).".format(make_dns_assoc_stop-make_dns_assoc_start))
    

    conn.close()


if __name__ == "__main__":
  main()

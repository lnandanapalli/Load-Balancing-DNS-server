#!/usr/bin/env python3
"""
Licensed under the Apache License, Version 2.0.
"""

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import yaml
import requests
import os
import json
import psutil
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from math import radians, sin, cos, sqrt, atan2
import logging
from dnslib import *

lock = threading.Lock()

def dns_log(message, severity=0):
    log_level = logging.CRITICAL if severity == -1 else (logging.INFO if severity == 0 else logging.WARNING)
    current_datetime = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    log_message = f"{current_datetime} - {message}"
    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.INFO)  
        file_handler = logging.FileHandler('dnsserver.log')
        file_handler.setLevel(logging.INFO)  
        logging.getLogger().addHandler(file_handler)
    logging.log(log_level, log_message)

def is_already_running():
    lock_file_path = "dns_server.lock"
    if os.path.isfile(lock_file_path):
        with open(lock_file_path, "r") as lock_file:
            pid = lock_file.read().strip()
            if pid and psutil.pid_exists(int(pid)):
                return True
            else:   
                os.remove(lock_file_path)
    with open(lock_file_path, "w") as lock_file:
        lock_file.write(str(os.getpid()))
    return False

def create_systemd_service():
    service_content = f"""
    [Unit]
    Description=DNS Server
    After=network.target

    [Service]
    ExecStart=/usr/bin/python3 {config["home_dir"]}/dnsserver.py --tcp --udp
    WorkingDirectory={config["home_dir"]}
    Restart=always
    RestartSec=3

    [Install]
    WantedBy=default.target
    """

    with open("/etc/systemd/system/dns_server.service", "w") as service_file:
        service_file.write(service_content)
    os.system("systemctl enable dns_server")
    os.system("systemctl start dns_server")
    os.system("systemctl daemon-reload")

def remove_systemd_service():
    os.system("systemctl stop dns_server")
    os.system("systemctl disable dns_server")
    os.system("rm /etc/systemd/system/dns_server.service")
    os.system("systemctl daemon-reload")


def remove_lock_file():
    lock_file_path = "dns_server.lock"
    if os.path.isfile(lock_file_path):
        os.remove(lock_file_path)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

class LoadRequestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        global load_data
        global lock
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        params = parse_qs(post_data.decode('utf-8'))
        
        ip = params.get('ip', [''])[0]
        load = float(params.get('load', [0])[0])

        lock.acquire()
        
        load_data[ip] = load

        
        with open("load.json", "w") as load_file:
            json.dump(load_data, load_file)
        lock.release()
        self.send_response(200)
        self.end_headers()

D = DomainName('lokeshwarreddyshanthanrao.com.')
IP = None
DNS_IP = None
TTL = 60
client_ip = None

soa_record = SOA(
    mname=D.ns3,  
    rname=D.lokesh,  
    times=(
        201307231,  
        60 * 60 * 1,  
        60 * 60 * 3,  
        60 * 60 * 24,  
        60 * 60 * 1,  
    )
)
ns_records = [NS(D.ns3), NS(D.ns4)]

def is_web_server_up(ip):
    try:
        response = requests.get(f"http://{ip}:80")
        return response.status_code == 200
    except Exception:
        return False

def load_ip_addresses(ips):
    ips_temp = []
    for ip in ips:
        if is_web_server_up(ip):
            ips_temp.append(ip)
    return ips_temp

config = None
geo_data = None
load_data = None

with open("config.yml", "r") as f:
    config = yaml.safe_load(f)

with open(config["geo_data_file"], "r") as geo_file:
    geo_data = json.load(geo_file)

with open(config["load_data_file"], "r") as load_file:
    load_data = json.load(load_file)

ip_addresses = load_ip_addresses(config["ip_addresses"])
DNS_IP = config["dns_ip_address"]

records = None

def start_load_service():
    global load_data  

    def load_service():
        port = 8080
        server_address = ('', port)
        httpd = HTTPServer(server_address, LoadRequestHandler)

        print(f"Load service running on port {port}")
        httpd.serve_forever()

    load_thread = threading.Thread(target=load_service)
    load_thread.daemon = True
    load_thread.start()

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371.0  
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    return distance

def get_nearest_ip():
    global geo_data
    global client_ip
    if not client_ip:
        print("Error: Client IP not available.")
        return None
    client_geo_info = requests.get(f"http://api.ipstack.com/{client_ip}?access_key={config['geo_api_key']}").json()
    client_lat = client_geo_info['latitude']
    client_lon = client_geo_info['longitude']
    nearest_ip = None
    min_distance = float('inf')
    for ip, geo_info in geo_data.items():
        lat = geo_info['latitude']
        lon = geo_info['longitude']
        distance = calculate_distance(client_lat, client_lon, lat, lon)
        if distance < min_distance:
            min_distance = distance
            nearest_ip = ip
    return nearest_ip

def get_lowest_load_ip():
    global load_data
    if not load_data:
        print("Error: Load data not available.")
        dns_log("Error: Load data not available.")
        return None
    lowest_load_ip = min(load_data, key=load_data.get)
    return lowest_load_ip

def next_ip_address():
    global IP
    global DNS_IP
    global ip_addresses
    global records
    lock.acquire()
    if config["algorithm"] == "geo":
        try:
            IP = get_nearest_ip()
        except:
            IP = config["ip_addresses"][0]
    elif config["algorithm"] == "load":
        try:
            IP = get_lowest_load_ip()
        except:
            IP = config["ip_addresses"][0]
    else:
        temp = ip_addresses.pop(0)
        IP = temp
        ip_addresses.append(temp)
    records = {
        D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
        D.ns3: [A(DNS_IP)],
        D.ns4: [A(DNS_IP)],
        D.mail: [A(DNS_IP)],
        D.lokesh: [CNAME(D)],
    }
    lock.release()

last_modified_time = 0
geo_last_modified_time = 0
load_last_modified_time = 0

def file_watcher():
    global last_modified_time
    global config
    global geo_data
    global load_data
    global ip_addresses
    while True:
        try:
            file_stat = os.stat('config.yml')
            current_modified_time = file_stat.st_mtime
            if current_modified_time != last_modified_time:
                last_modified_time = current_modified_time
                lock.acquire()
                with open("config.yml", "r") as f:
                    config = yaml.safe_load(f)
                with open(config["geo_data_file"], "r") as geo_file:
                    geo_data = json.load(geo_file)
                with open(config["load_data_file"], "r") as load_file:
                    load_data = json.load(load_file)
                ip_addresses = load_ip_addresses(config["ip_addresses"])
                dns_log("Config Updated")
                lock.release()
        except FileNotFoundError:
            pass
        time.sleep(1)

def geo_file_watcher():
    global geo_last_modified_time
    global geo_data

    while True:
        try:
            file_stat = os.stat('geo_data.json')
            current_modified_time = file_stat.st_mtime
            if current_modified_time != geo_last_modified_time:
                geo_last_modified_time = current_modified_time
                lock.acquire()
                with open(config["geo_data_file"], "r") as geo_file:
                    new_geo_data = json.load(geo_file)
                    
                    for ip in list(new_geo_data.keys()):
                        if ip not in geo_data and not is_web_server_up(ip):
                            del new_geo_data[ip]
                            dns_log(f"Removed {ip} from new_geo_data due to unavailability.")
                    geo_data = new_geo_data
                lock.release()
        except FileNotFoundError:
            pass
        time.sleep(1)


def load_file_watcher():
    global load_last_modified_time
    global load_data

    while True:
        try:
            file_stat = os.stat('load.json')
            current_modified_time = file_stat.st_mtime
            if current_modified_time != load_last_modified_time:
                load_last_modified_time = current_modified_time
                lock.acquire()
                with open(config["load_data_file"], "r") as load_file:
                    new_load_data = json.load(load_file)
                    
                    for ip in list(new_load_data.keys()):
                        if ip not in load_data and not is_web_server_up(ip):
                            del new_load_data[ip]
                            dns_log(f"Removed {ip} from new_load_data due to unavailability.")
                    load_data = new_load_data
                lock.release()
        except FileNotFoundError:
            pass
        time.sleep(1)

def dns_response(data):
    request = DNSRecord.parse(data)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qn == D or qn.endswith('.' + D):

        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    print("---- Reply:\n", reply)

    return reply.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        global client_ip
        client_ip = self.client_address[0]
        next_ip_address()
        dns_log("Client IP address: %s" % client_ip)
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        next_ip_address()
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        next_ip_address()
        return self.request[1].sendto(data, self.client_address)


def main():
    def check_config_files():
        dns_log("Configuration file check started.")
        config_file_path = 'config.yml'
        geo_data_file_path = 'geo_data.json'
        load_data_file_path = 'load.json'

        if not os.path.exists(config_file_path):
            print(f"Error: Config file '{config_file_path}' not found.")
            dns_log("Error: Config file '%s' not found." % config_file_path)
            return False

        if not os.path.exists(geo_data_file_path):
            print(f"Error: Geo data file '{geo_data_file_path}' not found.")
            dns_log("Error: Geo data file '%s' not found." % geo_data_file_)
            return False

        if not os.path.exists(load_data_file_path):
            print(f"Error: Load data file '{load_data_file_path}' not found.")
            dns_log("Error: Load data file '%s' not found." % load_data_file_path)
            return False

        with open(config_file_path, 'r') as config_file:
            config_data = yaml.safe_load(config_file)

        with open(geo_data_file_path, 'r') as geo_data_file:
            geo_data = json.load(geo_data_file)

        with open(load_data_file_path, 'r') as load_data_file:
            load_data = json.load(load_data_file)

        config_ips = set(config_data['ip_addresses'])
        geo_ips = set(geo_data.keys())
        load_ips = set(load_data.keys())

        if config_ips != geo_ips or config_ips != load_ips or geo_ips != load_ips:
            print("Error: IP addresses in config, geo data, and load data do not match.")
            dns_log("Error: IP addresses in config, geo data, and load data do not match.")
            return False

        print("All files are correct.")
        dns_log("All files are correct.")
        return True

    check_config_files()

    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  
        thread.daemon = True  
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        action = sys.argv[1]

        if action == "stop":
            remove_systemd_service()
            remove_lock_file()
            print("DNS server stopped.")
            dns_log("DNS server stopped.")
            sys.exit(0)
        else:
            print("To stop: Run as root - sudo python3 dns_server.py stop")

    try:
        if is_already_running():
            print("Another instance is already running. Exiting.")
            sys.exit(0)

        create_systemd_service()
        start_load_service()

        watcher_thread = threading.Thread(target=file_watcher)
        watcher_thread.daemon = True
        watcher_thread.start()

        geo_watcher_thread = threading.Thread(target=geo_file_watcher)
        geo_watcher_thread.daemon = True
        geo_watcher_thread.start()

        load_watcher_thread = threading.Thread(target=load_file_watcher)
        load_watcher_thread.daemon = True
        load_watcher_thread.start()
        main()

    except KeyboardInterrupt:
        print("DNS server stopped by the user.")
        dns_log("DNS server stopped by the user.")
        remove_lock_file()

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        dns_log(f"An unexpected error occurred: {e}")
        remove_lock_file()
        sys.exit(1)

from requests.exceptions import SSLError, ConnectTimeout, ConnectionError, ReadTimeout
from urllib3 import disable_warnings

import socket
import threading
import requests
import re


disable_warnings()


class Scan(object):
    ports = []

    def __init__(self, **kwargs):
        self.targets = kwargs.get('targets', [])
        self.threads = kwargs.get('threads', 40)
        self.lock = threading.BoundedSemaphore(self.threads)
        self.results = []

    def run(self):
        th_pool = []
        for ip in self.targets:
            for port in self.ports:
                th = threading.Thread(target=self._scan, args=(ip, port,))
                th.start()
                th_pool.append(th)
        for th in th_pool:
            th.join()

    def _scan(self, ip, port):
        pass

    def print(self):
        for i in self.results:
            for key, value in i.items():
                print('[+]{}: {}'.format(key, value))
            print()


class PortScan(Scan):
    def __init__(self, **kwargs):
        super(PortScan, self).__init__(**kwargs)

        self.ports = kwargs.get('ports')

    def _scan(self, ip, port):
        self.lock.acquire()
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, int(port)))

            self.results.append({'ip': ip, 'port': port, 'status': 'open'})
        except socket.timeout:
            # print('[ERR]', e)
            self.results.append({'ip': ip, 'port': port, 'status': 'close'})
            pass
        self.lock.release()


class DBScan(Scan):
    ports = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 389: 'ldap', 873: 'rsync',
        1433: 'mssql', 1521: 'oracle', 2181: 'zookeeper', 3690: 'svn',
        3306: 'mysql', 5000: 'DB2', 5432: 'PostGreSQL', 5984: 'CouchDB',
        6379: 'redis', 9200: 'ElasticSearch', 27017: 'mongodb',
        11211: 'memcached', 50070: 'hadoop'
    }

    def _scan(self, ip, port):
        self.lock.acquire()
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, int(port)))

            self.results.append({'ip': ip, 'port': port, 'info': self.ports[port]})
        except socket.timeout:
            # print('[ERR]', e)
            pass
        self.lock.release()


class WebScan(Scan):
    ports = [
        80, 83, 89, 8001, 8008, 8009, 8440, 8441, 8442, 8443, 8444,
        8445, 8446, 8447, 8448, 8449, 8450, 8080, 8081, 8082, 8083,
        8084, 8085, 8086, 8087, 8088, 8089, 9091
    ]

    def _scan(self, host, port):
        self.lock.acquire()
        protocols = ['http', 'https']
        for pro in protocols:
            try:
                url = '{}://{}:{}'.format(pro, host, port)
                resp = requests.get(url, timeout=2.0, verify=False)
                title = re.search('<title>(.*)</title>', resp.text)
                if title:
                    title = title.group(1)
                else:
                    title = ''

                self.results.append({'url': url, 'info': title})
            except (SSLError, ConnectTimeout, ConnectionError, ReadTimeout):
                # print('[ERR]', e)
                pass
        self.lock.release()

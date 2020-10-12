from base64 import b64encode
from ipaddress import ip_network

import requests
import time
import sys


class FoFa(object):
    hack_dict = {
        'Files Leak': 'body="index of/"',
        'PHPinfo': 'body="<title>phpinfo()"',

        'MySQL Brute': 'port=3306 && protocol=="mysql" && banner!="not allowed"',
        'MSSQL Brute': 'port=1433 && banner="MSSQL Server"',
        'Postgresql Brute': 'port=5432 && banner!="FATAL"',
        'Redis UnAuth': 'port=6379 && banner="redis_version"',
        'Zookeeper UnAuth': 'port=2181 && banner="Zookeeper version"',
        'CouchDB': 'port=5984 && protocol=="couchdb(http)"',
        'ElasticSearch': 'port=9200 && protocol=="elastic"',
        'MongoDB UnAuth': 'port=27017 && protocol=="mongodb" && banner="asserts"',
        'Memcache': 'port=11211 && protocol=="memcache"',
    }

    def __init__(self, **kwargs):
        self.email = kwargs.get('email')
        self.api_key = kwargs.get('api_key')

        self._check()

    def _check(self):
        if self.email is not None or self.api_key is not None:
            url = 'https://fofa.so/api/v1/info/my?email={0}&key={1}'.format(self.email, self.api_key)
            try:
                resp = requests.get(url)
                data = resp.json()
                if data.get('error'):
                    print(data['errmsg'])
                    sys.exit(1)
            except (ConnectionError, TimeoutError):
                print('Cannot connect!')
        else:
            print('No email or api key!')
            sys.exit(1)

    def search(self, keywords, clean=False):
        if clean:
            keywords += '&&after="{}"'.format(time.strftime('%Y', time.localtime()))

        query = b64encode(keywords.encode('utf-8')).decode('utf-8')
        url = 'https://fofa.so/api/v1/search/all?'
        url += 'email={}'.format(self.email)
        url += '&key={}'.format(self.api_key)
        url += '&qbase64={}'.format(query)
        try:
            resp = requests.get(url)
            return resp.json()
        except ConnectionError:
            return None

    def hack(self, target, clean=False):
        results = {}
        for name in self.hack_dict.keys():
            keywords = self.hack_dict[name]

            try:
                ip_network(target, strict=False)
                keywords += ' && ip="{}"'.format(target)
            except ValueError:
                keywords += ' && domain="{}"'.format(target)
            return_data = self.search(keywords, clean)

            # print(type(return_data.get('size')))
            if return_data.get('size') > 0:
                info = {
                    name: {
                        'query': return_data['query'],
                        'size': return_data['size'],
                        'results': return_data['results']
                    }
                }
                results.update(info)
            else:
                continue
        return results


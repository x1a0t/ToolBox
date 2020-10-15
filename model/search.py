from base64 import b64encode
from ipaddress import ip_network
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.keys import Keys

import requests
import time
import sys


class FoFa(object):
    dorks = {
        'Files Leak': 'body="index of/"',
        'PHPinfo': 'body="<title>phpinfo()</title>"',

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
        for name, keywords in self.dorks.items():
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


class Browser(object):
    def __init__(self, **kwargs):
        self.options = kwargs.get('options', [''])
        self._init_options()

    def _init_options(self):
        options = webdriver.FirefoxOptions()
        for option in self.options:
            options.add_argument(option)

        self.browser = webdriver.Firefox(options=options)

    def get_page_resource(self, url):
        try:
            self.browser.get(url)
            page_resource = self.browser.page_source
            return page_resource
        except TimeoutException:
            return None
        finally:
            self.browser.close()

    def baidu(self, keywords):
        tmp_results = set()

        try:
            self.browser.get('https://www.baidu.com')
        except TimeoutException:
            print('can not baidu')
            return
        key_input = self.browser.find_element_by_id('kw')
        key_input.send_keys(keywords)
        key_input.send_keys(Keys.ENTER)
        time.sleep(3)
        while 1:
            a = self.browser.find_elements_by_class_name('c-showurl')
            for i in a:
                href = i.get_attribute('href')
                if href:
                    tmp_results.add(href)
            try:
                next_page = self.browser.find_element_by_link_text('下一页 >')
                next_page.click()
                time.sleep(3)
            except NoSuchElementException:
                break
            finally:
                self.browser.close()

        results = set()
        for result in tmp_results:
            try:
                resp = requests.get(result, allow_redirects=False)
                results.add(resp.headers['Location'])
            except Exception:
                pass
        return results

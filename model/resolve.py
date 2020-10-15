from socket import gethostbyname_ex


class DomainResolve(object):
    def __init__(self, **kwargs):
        self.domains = kwargs.get('domains')
        self.results = []

    def simple_resolve(self):
        for domain in self.domains:
            a_cname, cname, ips = gethostbyname_ex(domain)
            cname.append(a_cname)
            domain = cname.pop(0)
            self.results.append({'domain': domain, 'cname': cname, 'ip': ips})

    # 判断有无cname来判断是否为真实IP，并不准确
    def get_real_ip(self):
        results = []
        if self.results:
            for info in self.results:
                if not info.get('cname'):
                    results.append(info)
        return results

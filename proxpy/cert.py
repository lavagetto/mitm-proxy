#!/usr/bin/python
"""
  Copyright notice
  ================
  
  Copyright (C) 2013
      Joe	<joe@autistici.org> 
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  Proxpy is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
"""
import os
import envoy
import tempfile
from jinja2 import Environment, FileSystemLoader
import shutil
import threading

# some useful paths
CODE_DIR = os.path.dirname(os.path.realpath(__file__))
CA_DIR = os.path.join(CODE_DIR,'cert')
CERTS_CACHE_DIR = os.path.join(CODE_DIR,'certcache')
TPL_DIR = os.path.join(CODE_DIR,'templates')


jinja = Environment(loader=FileSystemLoader(TPL_DIR), autoescape=True)
tpl =  jinja.get_template('openssl.tpl')

lock = threading.Lock()


class Certificate(object):
    fallback_cert = None
    def __init__(self, domain, logger):
        self.log = logger
        #TODO: validate domain a little bit better...
        if domain.find('/') >= 0:
            raise ValueError("Invalid domain %s" % domain)
        self.cn = domain
        self.cert_dir = os.path.join(CERTS_CACHE_DIR, domain)
        self.cert_path = os.path.join(self.cert_dir, 'cert.pem')
        if not os.path.exists(self.cert_path):
            if not self._generate_cert():
                self.log.error("Cannot generate certificate for domain %s" % domain)
                self.cert_path = self.fallback_cert

    def _generate_cert(self):
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
        t = tpl.render(common_name = self.cn, ca_cert_dir = CA_DIR )
        fh = tempfile.NamedTemporaryFile(delete=False)
        fh.write(t)
        fh.close()
        ssl_conf = fh.name
        key = os.path.join(self.cert_dir, 'cert.key')
        csr = os.path.join(self.cert_dir, 'cert.csr')
        crt = os.path.join(self.cert_dir, 'cert.crt')
        success = True
        #Now fiddle with all the shitty options of openssl(1)
        try:
            lock.acquire()
            if not os.path.exists(key):
                cmd = 'openssl req -config %s -days 365 -nodes -new -keyout %s -out %s' % (ssl_conf, key,csr)
                self.log.error(cmd)
                gencert = envoy.run(cmd)
                if gencert.status_code != 0:
                    raise OSError(gencert.status_code, "problem generating the certificate: %s" % gencert.std_err)
            if not os.path.exists(crt):
                cmd = 'openssl ca -batch -notext -config %s -out  %s -infiles %s' % (ssl_conf, crt, csr)
                self.log.error(cmd)
                signcert = envoy.run(cmd)
                if signcert.status_code != 0:
                    raise OSError(signcert.status_code, "problem signing the certificate: %s" % signcert.std_err)
            if not os.path.exists(self.cert_path):
                destination = open(self.cert_path, 'wb')
                shutil.copyfileobj(open(crt, 'rb'), destination)
                shutil.copyfileobj(open(key, 'rb'), destination)
                destination.close()
        except Exception, e:
            self.log.error(str(e))            
            success = False
        finally:
            #clean after myself
            os.unlink(ssl_conf)
            lock.release()
            return success

if __name__ == '__main__':
    c = Certificate('time.it.adp.com')

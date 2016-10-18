#! /usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import os
import re
import time
import sys
import readline
import urllib3
import httplib
import json
import argparse
import getpass
import requests
import mimetypes
import hashlib
import binascii
import datetime
import webbrowser
from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from distutils.version import LooseVersion
from multiprocessing.dummy import Pool as ThreadPool
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

reload(sys)
sys.setdefaultencoding('utf8')

urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings()

session = requests.Session()

# Python 2 + 3 support
try:
    input = raw_input
except NameError:
    pass

srv_host = "bizapi.hosted.exosite.io"
pool = ThreadPool(4)

SECRET_FILE = '.Solutionfile.secret'
CONFIG_FILE = 'Solutionfile.json'
VERSION = '0.23'
LATEST_FORMAT_VERSION = '0.3'
PREVIOUS_FORMAT_VERSION = '0.2'

CONFIG_FORMAT = {
    PREVIOUS_FORMAT_VERSION: ["file_dir", "custom_api", "modules", "event_handler", "custom_api_hook", "default_page"],
    LATEST_FORMAT_VERSION: ["assets", "routes", "modules", "services", "routes_hook", "default_page"]
}

DEFAULT_CORS = {"origin": ["http://localhost:*"]}

PUB_CONF_DESC = {
    LATEST_FORMAT_VERSION: {
        "routes": ["Custom api file: ", "sample_api.lua"],
        "assets": ["Static file directory: ", "public"],
        "default_page": ["Default page: ", "index.html"]
    },
    PREVIOUS_FORMAT_VERSION: {
        "custom_api": ["Custom api file: ", "sample_api.lua"],
        "file_dir": ["Static file directory: ", "public"],
        "default_page": ["Default page: ", "index.html"]
    }
}

def admin_domain(host):
    return host.lower().replace(".hosted.exosite.io", ".io/business").replace("bizapi", "www.exosite")

def file_only(path):
    return True if os.path.dirname(path) == '' else False

def tohex(str):
    return binascii.hexlify(str)

def sha1(fname):
    hasher = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(tohex(chunk))
    return hasher.hexdigest()

def line_input(prompt, prefill=''):
    readline.set_startup_hook(lambda: readline.insert_text(prefill))
    try:
        return input(prompt)
    finally:
        readline.set_startup_hook()

def gen_assets(file_dir, default_page):
    assets = []
    for root, dirs, files in os.walk(file_dir):
        for name in files:
            full_path = os.path.join(root, name)
            checksum = sha1(full_path)
            if name == default_page:
                target_path = '/'
            else:
                target_path = full_path[len(file_dir):]
            (mime_type, encoding) = mimetypes.guess_type(full_path)
            if mime_type is None:
                mime_type = 'application/binary'
            assets.append({
                'full_path': full_path,
                'checksum': checksum,
                'mime_type': mime_type,
                'name': name,
                'path': target_path,
            })
    return assets

def get_config(file):
    try:
        with open(file, 'r') as fh:
            content = fh.read()
            try:
                return json.loads(content)
            except Exception:
                print("Config file '{0}' is invalid json".format(file))
                sys.exit(0)
    except IOError:
        print("Config file '{0}' not exist".format(file))
        sys.exit(0)


# Prompt user to pick from a list of dict items,
# assuming the first column key is a unique ID
def pick_from_list(promptText, items, keys, headings):
    # assume first key is the one we need to fill in]
    id_key = keys[0]

    # display available products
    maxwidths = dict([(k, max([len(item[k]) for item in items] +
                              [len(h)]))
                      for (k, h) in zip(keys, headings)])
    print('\n' + ' | '.join([headings[i].ljust(maxwidths[k])
                      for (i, k) in enumerate(keys)]))
    for item in items:
        item['display_meta'] = ' | '.join([item[k] for k in keys[1:]])
        print(' | '.join([item[k].ljust(maxwidths[k]) for k in keys]))

    class ItemCompleter(Completer):
        def get_completions(self, document, complete_event):
            for item in items:
                for k in keys[:2]:
                    if item[k][:len(document.text)] == document.text:
                        yield Completion(
                            item[id_key],
                            start_position=-len(document.text),
                            display_meta=item['display_meta'])

    selected_item = None
    while selected_item is None:
        item_id = prompt(promptText, completer=ItemCompleter())
        matches = list(filter(lambda p: p[id_key] == item_id, items))
        if len(matches) == 1:
            selected_item = matches[0]
        else:
            print('Found {0} matches for "{1}". Try again.'.format(
                len(matches), item_id))
    return selected_item


def init_credential(host):
    private = {}
    print("Please log in with your Murano email and password, and " +
          "\nchoose an existing solution ID and product ID.")
    while True:
        email_input = line_input("Email: ")
        if re.match(r"[^@]+@[^@]+\.[^@]+", email_input):
            break
        print("Invalid email format.")
    private["email"] = email_input
    while True:
        password_input=getpass.getpass()
        if password_input:
            break
    private["password"] = password_input
    sys.stdout.write("Testing those credentials... ")
    token = get_token(host, private['email'], private['password'])
    if token is None:
        print(
            "Unable to log in with those credentials. Be sure to \npass \
            --host if you're working with a development server"
        )
        sys.exit(0)
    else:
        print("OK")

    # get user's business memberships
    user = User(host, token, private["email"])
    businesses = user.get_businesses()

    # get user's solutions in all businesses
    solutions = []
    for b in businesses:
        # filter out non-Murano solutions
        bizsolutions = [s for s in user.get_solutions(b['bizid'])
                        if s['type'] == 'dataApi']
        for p in bizsolutions:
            p.update({'bizname': b['name']})
        solutions = solutions + bizsolutions

    solution = pick_from_list('Solution ID: ',
                              solutions,
                              ('apiId', 'domain', 'bizname'),
                              ('Solution ID', 'Domain', 'Business'))
    private['solution_id'] = solution['apiId']

    # get user's products in the business of the selected solution
    products = user.get_products(solution['bizid'])
    for p in products:
        p.update({'bizname': solution['bizname']})

    product = pick_from_list('Product ID: ',
                             products,
                             ('modelId', 'label', 'bizname'),
                             ('Product ID', 'Label', 'Business'))
    private['product_id'] = product['modelId']

    try:
        with open(SECRET_FILE, "w") as fh:
            fh.write(json.dumps(private))
        os.chmod(SECRET_FILE, 0o600)
        print("Successfully created credential file '{0}'. ".format(SECRET_FILE) +
              "To deploy your solution, run 'exosite --deploy'.")
    except Exception as e:
        print("Unable to generate credential: {0}".format(str(e)))


def get_token(host, email, password):
    srv_url = host + '/token/'
    try:
        resp = session.post(
            srv_url,
            headers = {'Content-Type': 'application/json'},
            json = {"email": email, "password": password}
        )
        resp.raise_for_status()
        return resp.json()['token']
    except Exception as e:
        print("Unexpected exception: {0}".format(str(e)))
    return None

class Product:
    def __init__(self, host, token, product_id):
        self.token = token
        self.host = host
        self.product_id = product_id
        self.url_base = self.host + '/product/' + self.product_id
        self.session = session
        self.session.headers.update({
            "content-type": "application/json",
            "authorization": "token " + self.token
        })

    def sn_enable(self, sn):
        ret = self.session.post(self.url_base + "/device/" + sn)
        ret.raise_for_status()
        rid = ret.json()['rid']
        ret = self.aggregate_rpc('', calls = self.compose_calls('map', ['alias', rid, sn]))
        if ret[0]['status'] == 'ok':
            ret = self.aggregate_rpc('', calls = self.compose_calls('update', [{'alias': sn}, {'name': sn}]))
            if ret[0]['status'] == 'ok':
                return rid
            else:
                return ret[0]['status']
        else:
            return ret[0]['status']

    def model_list_sn(self):
        ret = self.session.get(self.url_base + "/proxy/provision/manage/model/" + self.product_id + "/")
        ret.raise_for_status()
        return ret.text

    def proxy_rpc(self, auth, calls):
        obj = {}
        if auth != None:
            obj['auth'] = auth
        obj['calls'] = calls
        ret = self.session.post(
            self.url_base + "/proxy/onep:v1/rpc/process",
            headers = {'Content-Type': 'application/json'},
            json = obj
        )
        ret.raise_for_status()
        return ret.json()

    def compose_calls(self, procedure, arguments, id = 1):
        return [{'id': id, 'procedure': procedure, 'arguments': arguments}]

    def aggregate_rpc(self, client_alias, calls):
        ret =  self.proxy_rpc(
            auth = None,
            calls = self.compose_calls('lookup', ['alias', client_alias])
        )
        if (ret[0]['status'] == 'ok'):
            return self.proxy_rpc(auth = {'client_id': ret[0]['result']}, calls = calls)
        else:
            return ret

    def read(self, identity, alias):
        ret = self.aggregate_rpc(
            client_alias = identity,
            calls = self.compose_calls('read', [{'alias': alias}, {'limit': 1}])
        )
        if ret[0]['status'] == 'ok':
            if len(ret[0]['result']) == 1:
                return "%s [%s]" % (ret[0]['result'][0][1], datetime.datetime.fromtimestamp(ret[0]['result'][0][0]).strftime('%Y-%m-%d %H:%M:%S'))
            else:
                return "Identity '%s' with alias '%s' has no value" % (identity, alias)
        else:
            return ret[0]['status']

    def write(self, identity, alias, value):
        ret = self.aggregate_rpc(
            client_alias = identity,
            calls = self.compose_calls('write', [{'alias': alias}, value])
        )
        if ret[0]['status'] == 'ok':
            return datetime.datetime.fromtimestamp(ret[0]['result']).strftime('%Y-%m-%d %H:%M:%S')
        else:
            return ret[0]['status']

    def tree(self):
        raw = self.model_list_sn()
        sns = {}
        for item in raw.split('\r\n'):
            if item:
                data = item.split(',')
                sns[data[1]] = data[0]
        calls = []
        id = 1
        rev = {}
        for rid in sns.keys():
            calls.extend(self.compose_calls('info', [rid, {"aliases": True, "basic": True, "description": True}], id))
            rev[id] = rid
            id += 1
        if len(calls) == 0:
            return "No device."
        ret = self.aggregate_rpc(
            client_alias = '',
            calls = calls
        )
        icalls = []
        irev = {}
        info = {}
        iid = 0
        for item in ret:
            client_rid = rev[item["id"]]
            client_name = item['result']['description']['name']
            client_sn = sns[client_rid]
            client_state = item['result']['basic']['status']
            info[client_sn] = {}
            info[client_sn]["aliases"] = []
            info[client_sn]["state"] = client_state
            info[client_sn]["name"] = client_name
            if item['result']['aliases'] == []:
                continue
            for dp_rid, aliases in item['result']['aliases'].iteritems():
                iid += 1
                icalls.extend(self.compose_calls('info', [dp_rid, {"description": True}], iid))
                irev[iid] = [client_sn, aliases[0]]
                iid += 1
                icalls.extend(self.compose_calls('read', [dp_rid, {'limit': 1}], iid))
                irev[iid] = [client_sn]
        if len(icalls) == 0:
            return "No resource."
        iret = self.aggregate_rpc(
            client_alias = '',
            calls = icalls
        )

        obj = {}
        for dat in iret:
            sn = irev[dat['id']][0]
            if 'description' in dat['result']: #info
                obj["name"] = irev[dat['id']][1]
                obj["format"] = dat['result']['description']['format']
            else:
                obj["value"] = dat['result'][0][1] if dat['result'] else None
                obj["timestamp"] = datetime.datetime.fromtimestamp(dat['result'][0][0]).strftime('%Y-%m-%d %H:%M:%S') if dat['result'] else None
                info[sn]['aliases'].append(obj)
                obj = {}
        txt = "Identity Name State\n"
        for sn in info:
            txt = txt + "- %s %s [%s]\n" % (sn, info[sn]["name"], info[sn]["state"])
            for i, item in enumerate(info[sn]["aliases"]):
                islast = i == len(info[sn]["aliases"]) - 1
                seg = '  └─' if islast else '  ├─'
                if item["value"] is not None:
                    txt = txt + seg + " %s (%s) value: %s, time: %s\n" % (item["name"], item["format"], item["value"], item["timestamp"])
                else:
                    txt = txt + seg + " %s (%s)\n" % (item["name"], item["format"])
        return txt

class User:
    def __init__(self, host, token, email):
        self.host = host
        self.token = token
        self.session = session
        self.email = email
        self.session.headers.update({
            "content-type": "application/json",
            "authorization": "token " + self.token
        })

    def get_businesses(self):
        ret = session.get(self.host + "/user/" + self.email + "/membership/")
        ret.raise_for_status()
        return ret.json()

    def get_products(self, bizid):
        ret = session.get(self.host + "/business/" + bizid + "/product/")
        ret.raise_for_status()
        return ret.json()

    def get_solutions(self, bizid):
        ret = session.get(self.host + "/business/" + bizid + "/solution/")
        ret.raise_for_status()
        return ret.json()

class Solution:

    def __init__(self, host, token, solution_id):
        self.token = token
        self.host = host
        self.solution_id = solution_id
        self.session = session
        self.session.headers.update({
            "content-type": "application/json",
            "authorization": "token " + self.token
        })


    def url(self, append = ''):
        return self.host + "/solution/" + self.solution_id + append
    def request(self, method, append = '', **kwargs):
        #print(self.url(append))
        r = self.session.request(method, self.url(append), **kwargs)

        if r.status_code >= 400:
            print(" Request:  {0} \n failed with status: {1} \n Request: \n {2} \n Response: \n {3}".format(self.url(append), r.status_code, kwargs, r.text))

        r.raise_for_status()
        if r.text == "":
            return r.status_code
        else:
            # print(json.dumps(r.json()))
            return r.json()
    def get(self, append = '', **kwargs):
        return self.request('get', append, **kwargs)
    def put(self, append = '', **kwargs):
        return self.request('put', append, **kwargs)
    def post(self, append = '', **kwargs):
        return self.request('post', append, **kwargs)
    def delete(self, append = '', **kwargs):
        return self.request('delete', append, **kwargs)


    def version(self):
        return self.get('/version')

    def list_endpoints(self):
        return self.get('/endpoint')

    def logs(self, stream=True):
        try:
            headers = {
                "content-type": "application/json",
                "Accept-Encoding": "None",
                "authorization": "token " + self.token
            }
            r = requests.get(
                self.url('/logs'),
                headers = headers,
                params = {'polling': "true" if stream else "false"},
                stream = stream)
            if stream:
                for line in r.iter_lines():
                    if line:
                        print(line)
            else:
                for item in r.json()['items']:
                    print(item)
        except httplib.IncompleteRead as e:
            print(e.partial)
        except KeyboardInterrupt:
            pass
        except Exception as e :
            print(e)
        return

    def create_endpoint(self, endpoint):
        resp = self.post('/endpoint', json=endpoint)
        print("  {0} {1} {2}".format(endpoint["method"], endpoint["path"], json.dumps(resp)))

    def delete_endpoint(self, id):
        sys.stdout.write('.')
        sys.stdout.flush()
        return self.delete('/endpoint/' + id)

    def update_cors(self, config):
        return self.put('/cors', json=config)

    def get_cors(self):
        return self.get('/cors')

    def update_custom_api(self, script_file):
        print('  Fetching endpoint list')
        existing_endpoints = {}
        for endpoint in self.list_endpoints():
            existing_endpoints[endpoint['method'] + endpoint['path']] = endpoint

        try:
            with open(script_file, 'r') as fh:
                content = fh.read()
        except IOError:
            print("Custom script file '{0}' not exist".format(script_file))
            sys.exit(0)
        new_endpoints = {}
        for snippet in content.split('--#ENDPOINT '):
            raw = snippet.strip()
            if len(raw) == 0:
                continue
            try:#skip invalid format
                signature, script = raw.split('\n', 1)
                method, path = signature.split(' ')
            except:
                continue
            path = path.strip()
            endpoint = {
                'method': method,
                'path': path,
                'script': script,
            }
            key = method.lower() + path.lower()
            if key in existing_endpoints and existing_endpoints[key]['script'] == script:
                del existing_endpoints[key]
            else:
                new_endpoints[key] = endpoint

        if len(existing_endpoints) > 0:
            sys.stdout.write('  Deleting old endpoints')
            pool.map(lambda k: self.delete_endpoint(existing_endpoints[k]['id']), existing_endpoints)
            print("")
        pool.map(lambda k: self.create_endpoint(new_endpoints[k]), new_endpoints)
        return list(new_endpoints.keys()) + list(existing_endpoints.keys())

    def list_files(self):
        return self.get('/file')

    def delete_file(self, path):
        sys.stdout.write('.\n  %s' % path)
        sys.stdout.flush()
        return self.delete('/file' + path)

    def upload_files(self, assets):
        existing_files = {}
        for asset in self.list_files():
            existing_files[asset['path']] = asset

        new_assets = {}
        for asset in assets:
            key = asset['path']
            if key in existing_files:
                if (existing_files[key]['checksum'] != asset['checksum'] or
                    existing_files[key]['mime_type'] != asset['mime_type']):
                    new_assets[key] = asset
                del existing_files[key]
            else:
                new_assets[key] = asset

        if len(existing_files) > 0:
            sys.stdout.write('  Deleting old assets')
            pool.map(lambda k: self.delete_file(existing_files[k]['path']), existing_files)
            print("")
        pool.map(lambda k: self.upload_file(new_assets[k]), new_assets)
        return list(new_assets.keys()) + list(existing_files.keys())

    def upload_file(self, asset):
        resp = self.put(
            "/fileupload" + asset['path'],
            files={"file": (asset['name'], open(asset['full_path'], 'rb'), asset['mime_type'])},
            headers={"content-type": None}
        )
        print("  {0} {1} {2}".format(asset['path'], asset['checksum'], json.dumps(resp)))

    def upload_productid(self, pid):
        item = self.get_product_serviceconfig()
        if item is not None:
            item["triggers"] = {"pid": [pid], "vendor": [pid]}
            return self.put(
                "/serviceconfig/" + item["id"],
                json = item
            )
        return "serviceconfig not found"

    def get_product_serviceconfig(self):
        resp = self.get("/serviceconfig/")
        items = resp["items"]
        for item in items:
            if item["service"] == "device":
                return self.get("/serviceconfig/" + item["id"])
        return None

    def update_service(self, type, name, content):
        try:
            return self.put(
              "/" + type + "/" + self.solution_id + "_" + name,
               json = content
            )
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                return self.post(
                  "/" + type + "/",
                  json = content
                )
            else:
                raise(err)

    def update_module(self, module, content):
        resp = self.update_service('library', module, {
            "name": module,
            "solution_id": self.solution_id,
            "script": content
        })
        print("  {0} {1}".format(module, json.dumps(resp)))

    def update_eventhandler(self, service, event, content):
        resp = self.update_service(
            'eventhandler', service + "_" + event, {
                "service": service,
                "event": event,
                "solution_id": self.solution_id,
                "script": content
            }
        )
        print("  {0} {1} {2}".format(service, event, json.dumps(resp)))

    def get_solution(self):
        return self.get()

class Watcher:
    def __init__(self, conf, napi, product_id, file_format):
        self.observer = Observer()
        self.conf = conf
        self.napi = napi
        self.product_id = product_id
        self.format = file_format

    def run(self):
        targets = {}
        file_dir = None
        for item in self.conf:
            if self.format.routes == item:
                path = self.conf[item]
                key = "./" +  path if file_only(path) else path
                targets[key] = [self.format.routes]
            if self.format.assets == item:
                targets[self.conf[item] + "/*"] = [self.format.assets]
                file_dir = self.conf[item]
            if self.format.modules == item:
                for name, path in self.conf[item].iteritems():
                    key = "./" + path if file_only(path) else path
                    targets[key] = [self.format.modules, name]
            if self.format.services == item:
                services = self.conf[item]
                for service in services:
                    for event in services[service]:
                        path = self.conf[item][service][event]
                        key = "./" + path if file_only(path) else path
                        targets[key] = [self.format.services, service, event]

        handler = UpdateHandler(self.napi, targets, self.product_id, self.conf, self.format)
        for dir in set(map(lambda x: os.path.dirname(x), targets.keys())):
            self.observer.schedule(handler, dir, recursive = False if dir == "." else True)
        self.observer.start()
        try:
            while True:
                time.sleep(10)
        except:
            print("Stop watching files.")
            self.observer.stop()
        self.observer.join()

class UpdateHandler(FileSystemEventHandler):
    def __init__(self, napi, targets, product_id, conf, format):
        self.napi = napi
        self.targets = targets
        self.product_id = product_id
        self.conf = conf
        self.format = format
        super(FileSystemEventHandler, self).__init__()

    def on_any_event(self, event):
        if event.event_type in ['modified', 'deleted', 'created']:
            #print "Received %s event - %s" % (event.event_type, event.src_path)
            if event.src_path in self.targets:
                info = self.targets[event.src_path]
                if info[0] == self.format.routes:
                    try:
                        self.napi.update_custom_api(event.src_path)
                    except Exception, e:
                        print(e.response)
                elif info[0] == self.format.services:
                    with open(event.src_path, 'r') as fh:
                        content = fh.read().replace("$PRODUCT_ID", self.product_id)
                        try:
                            self.napi.update_eventhandler(info[1], info[2], content)
                        except Exception, e:
                            print(e.response)
                elif info[0] ==  self.format.modules:
                    with open(event.src_path, 'r') as fh:
                        content = fh.read().replace("$PRODUCT_ID", self.product_id)
                        try:
                            self.napi.update_module(info[1], content)
                        except Exception, e:
                            print(e.response)
            elif os.path.dirname(event.src_path) == self.conf[self.format.assets]:
                assets = gen_assets(self.conf[self.format.assets], self.conf[self.format.default_page])
                self.napi.upload_files(assets)

class FileFormat():
    def __init__(self, spec):
        self.assets = spec[0]
        self.routes = spec[1]
        self.modules = spec[2]
        self.services = spec[3]
        self.routes_hook = spec[4]
        self.default_page = spec[5]

def validate_public_config(domain_name):
    def query_user(version, conf):
        changed = False
        conf['version'] = version
        conf_desc = PUB_CONF_DESC[version]
        for key in conf_desc:
            if key not in public:
                item = conf_desc[key]
                answer = line_input(item[0], item[1])
                try:
                    conf[key] = json.loads(answer)
                except:
                    conf[key] = answer
                changed = True
        return changed
    DEFAULT_CORS['origin'].append('https://' + domain_name)
    for v in PUB_CONF_DESC:
        PUB_CONF_DESC[v]['cors'] = ["CORS setup: ", json.dumps(DEFAULT_CORS)]
    public = {}
    if not os.path.isfile(CONFIG_FILE):
        query_user(LATEST_FORMAT_VERSION, public)
        fh = open(CONFIG_FILE, "w")
        fh.write(json.dumps(public))
        print("Configuration file '{0}' is created".format(CONFIG_FILE))
    else:
        public = get_config(CONFIG_FILE)
        if 'version' in public:
            version = public['version']
        else:
            version = PREVIOUS_FORMAT_VERSION
        if LooseVersion(version) > LooseVersion(LATEST_FORMAT_VERSION) or version not in CONFIG_FORMAT:
            print(
                "Solutionfile format version {0} is not supported by this ".
                format(version) +
                "version of the exosite murano tool. Please update using: \n" +
                "pip install exosite --upgrade"
            )
            exit(0)
        changed = query_user(version, public)
        if changed:
            fh = open(CONFIG_FILE, "w")
            fh.write(json.dumps(public))
    return public

def main():
    parser = argparse.ArgumentParser(
        description='Deploy Solution to Exosite Murano')

    parser.add_argument('--host', nargs='?', const=None, default=srv_host)
    parser.add_argument("-k", "--insecrue", dest="secured",
                        required=False, action='store_false',
                        help='Ignore SSL')
    parser.add_argument("-p", "--upload_productid", required=False,
                        action='store_true', help='Upload static file')
    parser.add_argument("-s", "--upload_static", required=False,
                        action='store_true', help='Upload static file')
    parser.add_argument("-a", "--upload_api", required=False,
                        action='store_true', help='Upload api')
    parser.add_argument("-e", "--upload_eventhandler", required=False,
                        action='store_true', help='Upload event handler')
    parser.add_argument("-m", "--upload_modules", required=False,
                        action='store_true', help='Upload modules')
    parser.add_argument("-c", "--update_cors", required=False,
                        action='store_true', help='Update cors configuration')

    parser.add_argument("--enable_identity", metavar=('<identity>'), nargs=1, help='Add new identity', required=False)

    parser.add_argument("--logs", metavar=('tail'), nargs="?", const='once', default=None, help='Script log information')

    parser.add_argument("--read", metavar=('<identity>', '<alias>'), nargs=2, help='Read data from resource', required=False)
    parser.add_argument("--write",metavar=('<identity>', '<alias>', '<value>'), nargs=3, help='Write data to resource', required=False)
    parser.add_argument("--tree", action='store_true', required=False, help = 'Listing resources')
    parser.add_argument("--watch", action='store_true', required=False, help = 'Watch for modified files and deploy automatically')
    parser.add_argument("--open", metavar=('product|solution'), nargs="?", const='domain', default=None, help = 'Open solution/product url in browser')
    parser.add_argument("--deploy", required=False, action='store_true',
                        help='Upload all solution configurations')
    parser.add_argument("--init", required=False, action='store_true',
                        help='Configure for credential parameters')
    parser.add_argument("-v", "--version", required=False,
                        action='store_true', help='Show Version number')
    parser.set_defaults(secured=True)
    args = parser.parse_args()

    if (args.host is None):
        print "--host option need to provide server name"
        sys.exit(0)

    host = "https://" + args.host.lower() + "/api:1"
    verify_ssl = args.secured

    if args.version:
        print("exosite cli version: " + VERSION)
        sys.exit(0)

    # init private credential
    if args.init:
        init_credential(host)
        sys.exit(0)

    if not os.path.isfile(SECRET_FILE):
        print(
            "No credential file found, please run with --init to " +
            "generate secret configuration."
        )
        sys.exit(0)

    args.upload_api = args.upload_api or args.deploy
    args.upload_static = args.upload_static or args.deploy
    args.upload_modules = args.upload_modules or args.deploy
    args.upload_eventhandler = args.upload_eventhandler or args.deploy
    args.upload_productid = args.upload_productid or args.deploy
    args.update_cors = args.update_cors or args.deploy
    if not (args.upload_api or args.upload_static or args.upload_modules or
            args.upload_eventhandler or args.upload_productid or args.update_cors or
            args.enable_identity or args.read or args.write or args.tree or
            args.watch or (args.open is not None) or (args.logs is not None)):
        print("One option of -a, -s, -e, -m, -p, --read, --write, --tree, --enable_identity, --watch, --open, --logs or --deploy must be set")
        sys.exit(0)

    private = get_config(SECRET_FILE)
    solution_id = private['solution_id']
    product_id = private['product_id']
    # get token
    token = get_token(host, private['email'], private['password'])
    if not token:
        print(
            "Username/Password is not valid for server '{0}', please ".
            format(host) +
            "update credential file or run with --init option "
        )
        exit(0)

    napi = Solution(host, token, solution_id)
    domain_name = napi.get_solution()["domain"]

    # get public config
    public = validate_public_config(domain_name)
    file_format = FileFormat(CONFIG_FORMAT[public["version"]])

    version_info = napi.version()

    if LooseVersion(version_info['min_cli_version']) > LooseVersion(VERSION):
        print(
            "This version of the exosite murano tool is outdated. Please update: \n" +
            "pip install exosite --upgrade"
        )
        sys.exit(0)

    prod = Product(host, token, product_id)
    if args.enable_identity:
        print("Enable new identity...")
        print("  {0} {1}".format(product_id, prod.sn_enable(args.enable_identity[0])))
        sys.exit(0)

    if args.read:
        print(prod.read(args.read[0], args.read[1]))
        sys.exit(0)

    if args.write:
        print(prod.write(args.write[0], args.write[1], args.write[2]))
        sys.exit(0)

    if args.tree:
        print(prod.tree())
        sys.exit(0)

    if args.logs != None:
        if args.logs == 'tail':
            logs = napi.logs(stream = True)
        elif args.logs == 'once':
            logs = napi.logs(stream = False)
        sys.exit(0)

    if args.upload_productid:
        print("Assigning product id...")
        print("  {0} {1}".format(product_id, napi.upload_productid(product_id)))

    if args.upload_eventhandler:
        print("Updating services...")
        if file_format.services in public:
            services = public[file_format.services]
            for service in services:
                for event in services[service]:
                    with open(services[service][event], 'r') as fh:
                        content = fh.read().replace("$PRODUCT_ID", product_id)
                    napi.update_eventhandler(service, event, content)
        else:
            print("no services found!")

    if args.upload_modules:
        print("Updating modules...")
        if file_format.modules in public:
            modules = public[file_format.modules]
            for modulename in modules:
                with open(modules[modulename], 'r') as fh:
                    content = fh.read().replace("$PRODUCT_ID", product_id)
                napi.update_module(modulename, content)
        else:
            print("no modules found!")
    # update custom api
    if args.upload_api:
        print("Updating routes...")
        updates = napi.update_custom_api(public[file_format.routes])
        if file_format.routes_hook in public:
            key = 'get/' + public[file_format.routes_hook]
            if key in updates:
                print("  Executing init call")
                init_url = "https://{0}/{1}".format(
                    domain_name,
                    public[file_format.routes_hook])
                print("    GET " + init_url + " " + str(session.get(init_url)))

    # upload static file
    if args.upload_static:
        print("Updating assets...")
        assets = gen_assets(public[file_format.assets], public[file_format.default_page])
        napi.upload_files(assets)
        # pool.map(lambda a: napi.upload_file(*a), assets)

    if args.update_cors and "cors" in public:
        print("Updating CORS configuration...")
        try:
            cors = json.loads(public["cors"])
        except:
            cors = public["cors"]
        print(napi.update_cors(cors))
        print(napi.get_cors())

    if args.open != None:
        if args.open == 'solution':
            webbrowser.open_new_tab("https://{0}/solutions/{1}".format(admin_domain(args.host), solution_id))
        elif args.open == 'product':
            webbrowser.open_new_tab("https://{0}/products/{1}".format(admin_domain(args.host), product_id))
        elif args.open == 'domain':
            webbrowser.open_new_tab("https://{0}".format(domain_name))
        else:
            print ("Invalid argument for --open option")
        sys.exit(0)

    if args.watch:
        print("Start watching files...")
        watcher = Watcher(public, napi, product_id, file_format)
        watcher.run()

    print(
        "\nSolution URL: https://{0}\n".format(domain_name)
    )

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print e.message

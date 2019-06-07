from datetime import datetime
import gevent
from gevent.monkey import  patch_all; patch_all()
from gevent.pool import Event
import json
import logging
import odoorpc
from odoorpc.error import RPCError
import os
import requests
import sys
from urllib2 import URLError
import uuid
from gevent.pywsgi import WSGIServer


logger = logging.getLogger('odoo_agent')


class Agent(object):
    version = 1
    odoo = None
    odoo_connected = Event()
    odoo_disconnected = Event()
    odoo_session = requests.Session()
    # Environment settings
    agent_uid = os.getenv('AGENT_UID') or str(uuid.getnode())
    agent_model = os.getenv('ODOO_AGENT_MODEL')
    debug = os.getenv('DEBUG')
    # Odoo settings
    odoo_host = os.getenv('ODOO_HOST', 'odoo')
    odoo_port = os.getenv('ODOO_PORT', '8069')
    odoo_protocol = 'jsonrpc+ssl' if os.getenv(
                                    'ODOO_SCHEME') == 'https' else 'jsonrpc'
    odoo_db = os.getenv('ODOO_DB', 'odoo')
    odoo_login = os.getenv('ODOO_LOGIN', 'agent')
    odoo_password = os.getenv('ODOO_PASSWORD', 'service')
    odoo_scheme = os.getenv('ODOO_SCHEME', 'http'),
    odoo_polling_port = os.getenv('ODOO_POLLING_PORT', '8072')
    odoo_reconnect_timeout = float(os.getenv(
                                            'ODOO_RECONNECT_TIMEOUT', '1'))
    # Poll timeout when when agents calls /longpolling/poll
    odoo_bus_timeout = float(os.getenv('ODOO_BUS_TIMEOUT', '55'))
    # Response timeout when Odoo communicates via bus with agent
    bus_call_timeout = float(os.getenv('ODOO_BUS_CALL_TIMEOUT', '5'))
    disable_odoo_bus_poll = os.getenv('DISABLE_ODOO_BUS_POLL')
    odoo_verify_cert = bool(int(os.getenv('ODOO_VERIFY_CERT', '0')))
    # HTTPS communication settings when bus is not enabled
    https_port = int(os.getenv('AGENT_PORT', '40000'))
    https_address = os.getenv('AGENT_ADDRESS', 'agent')
    https_timeout = os.getenv('AGENT_TIMEOUT', '5')
    https_verify_cert = bool(int(os.getenv('VERIFY_CERT', '0')))
    https_key_file = os.getenv('AGENT_KEY_FILE', 'agent.key')
    https_cert_file = os.getenv('AGENT_CERT_FILE', 'agent.crt')

    # Secure token known only to Odoo
    token = None
    # Builtin HTTPS server to accept messages
    wsgi_server = None

    def __init__(self, agent_model=None, message_target=None):
        self.message_target = message_target
        if agent_model:
            self.agent_model = agent_model
        if not self.agent_model:
            raise Exception('Odoo agent model not set!')
        if self.debug == '1':
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        logger.info('Odoo agent version {} init'.format(self.version))
        # Init event with disconnected state
        self.odoo_disconnected.set()
        # Init WEB server
        if self.disable_odoo_bus_poll == '1':
            try:
                self.wsgi_server = WSGIServer(
                                          ('', self.https_port),
                                          self.wsgi_application,
                                          keyfile=self.https_key_file,
                                          certfile=self.https_cert_file)
            except (IOError, OSError) as e:
                logger.error('HTTPS server init error: %s', e)
        # Hack for slef-signed certificates.
        if not self.odoo_verify_cert:
            # Monkey patch SSL for self signed certificates
            import ssl
            if hasattr(ssl, '_create_unverified_context'):
                ssl._create_default_https_context = ssl._create_unverified_context
            # Supress InsecureRequestWarning on odoo_bus_poll
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logging.getLogger("urllib3").setLevel(logging.ERROR)


    def spawn(self):
        hlist = []
        hlist.append(gevent.spawn(self.connect))
        hlist.append(gevent.spawn(self.odoo_bus_poll))
        if self.disable_odoo_bus_poll == '1':
            logger.info('Starting Agent WEB server at port %s', self.https_port)
            hlist.append(gevent.spawn(self.wsgi_server.serve_forever))
        return hlist


    def start(self):
        try:
            hlist = self.spawn()
            gevent.joinall(hlist)
        except (KeyboardInterrupt, SystemExit):
            self.stop()
            logger.info('Odoo Agent exit')
            sys.exit(0)


    def stop(self):
        if self.wsgi_server:
            logger.info('Stopping WSGI server')
            self.wsgi_server.stop()


    def connect(self):
        self.token = uuid.uuid4().hex
        while True:
            try:
                logger.info('Connecting to Odoo at %s://%s:%s',
                        self.odoo_protocol, self.odoo_host, self.odoo_port)
                odoo = odoorpc.ODOO(self.odoo_host, port=self.odoo_port,
                                    protocol=self.odoo_protocol)
                odoo.login(self.odoo_db, self.odoo_login, self.odoo_password)
                logger.info('Connected to Odoo as %s', self.odoo_login)
                self.odoo = odoo
                self.odoo_connected.set()
                self.odoo_disconnected.clear()
                if self.disable_odoo_bus_poll == '1':
                    self.set_https_options()
                else:
                    self.set_bus_options()
                # Send 1-st message that will be omitted
                self.odoo.env[self.agent_model].notify(
                                            self.agent_uid,
                                            json.dumps({'Message': 'ping'}))
                self.odoo_disconnected.wait()

            except RPCError as e:
                if 'res.users()' in str(e):
                    logger.error(
                            'Odoo login %s not found or bad password %s, '
                            'check in Odoo!',
                            self.odoo_login, self.odoo_password)
                else:
                    logger.exception(e)
                self.odoo_connected.clear()
                self.odoo_disconnected.set()
            except URLError as e:
                self.odoo_connected.clear()
                self.odoo_disconnected.set()
                logger.error(e)
            except Exception as e:
                self.odoo_connected.clear()
                self.odoo_disconnected.set()
                if 'Connection refused' in repr(e):
                    logger.error('Odoo refusing connection.')
                else:
                    logger.exception(e)

            gevent.sleep(self.odoo_reconnect_timeout)


    def set_bus_options(self):
        # Generate a bus channel token and send it to Odoo
        self.odoo.env[self.agent_model].set_bus_options(self.agent_uid, {
                                    'token': self.token,
                                    'bus_timeout': self.bus_call_timeout})


    def set_https_options(self):
        # Set Agent HTTP communication options
        options = {
            'token': self.token,
            'https_address': self.https_address,
            'https_port': self.https_port,
            'https_timeout': self.https_timeout,
        }
        self.odoo.env[
            self.agent_model].set_http_options(self.agent_uid, options)


    def select_db(self):
        if not self.odoo_connected.is_set() or self.odoo_disconnected.is_set():
            logger.debug('Selecting Odoo database (session refresh)')
            auth_url = '{}://{}:{}/web/session/authenticate'.format(
                    self.odoo_scheme, self.odoo_host, self.odoo_polling_port)
            data = {
                'jsonrpc': '2.0',
                'params': {
                    'context': {},
                    'db': self.odoo_db,
                    'login': self.odoo_login,
                    'password': self.odoo_password,
                },
            }
            headers = {
                'Content-type': 'application/json'
            }
            #req = Request('POST', url, data=json.dumps(data), headers=headers)
            rep = self.odoo_session.post(
                             auth_url,
                             verify=self.https_verify_cert,
                             data=json.dumps(data),
                             headers=headers)
            result = rep.json()
            if rep.status_code != 200 or result.get('error'):
                logger.error(u'Odoo authenticate error {}: {}'.format(
                                        rep.status_code,
                                        json.dumps(result['error'], indent=2)))
            else:
                logger.info('Odoo authenticated for long polling')


    def odoo_bus_poll(self):
        if self.disable_odoo_bus_poll == '1':
            logger.info('Odoo bus poll is disabled')
            return
        self.odoo_connected.wait()
        last = 0
        while True:
            try:
                bus_url = '{}://{}:{}/longpolling/poll'.format(
                    self.odoo_scheme, self.odoo_host, self.odoo_polling_port)
                logger.debug('Starting odoo bus polling at %s', bus_url)
                # Select DB first
                self.select_db()
                # Now let try to poll
                r = self.odoo_session.post(
                            bus_url,
                            timeout=self.odoo_bus_timeout,
                            verify=self.odoo_verify_cert,
                            headers={'Content-Type': 'application/json'},
                            json={
                                'params': {
                                    'last': last,
                                    'channels': ['asterisk_agent/{}'.format(
                                                        self.agent_uid)]
                                }})
                result = r.json().get('result')
                if not result:
                    error = r.json().get('error')
                    if error:
                        logger.error(json.dumps(error, indent=2))
                        gevent.sleep(self.odoo_reconnect_timeout)
                        continue
                if last == 0:
                    # Ommit queued data
                    for msg in result:
                        if type(msg['message']) != dict:
                            message = json.loads(msg['message'])
                        else:
                            message = msg['message']
                        logger.debug('Ommit bus message %s', message['Message'])
                        last = msg['id']
                    continue

                for msg in result:
                    last = msg['id']
                    if type(msg['message']) != dict:
                        message = json.loads(msg['message'])
                    else:
                        message = msg['message']
                    logger.debug('Handle bus message %s', message['Message'])
                    gevent.spawn(self.handle_message,
                                 msg['channel'], msg['message'])

            except Exception as e:
                no_wait = False
                if isinstance(e, requests.ConnectionError):
                    if 'Connection aborted' in str(e.message):
                        logger.warning('Connection aborted')
                    elif 'Connection refused' in str(e.message):
                        logger.warning('Connection refused')
                    else:
                        logger.warning(e.message)
                elif isinstance(e, requests.HTTPError):
                    logger.warning(r.reason)
                elif isinstance(e, requests.ReadTimeout):
                    no_wait = True
                    logger.warning('Bus poll timeout, re-polling')
                else:
                    logger.exception('Bus error:')
                if not no_wait:
                    gevent.sleep(self.odoo_reconnect_timeout)


    def wsgi_application(self, env, start_response):
        if env['PATH_INFO'] == '/' and env['REQUEST_METHOD'] == 'POST' \
                and env.get('CONTENT_TYPE') == 'application/json':
            try:
                data = env['wsgi.input'].read()
                message = json.loads(data)
                gevent.spawn(self.handle_message, 'https', message)
                status = '200 OK'
                headers = [('Content-Type', 'application/json')]
                start_response(status, headers)
                return json.dumps({'status': 'ok'})
            except Exception:
                logger.exception('Agent HTTP error')
                start_response('500 Server Error',
                               [('Content-Type', 'text/html')])
                return [b'<h1>Server error</h1>']
        # Default action
        logger.error('Bad request %s', env['PATH_INFO'])
        start_response('404 Not Found', [('Content-Type', 'text/html')])
        return [b'<h1>Not Found</h1>']


    def handle_message(self, channel, msg):
        if not type(msg) == dict:
            msg = json.loads(msg)
        # Check for bus token
        if self.token != msg.pop('token', None):
            logger.warning('Channel %s token mismatch, ignore message: %s',
                           channel, msg)
            return
        self.last_message_datetime = datetime.now()
        name = msg.pop('Message')
        logger.debug(u'Message {}'.format(name))
        if hasattr(self, 'on_message_{}'.format(name)):
            getattr(self, 'on_message_{}'.format(name))(channel, msg)
        elif hasattr(self.message_target, 'on_message_{}'.format(name)):
            getattr(self.message_target,
                    'on_message_{}'.format(name))(channel, msg)
        else:
            logger.error('Message handler not found for {}'.format(name))


    def on_message_ping(self, channel, msg):
        logger.debug(u'Ping received')


    def notify_user(self, uid, msg, title=None):
        self.odoo_connected.wait()
        if not uid:
            logger.debug(u'No uid, will not notify')
            return
        if title:
            msg['Response'] = title
        logger.debug(u'Notify user: {}'.format(json.dumps(msg, indent=2)))
        if msg.get('Success'):
            notify_type = 'notify_info_{}'.format(uid)
        else:
            notify_type = 'notify_warning_{}'.format(uid)
        self.odoo.env['asterisk_calls.util'].asterisk_send_bus(
                                     notify_type,
                                     {'message': msg.get('Message', ''),
                                      'title': msg.get('Response', '')})


if __name__ == '__main__':
    logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    a = Agent()
    a.start()

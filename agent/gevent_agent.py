# -*- coding: utf-8 -*-
import argparse
import gevent
from gevent.monkey import  patch_all; patch_all()
from gevent.pool import Event
from gevent.queue import Queue
from gevent.pywsgi import WSGIServer
import json
import logging
import odoorpc
from odoorpc.error import RPCError
import os
import random
import requests
import sys
from tinyrpc.dispatch import RPCDispatcher, public
from tinyrpc.transports.callback import CallbackServerTransport
from tinyrpc.server.gevent import RPCServerGreenlets
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from urllib2 import URLError
import uuid


logger = logging.getLogger('remote_agent')

rpc_protocol = JSONRPCProtocol()
rpc_dispatcher = RPCDispatcher()


class AgentCallbackServerTransport(CallbackServerTransport):
    # Patch tinyrpc
    def receive_message(self):
        return self.reader()

    def send_reply(self, context, reply):
        self.writer(context, reply)


class GeventAgent(object):
    version = '1.0-gevent'
    message_handlres = {}  # External message handlers are register here
    odoo = None
    odoo_connected = Event()
    odoo_disconnected = Event()
    odoo_session = requests.Session()
    # Environment settings
    agent_uid = os.getenv('AGENT_UID') or str(uuid.getnode())
    agent_channel = os.getenv('AGENT_CHANNEL', 'remote_agent')
    agent_model = os.getenv('ODOO_AGENT_MODEL', 'remote_agent.agent')

    debug = os.getenv('DEBUG')
    # Odoo settings
    odoo_host = os.getenv('ODOO_HOST', 'odoo')
    odoo_port = os.getenv('ODOO_PORT', '8069')
    odoo_protocol = 'jsonrpc+ssl' if os.getenv(
                                    'ODOO_SCHEME') == 'https' else 'jsonrpc'
    odoo_db = os.getenv('ODOO_DB', 'odoo')
    odoo_login = os.getenv('ODOO_LOGIN', 'agent')
    odoo_password = os.getenv('ODOO_PASSWORD', 'service')
    odoo_scheme = os.getenv('ODOO_SCHEME', 'http')
    odoo_polling_port = os.getenv('ODOO_POLLING_PORT', '8072')
    odoo_reconnect_timeout = float(os.getenv(
                                            'ODOO_RECONNECT_TIMEOUT', '1'))
    # Poll timeout when when agents calls /longpolling/poll
    odoo_bus_timeout = float(os.getenv('ODOO_BUS_TIMEOUT', '55'))
    # Response timeout when Odoo communicates via bus with agent
    bus_call_timeout = int(os.getenv('ODOO_BUS_CALL_TIMEOUT', '-1'))
    disable_odoo_bus_poll = bool(int(os.getenv('DISABLE_ODOO_BUS_POLL', '0')))
    bus_enabled = not disable_odoo_bus_poll
    bus_trace = bool(int(os.getenv('BUS_TRACE', '0')))
    https_enabled = disable_odoo_bus_poll
    odoo_verify_cert = bool(int(os.getenv('ODOO_VERIFY_CERT', '0')))
    # HTTPS communication settings when bus is not enabled
    https_port = int(os.getenv('AGENT_PORT', '40000'))
    https_address = os.getenv('AGENT_ADDRESS', 'agent')
    https_timeout = int(os.getenv('AGENT_TIMEOUT', '-1'))
    https_verify_cert = bool(int(os.getenv('VERIFY_CERT', '0')))
    https_key_file = os.getenv(
        'AGENT_KEY_FILE',
        os.path.join(os.path.dirname(os.path.realpath(__file__)), 'agent.key'))
    https_cert_file = os.getenv(
        'AGENT_CERT_FILE',
        os.path.join(os.path.dirname(os.path.realpath(__file__)), 'agent.crt'))
    # Secure token known only to Odoo
    token = None
    # Builtin HTTPS server to accept messages
    wsgi_server = None
    rpc_server = None
    rpc_requests = Queue()
    trace_rpc = bool(int(os.getenv('TRACE_RPC', '0')))

    def __init__(self, agent_model=None, agent_channel=None):
        if agent_model:
            self.agent_model = agent_model
        if agent_channel:
            self.agent_channel = agent_channel
        if not self.agent_model:
            raise Exception('Odoo agent model not set!')
        if self.debug == '1':
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        logger.info('Odoo agent UID {} version {} init'.format(
                                                self.agent_uid, self.version))
        # Init event with disconnected state
        self.odoo_disconnected.set()
        # Init WEB server
        if self.https_enabled:
            logger.debug('Loading HTTPS key from %s', self.https_key_file)
            logger.debug('Loading HTTPS cert from %s', self.https_cert_file)
            self.wsgi_server = WSGIServer(
                                      ('', self.https_port),
                                      self.wsgi_application,
                                      keyfile=self.https_key_file,
                                      certfile=self.https_cert_file)
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
            # Init RPC
        rpc_dispatcher.register_instance(self)
        self.rpc_server = RPCServerGreenlets(
                    AgentCallbackServerTransport(
                        self.receive_rpc_message, self.send_rpc_reply),
                    rpc_protocol,
                    rpc_dispatcher)
        if self.trace_rpc:
            self.rpc_server.trace = self.trace_rpc_message


    def spawn(self):
        hlist = []
        hlist.append(gevent.spawn(self.connect))
        hlist.append(gevent.spawn(self.odoo_bus_poll))
        hlist.append(gevent.spawn(self.rpc_server.serve_forever))
        gevent.spawn(self.on_start)
        if self.https_enabled:
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


    def on_start(self):
        # Parse args
        parser = argparse.ArgumentParser(description='Remote Agent')
        parser.add_argument('--notify_uid', type=int,
                            help='Odoo UID to notify on agent start')
        parser.add_argument('--alarm',
                            help='Alarm message to set on start')
        args = parser.parse_args()
        if args.notify_uid:
            self.odoo_connected.wait()
            self.notify_user(args.notify_uid, 'Agent has been started!')
        if args.alarm != None:
            if args.alarm:
                self.set_alarm(args.alarm)
            else:
                self.clear_alarm()


    def stop(self):
        if self.wsgi_server:
            logger.info('Stopping WSGI server')
            self.wsgi_server.stop()


    def register_message(self, message, method):
        if not self.message_handlres.get('message'):
            logger.debug('Registering message handler for %s', message)
            self.message_handlres[message] = method
        else:
            logger.warning('Overriding message handler for %s', message)
            self.message_handlres[message] = method


    def connect(self):
        self.token = uuid.uuid4().hex
        while True:
            try:
                logger.info(
                        'Connecting to Odoo at %s://%s:%s',
                        self.odoo_protocol, self.odoo_host, self.odoo_port)
                odoo = odoorpc.ODOO(self.odoo_host, port=self.odoo_port,
                                    protocol=self.odoo_protocol)
                odoo.login(self.odoo_db, self.odoo_login, self.odoo_password)
                logger.info('Connected to Odoo as %s', self.odoo_login)
                self.odoo = odoo
                self.update_settings()
                # Now let other methods wake up and do the work
                self.odoo_connected.set()
                self.odoo_disconnected.clear()
                self.odoo_disconnected.wait()
                # Create a new online state
                self.update_state(force_create=True, note='Agent started')
            except RPCError as e:
                if 'res.users()' in str(e):
                    logger.error(
                            'Odoo login %s not found or bad password %s, '
                            'check in Odoo!',
                            self.odoo_login, self.odoo_password)
                else:
                    logger.exception('RPC error:')
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


    def update_settings(self):
        # Set Agent HTTP communication options
        settings = {
            'token': self.token,
            'bus_enabled': self.bus_enabled,
            'https_enabled': self.https_enabled,
            'https_address': self.https_address,
            'https_port': self.https_port,
            'agent_version': self.version,
        }
        if self.bus_call_timeout != -1:
            settings.update({'bus_timeout': self.bus_call_timeout})
        if self.https_timeout != -1:
            settings.update({'https_timeout': self.https_timeout})
        self.odoo.env[
            self.agent_model].update_settings(self.agent_uid, settings)


    def update_state(self, force_create=False, note=False):
        self.odoo_connected.wait()
        self.odoo.env[
            self.agent_model].update_state(self.agent_uid, state='online',
                                           force_create=force_create,
                                           note=note)


    def set_alarm(self, message):
        logger.debug('Set alarm: %s', message)
        self.odoo_connected.wait()
        self.odoo.env[
            self.agent_model].set_alarm(self.agent_uid, message)


    def clear_alarm(self, message=None):
        logger.debug('Clear alarm: %s', message or '')
        self.odoo_connected.wait()
        self.odoo.env[
            self.agent_model].clear_alarm(self.agent_uid, message)


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
        if not self.bus_enabled:
            logger.info('Odoo bus poll is disabled')
            return
        self.odoo_connected.wait()
        # Send 1-st message that will be omitted
        self.odoo.env[self.agent_model].send_agent(
                                self.agent_uid,
                                json.dumps({
                                    'message': 'ping',
                                    'random_sleep': '0'}))
        last = 0
        while True:
            try:
                bus_url = '{}://{}:{}/longpolling/poll'.format(
                    self.odoo_scheme, self.odoo_host, self.odoo_polling_port)
                channel = '{}/{}'.format(self.agent_channel, self.agent_uid)
                logger.debug('Polling %s at %s',
                             channel, bus_url)
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
                                    'channels': [channel]}})
                if self.bus_trace:
                    logger.debug('Bus trace: %s', r.text)
                try:
                    r.json()
                except ValueError:
                    logger.error('JSON parse bus reply error: %s', r.text)
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
                        if not message.get('message'):
                            logger.error('No Message attribute in message: %s',
                                         message)
                            continue
                        logger.debug('Ommit bus message %s', message['message'])
                        last = msg['id']
                    continue

                for msg in result:
                    last = msg['id']
                    if type(msg['message']) != dict:
                        message = json.loads(msg['message'])
                    else:
                        message = msg['message']
                    if not message.get('message'):
                        logger.error('No Message attribute in message: %s',
                                     message)
                        continue
                    logger.debug('Handle bus message %s', message['message'])
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
        name = msg.pop('message')
        logger.debug(u'Message {}'.format(name))
        if hasattr(self, 'on_message_{}'.format(name)):
            getattr(self, 'on_message_{}'.format(name))(channel, msg)
        # Get message handler from external classes
        elif self.message_handlres.get(name):
            logger.debug('Found message handler for %s', name)
            self.message_handlres[name](channel, msg)
        else:
            logger.error('Message handler not found for {}'.format(name))


    def on_message_rpc(self, channel, msg):
        logger.debug('RPC message received: %s', msg['data'])
        self.rpc_requests.put((msg.get('reply_channel'), msg['data']))


    def on_message_update_state(self, channel, msg):
        random_sleep = int(msg.get('random_sleep', '0'))
        sleep_time = random_sleep * random.random()
        logger.debug('State update after %0.2f sec', sleep_time)
        gevent.sleep(sleep_time)
        self.update_state(note='State update')
        logger.info('State updated')


    def on_message_restart(self, channel, msg):
        logger.info('Restarting')
        if msg.get('reply_channel'):
            self.odoo.env[self.agent_model].bus_sendone(msg['reply_channel'], {
                                                   'status': 'restarting'})
        self.stop()
        args = sys.argv[:]
        if msg.get('notify_uid'):
            logger.debug('Will notify uid %s after restart', msg['notify_uid'])
            args.append('--notify_uid={}'.format(msg['notify_uid']))
        os.execv(sys.executable, ['python2.7'] + args)


    def receive_rpc_message(self):
        # Get next message from the requests queue
        logger.debug('Waiting for next RPC message...')
        reply_channel, r = self.rpc_requests.get()
        logger.debug('RPC queue received: %s', r)
        return reply_channel, bytes(r)


    def send_rpc_reply(self, reply_channel, reply):
        self.odoo_connected.wait()
        logger.debug('RPC reply to %s: %s', reply_channel, reply)
        self.odoo.env[
            self.agent_model].bus_sendone(reply_channel, {'rpc_result': reply})


    def trace_rpc_message(self, direction, context, message):
        logger.debug('RPC %s, %s, %s', direction, context, message)


    @public
    def ping(self):
        logger.info('RPC Ping')
        return True


    def notify_user(self, uid, message, title='Agent', warning=False,
                    sticky=False):
        self.odoo_connected.wait()
        if not uid:
            logger.debug(u'No uid, will not notify')
            return
        logger.debug('Notify user %s: %s', uid, message)
        if not warning:
            notify_type = 'notify_info_{}'.format(uid)
        else:
            notify_type = 'notify_warning_{}'.format(uid)
        self.odoo.env[self.agent_model].bus_sendone(
                                     notify_type,
                                     {'message': message,
                                      'title': title,
                                      'sticky': sticky})


if __name__ == '__main__':
    logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - '
                       '%(name)s.%(funcName)s:%(lineno)d - %(message)s')
    a = GeventAgent()
    a.start()

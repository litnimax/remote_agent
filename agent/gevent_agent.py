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
    version = '1.2-gevent'
    message_handlers = {}  # External message handlers are register here
    odoo = None
    odoo_connected = Event()
    odoo_disconnected = Event()
    odoo_session = requests.Session()
    odoo_session_db_selected = False
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
    odoo_reconnect_seconds = float(os.getenv(
                                            'ODOO_RECONNECT_SECONDS', '1'))
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
    # Agent can overwite its settings on start
    update_settings_on_start = bool(int(os.getenv(
                                            'UPDATE_SETTINGS_ON_START', '0')))
    # Secure token known only to Odoo
    token = None
    # Builtin HTTPS server to accept messages
    wsgi_server = None
    https_rpc_server = None
    https_rpc_requests = Queue()
    https_rpc_replies = Queue()
    bus_rpc_server = None
    bus_rpc_requests = Queue()
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
        self.bus_rpc_server = RPCServerGreenlets(
                    AgentCallbackServerTransport(
                        self.receive_bus_rpc_message, self.send_bus_rpc_reply),
                    rpc_protocol,
                    rpc_dispatcher)
        self.https_rpc_server = RPCServerGreenlets(
                    AgentCallbackServerTransport(
                        self.receive_https_rpc_message,
                        self.send_https_rpc_reply),
                    rpc_protocol,
                    rpc_dispatcher)
        if self.trace_rpc:
            self.bus_rpc_server.trace = self.trace_rpc_message
            self.https_rpc_server.trace = self.trace_rpc_message


    def spawn(self):
        hlist = []
        hlist.append(gevent.spawn(self.connect))
        hlist.append(gevent.spawn(self.odoo_bus_poll))
        hlist.append(gevent.spawn(self.bus_rpc_server.serve_forever))
        hlist.append(gevent.spawn(self.https_rpc_server.serve_forever))
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
        if args.alarm is not None:
            if args.alarm:
                self.set_alarm(args.alarm)
            else:
                self.clear_alarm()


    def stop(self):
        if self.wsgi_server:
            logger.info('Stopping WSGI server')
            self.wsgi_server.stop()


    def register_message(self, message, method):
        if not self.message_handlers.get('message'):
            logger.debug('Registering message handler for %s', message)
            self.message_handlers[message] = method
        else:
            logger.warning('Overriding message handler for %s', message)
            self.message_handlers[message] = method


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

            gevent.sleep(self.odoo_reconnect_seconds)


    def update_settings(self):
        # Set Agent HTTP communication options
        settings = {
            'token': self.token,
            'agent_version': self.version,
        }
        if self.update_settings_on_start:
            if self.bus_call_timeout != -1:
                settings.update({'bus_timeout': self.bus_call_timeout})
            if self.https_timeout != -1:
                settings.update({'https_timeout': self.https_timeout})
            settings.update({
                'bus_enabled': self.bus_enabled,
                'https_enabled': self.https_enabled,
                'https_address': self.https_address,
                'https_port': self.https_port,
            })
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
        if self.odoo_session_db_selected:
            return
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
        self.odoo_session_db_selected = True


    def odoo_bus_poll(self):
        if not self.bus_enabled:
            logger.info('Odoo bus poll is disabled')
            return
        self.odoo_connected.wait()
        # Send 1-st message that will be omitted
        try:
            self.odoo.env[self.agent_model].send_agent(
                                self.agent_uid,
                                json.dumps({
                                    'message': 'ping',
                                    'random_sleep': '0'}))
        except Exception as e:
            logger.exception('First ping error:')
        last = 0
        while True:
            try:
                bus_url = '{}://{}:{}/longpolling/poll'.format(
                    self.odoo_scheme, self.odoo_host, self.odoo_polling_port)
                channel = '{}/{}'.format(self.agent_channel, self.agent_uid)
                # Select DB first
                self.select_db()
                # Now let try to poll
                logger.debug('Polling %s at %s',
                             channel, bus_url)
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
                        gevent.sleep(self.odoo_reconnect_seconds)
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
                    gevent.spawn(self.handle_bus_message,
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
                    gevent.sleep(self.odoo_reconnect_seconds)


    def wsgi_application(self, env, start_response):
        if env['PATH_INFO'] == '/' and env['REQUEST_METHOD'] == 'POST' \
                and env.get('CONTENT_TYPE') == 'application/json':
            try:
                data = env['wsgi.input'].read()
                request_id = env.get('HTTP_X_REQUEST_ID')
                if not request_id:
                    raise Exception('No HTTP_X_REQUEST_ID sent!')
                token = env.get('HTTP_X_TOKEN')
                if not token:
                    raise Exception('No HTTP_X_TOKEN passed!')
                elif token != self.token:
                    raise Exception('Tokens mismatch!')
                message = json.loads(data)
                status = '200 OK'
                headers = [('Content-Type', 'application/json')]
                result = self.handle_https_message(message, request_id)
                start_response(status, headers)
                if result:
                    if type(result) == tuple and len(result) == 2:
                        return json.dumps(result[1])
                    elif type(result) == dict:
                        return json.dumps(result)
                return str(result)
            except Exception as e:
                logger.error('Agent HTTP error: %s', e)
                start_response('500 Server Error',
                               [('Content-Type', 'text/html')])
                return [b'<h1>Server error</h1>']
        # Default action
        logger.error('Bad request %s', env['PATH_INFO'])
        start_response('404 Not Found', [('Content-Type', 'text/html')])
        return [b'<h1>Not Found</h1>']


    def handle_message(self, channel, msg):
        name = msg.pop('message')
        logger.debug(u'Message {}'.format(name))
        if hasattr(self, 'on_message_{}'.format(name)):
            result = getattr(self, 'on_message_{}'.format(name))(channel, msg)
        # Get message handler from external classes
        elif self.message_handlers.get(name):
            logger.debug('Found message handler for %s', name)
            result = self.message_handlers[name](channel, msg)
        else:
            logger.error('Message handler not found for {}'.format(name))
            result = {'error': 'Message handler not found for {}'.format(name)}
        return result


    def handle_bus_message(self, channel, msg):
        if not type(msg) == dict:
            msg = json.loads(msg)
        if self.token != msg.pop('token', None):
            logger.warning(
                        'Channel %s token mismatch, ignore message: %s', msg)
            return
        # Check for RPC message
        if msg['message'] == 'rpc':
            logger.debug('RPC message received: %s', msg['data'])
            self.bus_rpc_requests.put((msg.get('reply_channel'), msg['data']))
        else:
            result = self.handle_message(channel, msg)
            if result and msg.get('reply_channel'):
                self.odoo.env[self.agent_model].bus_sendone(
                                            msg['reply_channel'], result)


    def handle_https_message(self, msg, request_id):
        # Sometimes HTTP server has more then one request at a time.
        # In this case we should be carefull giving back the result.
        def get_my_result():
            result = self.https_rpc_replies.get()
            if result[0] != request_id:
                self.https_rpc_replies.put_nowait(result)
                gevent.sleep(0.1)
                return get_my_result()
            else:
                return result
        if msg['message'] == 'rpc':
            logger.debug('HTTPS RPC message received: %s', msg['data'])
            rpc_data = json.dumps(msg['data']) if type(msg['data']) == dict \
                                                            else msg['data']
            self.https_rpc_requests.put((request_id, rpc_data))
            return get_my_result()
        else:
            return self.handle_message('https', msg)


    def on_message_update_state(self, channel, msg):
        random_sleep = int(msg.get('random_sleep', '0'))
        sleep_time = random_sleep * random.random()
        logger.debug('State update after %0.2f sec', sleep_time)
        gevent.sleep(sleep_time)
        self.update_state(note='State update')
        logger.info('State updated')


    def on_message_restart(self, channel, msg):
        def restart():
            self.stop()
            args = sys.argv[:]
            if msg.get('notify_uid'):
                logger.debug('Will notify uid %s after restart', msg['notify_uid'])
                args.append('--notify_uid={}'.format(msg['notify_uid']))
            os.execv(sys.executable, ['python2.7'] + args)

        logger.info('Restarting')
        gevent.spawn_later(1, restart)
        return {'status': 'restarting'}


    def receive_bus_rpc_message(self):
        # Get next message from the requests queue
        logger.debug('Waiting for next Bus RPC message...')
        reply_channel, r = self.bus_rpc_requests.get()
        logger.debug('Bus RPC queue received: %s', r)
        return reply_channel, bytes(r)


    def send_bus_rpc_reply(self, reply_channel, reply):
        self.odoo_connected.wait()
        logger.debug('Bus RPC reply to %s: %s', reply_channel, reply)
        self.odoo.env[
            self.agent_model].bus_sendone(reply_channel, {'rpc_result': reply})


    def receive_https_rpc_message(self):
        # Get next message from the requests queue
        logger.debug('Waiting for next HTTPS RPC message...')
        request_id, r = self.https_rpc_requests.get()
        logger.debug('HTTPS RPC queue received: %s', r)
        return request_id, bytes(r)


    def send_https_rpc_reply(self, request_id, reply):
        logger.debug('RPC reply %s', reply)
        self.https_rpc_replies.put((request_id, {'rpc_result': reply}))


    def trace_rpc_message(self, direction, context, message):
        logger.debug('RPC %s, %s, %s', direction, context, message)


    @public
    def ping(self):
        logger.info('RPC Ping')
        return True


    def notify_user(self, uid, message, title='Agent',
                    warning=False, sticky=False):
        self.odoo_connected.wait()
        if not uid:
            logger.debug(u'No uid, will not notify')
            return
        logger.debug('Notify user %s: %s', uid, message)
        self.odoo.env[self.agent_model].bus_sendone(
                                 'remote_agent_notification_{}'.format(uid), {
                                    'message': message,
                                    'warning': warning,
                                    'sticky': sticky,
                                    'title': title})


if __name__ == '__main__':
    logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - '
                       '%(name)s.%(funcName)s:%(lineno)d - %(message)s')
    a = GeventAgent()
    a.start()

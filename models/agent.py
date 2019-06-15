from datetime import datetime, timedelta
import json
try:
    import humanize
    HUMANIZE = True
except ImportError:
    HUMANIZE = False
import logging
import os
import random
import requests
import string
import time
import urllib3
import uuid

from odoo import models, fields, api, registry, _
from odoo.exceptions import ValidationError
from odoo.addons.bus.models.bus import dispatch

from tinyrpc import RPCClient
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports import ClientTransport

from .agent_state import STATES

# Default installation has self signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


DEFAULT_PASSWORD_LENGTH = os.getenv('AGENT_DEFAULT_PASSWORD_LENGTH', '10')

json_protocol = JSONRPCProtocol()


class AgentOffline(Exception):
    pass


class BusTransport(ClientTransport):
    def __init__(self, agent, timeout=None, fail_silent=False):
        self.timeout = timeout
        self.fail_silent = fail_silent
        self.agent = agent

    def send_message(self, message, expect_reply=True):
        data = {'message': 'rpc', 'data': message}
        if expect_reply:
            result = self.agent.call(data, timeout=self.timeout)
            if result:
                return result['rpc_result'].encode()
            if self.fail_silent:
                res = {'jsonrpc': '2.0',
                       'id': json.loads(message.decode())['id'],
                       'result': False}
                return json.dumps(res)
            raise AgentOffline()
        else:
            result = self.agent.send(data, timeout=self.timeout)


class AgentProxy(object):
    def __init__(self, agent):
        self.agent = agent

    def get_proxy(self, timeout=None, fail_silent=False, one_way=False):
        rpc_client = RPCClient(
                        json_protocol,
                        BusTransport(self.agent, timeout=timeout,
                                     fail_silent=fail_silent))
        server_proxy = rpc_client.get_proxy(one_way=one_way)
        return server_proxy


class Agent(models.Model):
    _name = 'remote_agent.agent'
    _description = 'Remote Agent'
    _rec_name = 'agent_uid'

    agent_uid = fields.Char(string=_('Agent UID'), required=True)
    agent_version = fields.Char(readonly=True, string=_('Version'))
    note = fields.Text()
    alarm = fields.Text(readonly=True)
    token = fields.Char(groups="base.no_group")
    bus_timeout = fields.Integer(default=10)
    bus_enabled = fields.Boolean(default=True)
    https_enabled = fields.Boolean(string=_('HTTPS Enabled'))
    https_address = fields.Char(string=_('HTTPS Address'))
    https_port = fields.Char(string=_('HTTPS Port'))
    https_timeout = fields.Integer(string=_('HTTPS Timeout'), default=10)
    user = fields.Many2one('res.users', ondelete='restrict', readonly=True)
    login = fields.Char(related='user.login', string=_('Login'),
                        required=True, readonly=False)
    password = fields.Char(related='user.password', string=_('Password'),
                           readonly=False,
                           default=lambda self: self.generate_password())
    states = fields.One2many(comodel_name='remote_agent.agent_state',
                             inverse_name='agent')
    last_state = fields.Datetime(compute='_get_last_state',
                                 string=_('State Changed'))
    last_state_name = fields.Selection(STATES, compute='_get_last_state_name',
                                       store=True, string=_('State'))
    last_state_human = fields.Char(compute='_get_last_state_human',
                                   string=_('State Changed'))
    state_count = fields.Integer(compute='_get_state_count')
    state_icon = fields.Char(compute='_get_last_state_icon')
    last_online = fields.Datetime(compute='_get_last_online')
    last_online_human = fields.Char(compute='_get_last_online_human',
                                    string=_('Last Online'))

    _sql_constraints = [
        ('uid_uniq', 'unique(agent_uid)',
            _('This agent uid already exists!')),
    ]


    @api.model
    def create(self, vals):
        agent_group = self.env['ir.model.data'].get_object('remote_agent',
                                                           'group_agent_agent')
        user = self.env['res.users'].sudo().search(
                                        [('login', '=', vals.get('login'))])
        if user:
            # Check that user has Agent group
            if not user.has_group('remote_agent.group_agent_agent'):
                agent_group = self.env['ir.model.data'].sudo().get_object(
                                            'remote_agent.group_agent_agent')
                agent_group.write([4, user.id])
        else:
            user = self.env['res.users'].sudo().create({
                'name': vals.get('agent_uid'),
                'login': vals.get('login'),
                'groups_id': [(6, 0, [agent_group.id])],
                'password': vals.get('password'),
            })
        vals.update({'user': user.id})
        agent = super(Agent, self).create(vals)
        return agent


    @api.multi
    def unlink(self):
        for rec in self:
            user = rec.sudo().user
            partner = user.partner_id
            super(Agent, self).unlink()
            if user:
                user.unlink()
            if partner:
                partner.unlink()
        return True


    @api.multi
    def write(self, vals):
        res = super(Agent, self.sudo()).write(vals)
        try:
            self.on_write(vals)
        except:
            logger.exception('Agent on_write error:')
        return res


    @api.multi
    def on_write(self, vals):
        # Override this to add your custom code e.g. notify agents on update
        pass


    def generate_password(length=DEFAULT_PASSWORD_LENGTH):
        try:
            length = int(length)
        except ValueError:
            logger.warning('Bad DEFAULT_PASSWORD_LENGTH: %s',
                           DEFAULT_PASSWORD_LENGTH)
            length = 10
        chars = string.ascii_letters + string.digits
        password = ''
        while True:
            password = ''.join(map(lambda x: random.choice(chars), range(length)))
            if filter(lambda c: c.isdigit(), password) and \
                    filter(lambda c: c.isalpha(), password):
                break
        return password


    @api.multi
    def send(self, message):
        self.ensure_one()
        return self.send_agent(self.agent_uid, message)


    @api.model
    def send_agent(self, agent_uid, message):
        # Unpack if required
        if type(message) != dict:
            message = json.loads(message)
        agent = self._get_agent_by_uid(agent_uid)
        if agent.https_enabled:
            # Use Agent HTTPS interface to communicate
            res = None
            try:
                message['token'] = agent.sudo().token
                res = requests.post(
                            'https://{}:{}'.format(agent.https_address,
                                                   agent.https_port),
                            json=message,
                            timeout=agent.https_timeout or 5,
                            verify=False)
                # Test for reply
                res.json()
            except Exception as e:
                logger.exception('Agent HTTPS connect error:')
                raise ValidationError('Agent HTTPS {}: {}'.format(
                                                    res and res.text, e))
        else:
            # Use Odoo bus for communication
            message['token'] = agent.sudo().token
            self.env['bus.bus'].sendone('remote_agent/{}'.format(
                                            agent.agent_uid), message)
        return True


    @api.multi
    def call(self, message, timeout=None, silent=False):
        self.ensure_one()
        return self.call_agent(self.agent_uid, message, timeout, silent)


    @api.model
    def call_agent(self, agent_uid, message, timeout=None, silent=False):
        agent = self._get_agent_by_uid(agent_uid)
        if not timeout:
            timeout = agent.bus_timeout
        channel = 'remote_agent/{}'.format(self.agent_uid)
        reply_channel = '{}/{}'.format(channel, uuid.uuid4().hex)
        message.update({'reply_channel': reply_channel,
                        'timestamp': time.time(),
                        'token': agent.sudo().token})
        # Commit sending message in separate transaction so that we could get an reply.
        with api.Environment.manage():
            with registry(self.env.cr.dbname).cursor() as new_cr:
                env = api.Environment(new_cr, self.env.uid, self.env.context)
                env['bus.bus'].sendone(channel, message)
                new_cr.commit()
        # Poll is done is separate transaction in bus.bus so we don't do it.
        if dispatch:
            # Gevent instance
            agent_reply = dispatch.poll(self.env.cr.dbname,
                                        [reply_channel],
                                        last=0, timeout=timeout)
        else:
            # Cron instance
            started = datetime.now()
            to_end = started + timedelta(seconds=timeout)
            agent_reply = None
            while datetime.now() < to_end:
                with api.Environment.manage():
                    with registry(self.env.cr.dbname).cursor() as new_cr:
                        env = api.Environment(new_cr, self.env.uid,
                                              self.env.context)
                        rec = env['bus.bus'].sudo().search(
                            [('create_date', '>=', started),
                             ('channel', '=', '"{}"'.format(reply_channel))])
                        if not rec:
                            time.sleep(0.25)
                        else:
                            logger.debug('Got reply within {} seconds'.format(
                                (datetime.now() - started).total_seconds()))
                            agent_reply = [{'message':
                                            json.loads(rec[0].message)}]
                            break
        if agent_reply:
            # Update agent state
            self.sudo().update_state(
                                self.agent_uid, state='online', safe=True,
                                note='{} reply'.format(message['message']))
            # Convert result message to dict
            reply_message = agent_reply[0]['message']
            if type(reply_message) != dict:
                json.loads(reply_message)
            return reply_message
        # No reply recieved
        else:
            self.sudo().update_state(
                            self.agent_uid, state='offline', safe=True,
                            note='{} not replied'.format(message['message']))
            return {}


    @api.multi
    def execute(self, method, *args, **kwargs):
        self.ensure_one()
        agent = AgentProxy(self).get_proxy(
                                fail_silent=kwargs.pop('fail_silent', None),
                                timeout=kwargs.pop('timeout', None))
        return getattr(agent, method)(*args, **kwargs)


    @api.multi
    def notify(self, method, *args, **kwargs):
        self.ensure_one()
        agent = AgentProxy(self).get_proxy(
                                one_way=True,
                                fail_silent=kwargs.pop('fail_silent', None),
                                timeout=kwargs.pop('timeout', None))
        getattr(agent, method)(*args, **kwargs)




    @api.multi
    def restart_agent(self):
        self.ensure_one()
        self.call({'message': 'restart',
                   'notify_uid': self.env.user.id})


    @api.multi
    def ping_button(self):
        self.ensure_one()
        res = self.execute('ping', fail_silent=True)
        if not res:
            self.env['bus.bus'].sendone(
                                'notify_warning_{}'.format(self.env.uid),
                                {'title': 'Agent',
                                 'message': 'Agent is offline!'})


    @api.model
    def update_state_all(self, random_sleep=10):
        # We use random sleep to distribute state update over this period.
        for agent in self.search([]):
            self.env['bus.bus'].sendone(
                        'remote_agent/{}'.format(agent.agent_uid), {
                                        'message': 'update_state',
                                        'token': agent.token,
                                        'random_sleep': random_sleep})

    @api.multi
    def _get_state_count(self):
        for rec in self:
            rec.state_count = len(rec.states)


    @api.multi
    @api.depends('states')
    def _get_last_state_name(self):
        for rec in self:
            last_state = self.env['remote_agent.agent_state'].search([
                ('agent', '=', rec.id)], limit=1, order='id desc')
            rec.last_state_name = last_state[0].state if last_state else 'offline'


    @api.multi
    def _get_last_state(self):
        for rec in self:
            last_state = self.env['remote_agent.agent_state'].search([
                ('agent', '=', rec.id)], limit=1, order='id desc')
            rec.last_state = last_state[0].create_date if last_state else False


    @api.multi
    def _get_last_state_human(self):
        if HUMANIZE:
            to_translate = self.env.context.get('lang', 'en_US')
            if to_translate != 'en_US':
                humanize.i18n.activate(to_translate)
        for rec in self:
            last_state = self.env['remote_agent.agent_state'].search([
                ('agent', '=', rec.id)], limit=1, order='id desc')
            if last_state:
                if HUMANIZE:
                    rec.last_state_human = humanize.naturaltime(
                        fields.Datetime.from_string(last_state[0].create_date))
                else:
                    rec.last_state_human = last_state[0].create_date


    @api.multi
    def _get_last_state_icon(self):
        for rec in self:
            if rec.last_state_name == 'online':
                rec.state_icon = '<span class="fa fa-chain"/>'
            else:
                rec.state_icon = '<span class="fa fa-chain-broken"/>'


    @api.multi
    def _get_last_online(self):
        for rec in self:
            last_state = self.env['remote_agent.agent_state'].search([
                ('agent', '=', rec.id), ('state', '=', 'online')],
                limit=1, order='id desc')
            rec.last_online = last_state[0].create_date if \
                last_state else False


    @api.multi
    def _get_last_online_human(self):
        if HUMANIZE:
            to_translate = self.env.context.get('lang', 'en_US')
            if to_translate != 'en_US':
                humanize.i18n.activate(to_translate)
        for rec in self:
            if HUMANIZE:
                rec.last_online_human = humanize.naturaltime(
                    fields.Datetime.from_string(
                                rec.last_online)) if rec.last_online else ''
            else:
                rec.last_online_human = rec.last_online

    @api.multi
    def clear_alarm_button(self):
        self.ensure_one()
        self.alarm = False

    @api.multi
    def refresh_view_button(self):
        return True

    ######################### RPC Calls from Agent ############################

    def _get_agent_by_uid(self, agent_uid, raise_excepion=True):
        agent = self.search([('agent_uid', '=', agent_uid)])
        if not agent:
            if raise_excepion:
                raise ValidationError(
                                'Agent not found by UID {}'.format(agent_uid))
            else:
                return
        # Agent found, return it.
        return agent[0]


    @api.model
    def bus_sendone(self, channel, message):
        # Override sendone as original method does not return value for RPC
        self.env['bus.bus'].sendone(channel, message)
        return True


    @api.model
    def update_settings(self, agent_uid, settings):
        # Invoked by Agent on connect
        self._get_agent_by_uid(agent_uid).write(settings)
        return True


    @api.model
    def update_state(self, agent_uid, state='online',
                     note=False, force_create=False, safe=False):
        agent = self._get_agent_by_uid(agent_uid)
        last_state = self.env['remote_agent.agent_state'].search([
            ('agent', '=', agent.id)], limit=1, order='id desc')
        # Create online state if previous state was offline
        if (force_create or not last_state or
                (last_state and last_state.state != state)):
            if safe:
                # Update state in separate transaction
                try:
                    with api.Environment.manage():
                        with registry(self.env.cr.dbname).cursor() as new_cr:
                            env = api.Environment(
                                        new_cr, self.env.uid, self.env.context)
                            env['remote_agent.agent_state'].create({
                                                    'agent': agent.id,
                                                    'note': note,
                                                    'state': state})
                except Exception as e:
                    logger.warning('Agent update state: %s', e)
            else:
                # Called from agents so no need for separate transaction
                self.env['remote_agent.agent_state'].create({
                                        'agent': agent.id,
                                        'note': note,
                                        'state': state})
        return True


    @api.model
    def set_alarm(self, agent_uid, message):
        agent = self._get_agent_by_uid(agent_uid)
        agent.alarm = message
        return True


    @api.model
    def clear_alarm(self, agent_uid, message):
        # TODO: alarm message in event log
        agent = self._get_agent_by_uid(agent_uid)
        agent.alarm = False
        return True


import json
import logging
import requests
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import urllib3
# Default installation has self signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logger = logging.getLogger(__name__)

STATES = [
    ('offline', 'Offline'),
    ('online', 'Online'),
]


class Agent(models.Model):
    _name = 'remote_agent.agent'
    _description = 'Remote Agent'
    _rec_name = 'agent_uid'

    agent_uid = fields.Char(string=_('Agent UID'))
    note = fields.Text()
    token = fields.Char(groups="base.no_group")
    bus_timeout = fields.Integer()
    bus_enabled = fields.Boolean(default=True)
    https_enabled = fields.Boolean(string=_('HTTPS enabled'))
    https_address = fields.Char(string=_('HTTPS address'))
    https_port = fields.Char(string=_('HTTPS port'))
    https_timeout = fields.Integer(string=_('HTTPS timeout'))
    state = fields.Selection(STATES)
    login = fields.Many2one('res.users', ondelete='restrict')


    @api.model
    def update_settings(self, agent_uid, settings):
        # Invoked by Agent on connect
        agent = self.search([('agent_uid', '=', agent_uid)])
        if not agent:
            agent = self.create({'agent_uid': agent_uid})
        agent.write(settings)
        return True


    @api.multi
    def notify(self, message):
        self.ensure_one()
        return self.notify_agent(self.agent_uid, message)


    @api.model
    def notify_agent(self, agent_uid, message):
        # Unpack if required
        if type(message) != dict:
            message = json.loads(message)
        agent = self.search([('agent_uid', '=', agent_uid)])
        if not agent:
            raise ValidationError('Agent not found by uid {}'.format(agent_uid))
        # Hack related to protocol change
        if message.get('name'):
            message['Message'] = message.pop('name')
        if agent.https_enabled:
            # Use Agent HTTPS interface to communicate
            res = None
            try:
                message['token'] = agent.sudo().token
                res = requests.post(
                            'https://{}:{}'.format(agent.https_address,
                                                   agent.https_port),
                            json=message,
                            timeout=int(agent.https_timeout or 5),
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
            self.env['bus.bus'].sendone('asterisk_agent/{}'.format(
                                            agent.agent_uid), message)
        return True


    @api.model
    def bus_sendone(self, channel, message):
        # Override sendone as original method does not return value for RPC
        self.env['bus.bus'].sendone(channel, message)
        return True


    @api.multi
    def restart_agent(self):
        self.ensure_one()
        self.notify(json.dumps({'name': 'restart', 'uid': self.env.user.id}))


    @api.multi
    def ping_button(self):
        self.ensure_one()
        self.notify({'name': 'ping'})


    @api.model
    def ping_all(self):
        logger.info('TODO: ping_all agents')


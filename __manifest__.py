# -*- encoding: utf-8 -*-
{
    'name': 'Odoo remote agent',
    'version': '1.0',
    'author': 'Odooist',
    'maintainer': 'Odooist',
    'support': 'odooist@gmail.com',
    'category': 'Hidden',
    'summary': 'Connect from Odoo to remote agents',
    'description': "",
    'depends': ['bus'],
    'data': [
        'security/common.xml',
        'security/user.xml',
        'security/agent.xml',
        'security/admin.xml',
        'views/agent.xml',
        'views/agent_state.xml',
        'views/ir_cron.xml',
        ],
    'demo': [
        'views/demo.xml',
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
    'images': ['static/description/history_graph_crm.png'],
}

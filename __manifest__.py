# -*- encoding: utf-8 -*-
{
    'name': 'Odoo remote agent',
    'version': '1.0',
    'author': 'Odooist',
    'maintainer': 'Odooist',
    'support': 'odooist@gmail.com',
    #'license': 'LGPL-1', TODO:
    'category': 'Hidden',
    'summary': 'Connect from Odoo to remote agents',
    'description': "",
    'depends': ['bus'],
    'data': [
        'security/common.xml',
        'security/agent.xml',
        'security/user.xml',
        'security/ir.model.access.csv',
        'security/rules.xml',
        'views/agent.xml',
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

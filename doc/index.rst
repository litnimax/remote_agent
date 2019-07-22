===========================================
 Odoo Remote Agent communication framework
===========================================

.. contents::
   :depth: 4

Concept
-------
Existing Odoo clients can only call Odoo methods. This solutions uses *odoorpc* library for this.

This solution also gives the ability to call remote client from Odoo  using 2 ways of communication:

* JSON-RPC over Odoo bus (PUB/SUB via long polling).
* JSON-RPC via HTTPS.

.. image:: https://raw.githubusercontent.com/litnimax/remote_agent/12.0/static/description/img/concept.png

Features
########

* Odoo connection watcher (auto re-connect after disconnect).
* Two alternative communication channels: bus and https.
* Connection monitor ans statistics (via cron job).
* Agent remote restart (restart agent process from Odoo).


Development documentation
#########################
See Wiki for more documentation:

* `Ideas <https://github.com/litnimax/remote_agent/wiki/Ideas>`_ (create new issues with your proposals).
* `Development workflow <https://github.com/litnimax/remote_agent/wiki/Development-workflow>`_ - my development cycle and environment.


Installation
------------
* Install Odoo module.
* Install external (optional) libraries and modules.
* Run agent somewhere.

Install Odoo module
###################
Copy *remote_agent* package to */mnt/external-addons* or another directory where Odoo modules are located.

Install external libs and modules
#################################
Install TinyRPC library:

```
pip3 install TinyRPC
```

The following dependencies are not required to install and run *remote_agent* but when installed provide additional features.

Humanize
++++++++
Agent tree view can show state changes in relative dates in human language (e.g. 4 minutes ago).
Install this in Odoo in the following way:

.. code:: bash

  pip3 install humanize


And restart Odoo.

Install agent
#############
Copy agent folder to your remote box to */srv/agent/* folder. Python2.7 is required. 

Install dependencies:

.. code:: bash

  pip install -r requirements.txt

Run agent using start_agent.sh script to check the installation:

.. code:: bash

  /srv/agent # ./start_agent.sh
  2019-06-10 16:02:36,551 - INFO - remote_agent - Odoo agent version 1.0-gevent init
  ...
  ^CKeyboardInterrupt
  Mon Jun 10 16:06:38 2019
  2019-06-10 16:06:38,283 - INFO - remote_agent - Odoo Agent exit

Configure Agent to be started on system boot:

.. code:: bash

  cp agent.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable odoo_agent
  systemctl start odoo_agent
  journalctl -u odoo_agent


Docker compose deploy
#####################
See docker-compose.yml in the package folder.

To customize your installation use ``docker-compose.override.yml`` to set your custom values.

Changelog
---------
1.1
###
* RPC over HTTPS implemented.
* Added option to odoo Agent model to verify agent's HTTPS certificate (in case
  you want to use your own certificates instead of suplied self-signed.).
* Agent now can overwrite it's settings on Odoo if 

1.0
###
Initial release.



===============================================
 Asterisk Calls Odoo Application documentation
===============================================

.. contents::
   :depth: 4


Installation
------------
To get this working You need:

* **Install Odoo module** and do some Odoo users <-> Asterisk extensions configuration.
* **Do some Asterisk configuration** - add getting caller name from Odoo and more.
* **Run Odoo Asterisk agent** - a script that connects to Asterisk Manager
  Interface (AMI) and listens for events / sends actions. Agent can be run
  from any place: Odoo server, Asterisk server or just a docker service.

Here is the architecture of the solution:

.. image:: img/asterisk_calls_dia.png
   :width: 800px

Docker compose deploy
#####################
There is a deploy folder in the application package that contains docker-compose style installation.
The deploy folder contains 3 directories:

- **agent** (a middleware between Odoo and Asterisk, you already have 
  Odoo and Asterisk you may want to run only a docker based Agent installation).
- **odoo** (installation of Odoo and PostgreSQL, if you already have  
  Asterisk running then you may want to run docker based Odoo and Agent.
- **asterisk** (If you want a complete all-in-one suite run all components).

To customize your installation use ``docker-compose.override.yml`` to set your custom values.


===========================================
 Odoo Remote Agent communication framework
===========================================

.. contents::
   :depth: 4

Concept
-------
Existing Odoo clients can only call Odoo methods. This solutions uses *odoorpc* library for this.

This solution also gives the ability to call from Odoo remote client using 2 ways of communication:

* Odoo bus polling
* HTTPS

Features
########

* Odoo connection watcher (auto re-connect after disconnect).
* Query pool (queries are not lost during Odoo disconnects).
* Two alternative communication channels: bus and https.


Installation
------------
To get this working You need:

* Install Odoo module
* Run agent


Docker compose deploy
#####################
To customize your installation use ``docker-compose.override.yml`` to set your custom values.




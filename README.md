# Odoo Agent
Remote Odoo communication framework

## Concept
Existing Odoo clients can only call Odoo methods. This solutions uses *odoorpc* library for this.

This solution also gives the ability to call from Odoo remote client using 2 ways of communication:
- Odoo bus polling
- HTTPS


## Features
* Odoo connection watcher (auto re-connect after disconnect).
* Query pool (queries are not lost during Odoo disconnects).
* Two alternative communication channels: bus and https.
* 


Work in progress....

Todo:
* execute (remote reply)
* ping state change
* Odoo agent module with sending agent uid and other settings to the agent
* Odoo account auto creating (Agent auto registration)
* aioagent (Asyncio Agent)
* RPC over HTTTPS/Bus channel
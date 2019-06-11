# Remote Agent - Odoo communication framework

The purpose of this framework is to create a common base for different applications like IoT boxes or brokers.

Its main goal is to give Odoo a way to call functions on remote side without any additional software like message bus (Kafka, RabbitMQ, NATS, etc).

This is possible becuase Odoo itself can be a message bus using PostgreSQL NOTIFY / LISTEN features and [bus](https://github.com/odoo/odoo/tree/12.0/addons/bus) module.

Remote Agent uses Odoo's /longpolling/poll controller to keep continuous connection and thus be available without a need to know its source address.

TinyRPC library is used to run a RPC server on remote agents.

See [Wiki](https://github.com/litnimax/remote_agent/wiki) for more documentation.

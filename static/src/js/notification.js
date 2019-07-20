odoo.define("remote_agent.notification", function (require) {
    "use strict";
  
    var WebClient = require('web.WebClient');
    var ajax = require('web.ajax');
    var utils = require('mail.utils');
    var session = require('web.session');    
    var channel = 'remote_agent_notification' + '_' + session.uid;

    WebClient.include({
        start: function() {
            this._super()
            var self = this
            ajax.rpc('/web/dataset/call_kw/res.users', {
                    "model": "res.users",
                    "method": "has_group",
                    "args": ['remote_agent.group_agent_user'],
                    "kwargs": {},            
            }).then(function (res) {
              if (res == true) {
                self.call('bus_service', 'addChannel', channel);
                self.call('bus_service', 'onNotification', self, self.on_agent_notification)
                // console.log('Listening on ', channel)                
              }
            })
        },

        on_agent_notification: function (notification) {
          for (var i = 0; i < notification.length; i++) {
             var ch = notification[i][0]
             var msg = notification[i][1]
             if (ch == channel) {
                 try {
                  this.handle_agent_message(msg)
                }
                catch(err) {console.log(err)}
             }
           }
        },

        handle_agent_message: function(msg) {
          // console.log(msg)
          if (typeof msg == 'string')
            var message = JSON.parse(msg)
          else
            var message = msg
          if (message.warning == true)
            this.do_warn(message.title, message.message, message.sticky)
          else
            this.do_notify(message.title, message.message, message.sticky)
      },
  })
})

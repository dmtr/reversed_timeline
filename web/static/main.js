require(['jquery', 'bootstrap', 'ramda', 'utils/utils'], function($, R, utils){
    // DOM ready
    $(function() {

    var conn = null;

    function connect() {
        disconnect();
        var wsUri = (window.location.protocol=='https:'&&'wss://'||'ws://')+window.location.host + '/tweets';
        conn = new WebSocket(wsUri);
        conn.onopen = function() {
        update_ui();
    };
            conn.onmessage = function(e) {
              log('Received: ' + e.data);
            };
            conn.onclose = function() {
              conn = null;
              update_ui();
            };
          }
          function disconnect() {
            if (conn !== null) {
              log('Disconnecting...');
              conn.close();
              conn = null;
                  update_ui();
            }
          }
          function update_ui() {
            var msg = '';
            if (conn === null) {
              $('#status').text('disconnected');
              $('#connect').html('Connect');
            } else {
              $('#status').text('connected (' + conn.protocol + ')');
              $('#connect').html('Disconnect');
            }
          }
          $('#connect').click(function() {
            if (conn === null) {
              connect();
            } else {
              disconnect();
            }
            update_ui();
            return false;
          });
          $('#send').click(function() {
            var msg = {  
                screen_name: $('#text').val(),
                type: 'start',
                client_key: utils.getCookie('auth')
            };
            conn.send(JSON.stringify(msg));
            $('#text').val('').focus();
            return false;
          });
          $('#text').keyup(function(e) {
            if (e.keyCode === 13) {
              $('#send').click();
              return false;
            }
            });

    });
});



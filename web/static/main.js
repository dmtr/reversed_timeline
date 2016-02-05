    function getcookie(name) {
        var cookievalue = null;
        if (document.cookie && document.cookie !== '') {
            var cookies = document.cookie.split(';');
            for (var i = 0; i < cookies.length; i++) {
                var cookie = $.trim(cookies[i]);
                // does this cookie string begin with the name we want?
                if (cookie.substring(0, name.length + 1) == (name + '=')) {
                    cookievalue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookievalue;
    }

    $(function() {
      var conn = null;
      function log(msg) {
        var control = $('#log');
        control.html(control.text() + msg + '<br/>');
        control.scrollTop(control.scrollTop() + 1000);
      }
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
        if (conn != null) {
          log('Disconnecting...');
          conn.close();
          conn = null;
              update_ui();
        }
      }
      function update_ui() {
        var msg = '';
        if (conn == null) {
          $('#status').text('disconnected');
          $('#connect').html('Connect');
        } else {
          $('#status').text('connected (' + conn.protocol + ')');
          $('#connect').html('Disconnect');
        }
      }
      $('#connect').click(function() {
        if (conn == null) {
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
            client_key: getcookie('auth')
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


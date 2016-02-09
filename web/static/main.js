var getCookieVal = function(name, cookies) {
    var findByName = R.pipe(
        R.split('='), 
        R.head,
        R.trim,
        R.equals(name)
    );

    var getVal = R.pipe( 
        R.split(';'),
        R.find(findByName),
        R.ifElse(
            R.isNil,
            R.identity,
            R.pipe(R.split('='), R.last)
        )
    );
    return decodeURIComponent(getVal(cookies));
};

var getCookie = function(name) {
    var r = R.ifElse(
        R.or(R.isNil, R.isEmpty),
        R.identity,
        R.curry(getCookieVal)
    );
  
    return r(document.cookie);
};

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
            client_key: getCookie('auth')
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


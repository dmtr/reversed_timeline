require(['jquery', 'ramda', 'utils/utils', 'utils/m'], function($, R, utils, m) {


    var log = function(x) {
        return new m.IO.of(function() { console.log(x); return x; });
    };

	var safeProp = function(x, obj) { 
		var p = R.propOr(m.Left.of('No such property ' + x), x)(obj); 
		return R.ifElse(R.is(m.Left), R.identity, m.Right.of)(p);
	};

	var nestedProp = function(props, obj) {
		function inner(props, o) {
            if( R.is(m.Left, o) || R.isEmpty(props) ) {
                return o;
            } else {
                return inner(R.tail(props), safeProp(R.head(props), o.join()));
            }
        }
        return inner(props, m.Right.of(obj));
    };

    var protocol = nestedProp(['location', 'protocol'], window);
    var host = nestedProp(['location', 'host'], window);
    var wsUri = (protocol.join() == 'https:' && 'wss://' || 'ws://') + host.join() + '/tweets';
    var client_key = utils.getCookie('auth');

    function connect() {
        var w = m.IO.of(function() {
                        try {
                             return m.Right.of(new WebSocket(wsUri));
                        }  
                        catch (e) {
                             return m.Left.of(e);
                        }
                });

        return R.compose(
            m.either(
             R.identity,
             function(c) {
                c.onmessage = function(e) {
                  log('Received: ' + e.data).join();
                };
                return m.IO.of(function() { return c;});
             } 
            ),
            m.join
        )(w);
    }


// DOM ready
    $( function() {

    var conn = connect();

    $('#go-btn').click(function() {
        var msg = {  
            screen_name: $('#username').val(),
            type: 'start',
            client_key: client_key
        };

        conn = m.chain(function(c) { 
            c.send(JSON.stringify(msg)); 
            return m.IO.of(function() {return c;});
            }, 
            conn);
        return false;
    });

    $('#username').keyup(function(e) {
        if (e.keyCode === 13) {
            $('#go-btn').click();
            return false;
        }
    });

    });
});



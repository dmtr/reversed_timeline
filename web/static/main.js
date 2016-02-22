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
            if (R.is(m.Left, o) || R.isEmpty(props)) {
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
    var tweets = Array();
    var conn = m.Left.of('Not Connected');


    function createTweet(id_str) {
        twttr.widgets.createTweet(
            id_str,
            document.getElementById(id_str),
            {
               align: "center",
               conversation: "none",
               cards: "hidden"
            }
            ).then(function(el) {
               console.log('tweet is displayed');
            });
    }

    function renderTweets() {
        var d = $('<div></div>');
        R.forEach(function (id_str) {
            d.append( $('<div id="' + id_str + '">') );
        },
        tweets);
        $("#tweets").prepend(d);
        R.forEach(createTweet, tweets);
    }

    function processMessage(m) {
        if (m.type === 'tweet') {
            tweets.push(m.tweet_id);
        } else if (m.type === 'end') {
            renderTweets();
            tweets = Array();
        } else if (m.type === 'error') {
            console.error('Server error');
        }
    }

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
                    processMessage(JSON.parse(e.data));
                };
                c.onclose = function() {
                    log('Closed!').join();
                };
                return c;
             } 
            ),
            m.join
        )(w);
    }

	function send_msg() {
        var msg = {  
            screen_name: $('#username').val(),
            type: 'start',
            client_key: client_key,
            count: $('#count').val()
        };

        conn.send(JSON.stringify(msg)); 
    }

// DOM ready
    $( function() {

        conn = connect();

        $("#mainform").submit(function(e){
            send_msg();
            e.preventDefault();
        });

    });
});



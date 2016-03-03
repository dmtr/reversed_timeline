require(['jquery', 'ramda', 'utils/utils', 'utils/m', 'jquery-mousewheel'], function($, R, utils, m) {


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
    var tweets = Array();
    var conn = m.Left.of('Not Connected');
    var currentUser = m.Left.of('None');
    var requestIsRunning = false;


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
        $("#alert").addClass("hidden");
        $("#progress_bar").addClass("hidden");

        if (m.type === 'tweet') {
            tweets.push(m.tweet_id);
        } else if (m.type === 'end') {
            renderTweets();
            tweets = Array();
        } else if (m.type === 'error') {
            $("#alert").removeClass("hidden");
            $("#alert").text(m.desc);
        }
    }

    function connect() {
        var w = m.IO.of(function() {return new WebSocket(wsUri);});

        return m.map(
             function(c) {
                c.onmessage = function(e) {
                    console.log('got message ', e.data);
                    requestIsRunning = false;
                    processMessage(JSON.parse(e.data));
                };
                c.onclose = function() {
                    log('Closed!').join();
                };
                return c;
             } 
        )(w);
    }

	function send_msg(type, screen_name, count) {
        requestIsRunning = true;
        var msg = {  
            screen_name: screen_name,
            type: type,
            count: count
        };
        console.log('sending msg ', msg);
        conn.send(JSON.stringify(msg)); 
    }

// DOM ready
    $( function() {

        conn = R.compose(m.join, connect)();

        $("#mainform").submit(function(e){
            if (currentUser !== $('#username').val()) {
                $("#tweets").empty();
            }
            currentUser = $('#username').val();
            send_msg('get', $('#username').val(), $('#count').val());
            e.preventDefault();
        });

        function get_tweets(e) {
            if (requestIsRunning === false) {
                if ($(this).scrollTop() + $(this).innerHeight() >= $(this)[0].scrollHeight) {
                    if ('deltaY' in e && e.deltaY > 0) {
                        return;
                    }
                    $("#tweets").after($("#progress_bar"));
                    $("#progress_bar").removeClass("hidden");
                    send_msg('get_newest', null, null);
                } else if ($(this).scrollTop() < 3) {
                    if ('deltaY' in e && e.deltaY < 0) {
                        return;
                    }
                    $("#progress_bar").removeClass("hidden");
                    $("#tweets").before($("#progress_bar"));
                    send_msg('get_oldest', null, null);
                }
            }
        }

        $("#tweets").scroll(get_tweets);
        $('#tweets').on('mousewheel', get_tweets);
    });
});

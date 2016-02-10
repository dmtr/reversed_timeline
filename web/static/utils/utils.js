define(["ramda"], function(R) {
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

    return {
        getCookie: function(name) {
            var r = R.ifElse(
                R.or(R.isNil, R.isEmpty),
                R.identity,
                R.curry(getCookieVal)
            );
          
            return r(document.cookie);
        }
    };
}
);
